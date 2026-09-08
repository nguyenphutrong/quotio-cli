use super::*;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(super::super::random_string().unwrap());
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
    fn envelope(&self) -> PathBuf {
        let path = self.0.join("fixture.qsv");
        let b64 = base64::engine::general_purpose::STANDARD;
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "wrappedKey": b64.encode([7; 256]),
                "sealedSecret": b64.encode([8; 48])
            }))
            .unwrap(),
        )
        .unwrap();
        path
    }
    fn inspect(&self, path: &Path) -> Plan {
        assess(path, &"a".repeat(64)).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn swift_envelope_blocks_import_without_claiming_hardware_access() {
    let f = Fixture::new();
    let path = f.envelope();
    let original = fs::read(&path).unwrap();
    let plan = f.inspect(&path);
    assert_eq!(
        plan.envelope_state,
        EnvelopeState::PresentLockedOrUnverified
    );
    assert_eq!(plan.key_access, "not_attempted");
    assert!(plan.migration_blocked);
    assert!(
        plan.protection
            .contains("no_keychain_or_software_vault_fallback")
    );
    assert_eq!(plan.fingerprint_binding, "caller_declared_unverified");
    let json = serde_json::to_string(&plan).unwrap();
    assert!(!json.contains("wrappedKey"));
    assert!(!json.contains("sealedSecret"));
    assert!(!json.contains(path.to_str().unwrap()));
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[test]
fn absent_unreadable_and_unsupported_are_distinct_and_never_fall_back() {
    let f = Fixture::new();
    let path = f.0.join("absent.qsv");
    assert_eq!(f.inspect(&path).envelope_state, EnvelopeState::Absent);
    fs::create_dir(&path).unwrap();
    assert_eq!(f.inspect(&path).envelope_state, EnvelopeState::Unreadable);
    let file = f.envelope();
    for bytes in [
        b"fixture-plaintext-secret".as_slice(),
        br#"{"version":2,"wrappedKey":"AA==","sealedSecret":"AA=="}"#,
        br#"{"version":1,"wrappedKey":"bad","sealedSecret":"bad"}"#,
    ] {
        fs::write(&file, bytes).unwrap();
        let plan = f.inspect(&file);
        assert_eq!(plan.envelope_state, EnvelopeState::UnsupportedEnvelope);
        assert_eq!(plan.envelope_sha256, None);
        assert!(plan.migration_blocked);
        assert!(
            !serde_json::to_string(&plan)
                .unwrap()
                .contains("fixture-plaintext-secret")
        );
    }
}

#[test]
fn receipt_reruns_preserve_original_bytes_and_inode_and_detect_source_change() {
    let f = Fixture::new();
    let source = f.envelope();
    let original = fs::read(&source).unwrap();
    let plan = f.inspect(&source);
    let id = stage(&plan, &f.0).unwrap();
    let receipt = f.0.join(format!("{id}.json"));
    let first = fs::metadata(&receipt).unwrap();
    let bytes = fs::read(&receipt).unwrap();
    assert_eq!(first.mode() & 0o777, 0o600);
    for _ in 0..3 {
        assert_eq!(stage(&f.inspect(&source), &f.0).unwrap(), id);
    }
    assert_eq!(fs::metadata(&receipt).unwrap().ino(), first.ino());
    assert_eq!(fs::read(&receipt).unwrap(), bytes);
    assert_eq!(fs::read(&source).unwrap(), original);
    let mut changed = original;
    changed.push(b' ');
    fs::write(&source, changed).unwrap();
    assert_ne!(stage(&f.inspect(&source), &f.0).unwrap(), id);
    assert_eq!(fs::read(&receipt).unwrap(), bytes);
}

#[test]
fn concurrent_receipts_converge_and_conflicting_receipts_are_never_overwritten() {
    let f = Fixture::new();
    let plan = f.inspect(&f.envelope());
    let ids = std::thread::scope(|s| {
        let workers: Vec<_> = (0..6).map(|_| s.spawn(|| stage(&plan, &f.0))).collect();
        workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .collect::<Vec<_>>()
    });
    for id in &ids {
        assert!(id.is_ok());
    }
    let id = stage(&plan, &f.0).unwrap();
    for value in ids.into_iter().flatten() {
        assert_eq!(value, id);
    }
    let path = f.0.join(format!("{id}.json"));
    fs::write(&path, b"interrupted-or-tampered-fixture").unwrap();
    assert!(matches!(stage(&plan, &f.0), Err(StagingError::Conflict)));
    assert_eq!(fs::read(path).unwrap(), b"interrupted-or-tampered-fixture");
}

#[test]
fn no_symlinks_public_destinations_or_hardlinks() {
    let f = Fixture::new();
    let source = f.envelope();
    let alias = f.0.join("alias.qsv");
    std::os::unix::fs::symlink(&source, &alias).unwrap();
    assert_eq!(f.inspect(&alias).envelope_state, EnvelopeState::Unreadable);
    let dir_alias = f.0.join("alias-dir");
    std::os::unix::fs::symlink(&f.0, &dir_alias).unwrap();
    assert_eq!(
        f.inspect(&dir_alias.join("fixture.qsv")).envelope_state,
        EnvelopeState::Unreadable
    );
    let plan = f.inspect(&source);
    assert!(stage(&plan, &dir_alias).is_err());
    let id = stage(&plan, &f.0).unwrap();
    let receipt = f.0.join(format!("{id}.json"));
    fs::set_permissions(&receipt, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(stage(&plan, &f.0), Err(StagingError::Conflict)));
    fs::remove_file(&receipt).unwrap();
    std::os::unix::fs::symlink(&source, &receipt).unwrap();
    assert!(stage(&plan, &f.0).is_err());
    fs::hard_link(&source, f.0.join("hardlink")).unwrap();
    assert_eq!(f.inspect(&source).envelope_state, EnvelopeState::Unreadable);
    fs::set_permissions(&f.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(stage(&plan, &f.0).is_err());
}

#[test]
fn interrupted_and_uncertain_receipts_recover_without_overwrite() {
    let f = Fixture::new();
    let bytes = b"synthetic-assessment";
    let fail = |_: &std::fs::File| Err(std::io::Error::other("fixture sync failure"));
    assert!(matches!(
        unix::save_with_sync(&f.0, "receipt.json", bytes, fail),
        Err(StagingError::Storage)
    ));
    assert!(!f.0.join("receipt.json").exists());
    // An abandoned temporary file from a killed process is not a completed receipt.
    std::fs::write(f.0.join(".abandoned.tmp"), b"partial-fixture").unwrap();
    let result = unix::save_with_sync(&f.0, "receipt.json", bytes, |file| {
        if file.metadata()?.is_dir() {
            fail(file)
        } else {
            file.sync_all()
        }
    });
    assert!(matches!(result, Err(StagingError::CommitUncertain)));
    let inode = std::fs::metadata(f.0.join("receipt.json")).unwrap().ino();
    unix::save(&f.0, "receipt.json", bytes).unwrap();
    assert_eq!(
        std::fs::metadata(f.0.join("receipt.json")).unwrap().ino(),
        inode
    );
    assert_eq!(std::fs::read(f.0.join("receipt.json")).unwrap(), bytes);
    assert_eq!(
        std::fs::read(f.0.join(".abandoned.tmp")).unwrap(),
        b"partial-fixture"
    );
}

#[test]
fn invalid_fingerprint_paths_and_large_inputs_are_safe() {
    let f = Fixture::new();
    assert!(assess(&f.envelope(), "fixture-secret").is_err());
    assert!(assess(Path::new("relative.qsv"), &"a".repeat(64)).is_err());
    let path = f.envelope();
    fs::write(&path, vec![0; 1024 * 1024 + 1]).unwrap();
    assert_eq!(f.inspect(&path).envelope_state, EnvelopeState::Unreadable);
}
