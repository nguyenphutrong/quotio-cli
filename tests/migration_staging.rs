#![cfg(unix)]
use base64::Engine;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    process::Command,
};

fn digest(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn cli_explicit_mapping_dry_run_restart_and_invalid_combinations() {
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("quotio-mapping-cli-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let dest = root.join("stage");
    fs::create_dir(&dest).unwrap();
    fs::set_permissions(&dest, fs::Permissions::from_mode(0o700)).unwrap();
    let metadata = root.join("accounts.json");
    let metadata_bytes = br#"{"accounts":[{"id":"fixture-account","provider":"amp","accountKey":"label","displayName":"name","source":"quotioKeychain","credentialReference":"keychain"}],"disabledAccountIDs":["unpersisted-native"]}"#;
    fs::write(&metadata, metadata_bytes).unwrap();
    let source = root.join(format!(
        "{}.qsv",
        digest(b"app.bytrong.quotio.monitor-auth\0fixture-account")
    ));
    let b64 = base64::engine::general_purpose::STANDARD;
    let ciphertext = serde_json::to_vec(&serde_json::json!({"version":1,"wrappedKey":b64.encode([1;256]),"sealedSecret":b64.encode([2;40])})).unwrap();
    fs::write(&source, &ciphertext).unwrap();
    let metadata_mode = fs::metadata(&metadata).unwrap().mode();
    let source_mode = fs::metadata(&source).unwrap().mode();
    let run = |stage: bool, provider: &str, service: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_quotio"));
        command
            .env_clear()
            .env("HOME", root.join("no-home"))
            .args(["migration-inspect", "--piv-envelope"])
            .arg(&source)
            .args(["--piv-fingerprint", &"a".repeat(64), "--metadata"])
            .arg(&metadata)
            .args([
                "--account-id",
                "fixture-account",
                "--provider",
                provider,
                "--source",
                "quotioKeychain",
                "--credential-reference",
                "keychain",
            ]);
        if let Some(service) = service {
            command.args(["--service", service]);
        }
        if stage {
            command.arg("--stage-dir").arg(&dest);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        for bytes in [&output.stdout, &output.stderr] {
            assert!(!String::from_utf8_lossy(bytes).contains(root.to_str().unwrap()));
        }
        output
    };
    for (provider, service) in [
        ("unknown", Some("app.bytrong.quotio.monitor-auth")),
        ("amp", Some("unknown-service")),
        ("amp", None),
    ] {
        let output = run(true, provider, service);
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
        assert_eq!(fs::read_dir(&dest).unwrap().count(), 0);
    }
    let valid = |stage| {
        let output = run(stage, "amp", Some("app.bytrong.quotio.monitor-auth"));
        assert!(output.stderr.is_empty());
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let dry = valid(false);
    assert!(dry["receipt_id"].is_null());
    assert_eq!(dry["plan"]["migration_blocked"], true);
    assert_eq!(dry["accounts_imported"], 0);
    assert_eq!(dry["encrypted_artifacts_staged"], false);
    assert_eq!(fs::read_dir(&dest).unwrap().count(), 0);
    let staged = valid(true);
    assert_eq!(staged["plan"], dry["plan"]);
    assert_eq!(staged["encrypted_artifacts_staged"], true);
    let snapshots: Vec<_> = fs::read_dir(&dest)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let meta = fs::metadata(&path).unwrap();
            assert_eq!(meta.mode() & 0o777, 0o600);
            (path.clone(), fs::read(path).unwrap(), meta.ino())
        })
        .collect();
    assert_eq!(snapshots.len(), 3);
    assert_eq!(valid(true), staged);
    for (path, bytes, inode) in snapshots {
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::metadata(path).unwrap().ino(), inode);
    }
    assert_eq!(fs::read(&metadata).unwrap(), metadata_bytes);
    assert_eq!(fs::read(&source).unwrap(), ciphertext);
    assert_eq!(fs::metadata(&metadata).unwrap().mode(), metadata_mode);
    assert_eq!(fs::metadata(&source).unwrap().mode(), source_mode);
    assert!(!root.join("no-home").exists());
    let staged_ciphertext = dest.join(format!("{}.qsv", digest(&ciphertext)));
    fs::write(&staged_ciphertext, b"tampered").unwrap();
    let output = run(true, "amp", Some("app.bytrong.quotio.monitor-auth"));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
    assert_eq!(fs::read(staged_ciphertext).unwrap(), b"tampered");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_dry_run_and_restarted_staging_do_not_import_or_discover() {
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("quotio-staging-cli-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let source = root.join("fixture.qsv");
    let b64 = base64::engine::general_purpose::STANDARD;
    let original = serde_json::to_vec(&serde_json::json!({"version":1,"wrappedKey":b64.encode([1;256]),"sealedSecret":b64.encode([2;40])})).unwrap();
    fs::write(&source, &original).unwrap();
    let run = |stage| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_quotio"));
        command
            .env_clear()
            .env("HOME", root.join("nonexistent-home"))
            .args(["migration-inspect", "--piv-envelope"])
            .arg(&source)
            .args(["--piv-fingerprint", &"a".repeat(64)]);
        if stage {
            command.arg("--stage-dir").arg(&root);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let dry = run(false);
    assert!(dry["receipt_id"].is_null());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    let staged = run(true);
    assert_eq!(staged["plan"], dry["plan"]);
    assert_eq!(staged["plan"]["migration_blocked"], true);
    assert_eq!(staged["accounts_imported"], 0);
    assert_eq!(staged["credentials_staged"], false);
    let receipt = root.join(format!("{}.json", staged["receipt_id"].as_str().unwrap()));
    let before = fs::metadata(&receipt).unwrap();
    assert_eq!(before.mode() & 0o777, 0o600);
    assert_eq!(run(true), staged);
    assert_eq!(fs::metadata(&receipt).unwrap().ino(), before.ino());
    assert_eq!(fs::read(&source).unwrap(), original);
    assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(receipt).unwrap()).unwrap(),
        staged["plan"]
    );
    fs::remove_dir_all(root).unwrap();
}
