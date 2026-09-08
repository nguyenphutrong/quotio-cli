#![cfg(unix)]
use base64::Engine;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    process::Command,
};

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
