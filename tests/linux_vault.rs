#![cfg(target_os = "linux")]
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture {
    root: PathBuf,
    key: [u8; 32],
}
impl Fixture {
    fn new() -> Self {
        let mut key = [0; 32];
        SystemRandom::new().fill(&mut key).unwrap();
        let root = std::env::temp_dir().join(format!(
            "quotio-linux-vault-{}-{}",
            std::process::id(),
            u64::from_le_bytes(key[..8].try_into().unwrap())
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("master"), key).unwrap();
        fs::set_permissions(root.join("master"), fs::Permissions::from_mode(0o600)).unwrap();
        Self { root, key }
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_quotio"));
        command
            .env_clear()
            .env("HOME", &self.root)
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("QUOTIO_VAULT_KEY_FILE", self.root.join("master"));
        command
    }
    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }
    fn seed(&self) -> PathBuf {
        let directory = self.root.join("data/quotio/vault");
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let mut doc = quotio::accounts::Document::empty();
        for label in ["one", "two"] {
            doc.add(
                quotio::cli::Provider::Amp,
                label,
                label.into(),
                quotio::accounts::Credential::ApiKey {
                    token: "fixture-token-not-real".into(),
                    region: None,
                    organization: None,
                },
            )
            .unwrap();
        }
        let mut ciphertext = serde_json::to_vec(&doc).unwrap();
        let header = b"quotio-vault\0\x01";
        let key =
            aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &self.key).unwrap());
        let nonce = [7; 12];
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(header),
            &mut ciphertext,
        )
        .unwrap();
        let path = directory.join("accounts.enc");
        fs::write(&path, [header.as_slice(), &nonce, &ciphertext].concat()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn headless_cli_reads_selects_removes_and_restarts_with_encrypted_accounts() {
    let f = Fixture::new();
    let path = f.seed();
    let list = f.run(&["accounts", "list", "--format", "json"]);
    assert!(
        list.status.success(),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    assert!(!String::from_utf8_lossy(&list.stdout).contains("fixture-token"));
    let rows: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let second = rows[1]["id"].as_str().unwrap();
    assert!(f.run(&["accounts", "use", second]).status.success());
    let rows: serde_json::Value =
        serde_json::from_slice(&f.run(&["accounts", "list", "--format", "json"]).stdout).unwrap();
    assert_eq!(rows[1]["active"], true);
    assert!(f.run(&["accounts", "remove", second]).status.success());
    let rows: serde_json::Value =
        serde_json::from_slice(&f.run(&["accounts", "list", "--format", "json"]).stdout).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["active"], true);
    assert!(
        !fs::read(path)
            .unwrap()
            .windows(13)
            .any(|w| w == b"fixture-token")
    );
}

#[test]
fn missing_wrong_conflicting_or_public_key_fails_without_overwrite() {
    let f = Fixture::new();
    let path = f.seed();
    let original = fs::read(&path).unwrap();
    let missing = f
        .command()
        .env_remove("QUOTIO_VAULT_KEY_FILE")
        .args(["accounts", "list", "--format", "json"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
    let conflict = f
        .command()
        .env("QUOTIO_VAULT_KEY_FD", "3")
        .args(["accounts", "list"])
        .output()
        .unwrap();
    assert!(!conflict.status.success());
    fs::write(f.root.join("master"), [9; 32]).unwrap();
    assert!(!f.run(&["accounts", "list"]).status.success());
    fs::write(f.root.join("master"), f.key).unwrap();
    fs::set_permissions(f.root.join("master"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!f.run(&["accounts", "list"]).status.success());
    assert_eq!(original, fs::read(path).unwrap());
}

#[test]
fn inherited_file_descriptor_respects_permissions_and_key_length() {
    use std::os::{fd::AsRawFd, unix::process::CommandExt};
    let f = Fixture::new();
    f.seed();
    for (mode, length, succeeds) in [(0o600, 32, true), (0o644, 32, false), (0o600, 31, false)] {
        fs::write(f.root.join("master"), &f.key[..length]).unwrap();
        fs::set_permissions(f.root.join("master"), fs::Permissions::from_mode(mode)).unwrap();
        let file = fs::File::open(f.root.join("master")).unwrap();
        let fd = file.as_raw_fd();
        let mut command = f.command();
        command
            .env_remove("QUOTIO_VAULT_KEY_FILE")
            .env("QUOTIO_VAULT_KEY_FD", fd.to_string());
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = command
            .args(["accounts", "list", "--format", "json"])
            .output()
            .unwrap();
        assert_eq!(output.status.success(), succeeds);
    }
}

#[tokio::test]
async fn rest_reports_locked_storage_instead_of_empty_accounts() {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};
    let f = Fixture::new();
    fs::write(f.root.join("config.toml"), "enabled_providers = []\n").unwrap();
    let token = "fixture-management-token-1234567890123456";
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_quotio"))
        .env_clear()
        .env("HOME", &f.root)
        .env("XDG_DATA_HOME", f.root.join("data"))
        .env("QUOTIO_CACHE_DIR", f.root.join("cache"))
        .env("QUOTIO_SERVER_TOKEN", token)
        .args(["serve", "--manage", "--listen", "127.0.0.1:0", "--config"])
        .arg(f.root.join("config.toml"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let line = tokio::time::timeout(std::time::Duration::from_secs(10), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let base = line.strip_prefix("Quotio API listening on ").unwrap();
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap()
        .get(format!("{base}/v1/accounts"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    let body = response.text().await.unwrap();
    assert!(body.contains("credential_storage_unavailable"));
    assert!(!body.contains(token));
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}
