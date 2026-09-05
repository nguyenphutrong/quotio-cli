#![cfg(unix)]
use std::{
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, BufReader};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "quotio-cache-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("config.toml"), "enabled_providers = ['codex']\n").unwrap();
        std::fs::write(path.join("login"), "first@example.test").unwrap();
        std::fs::write(path.join("codex"), r#"#!/usr/bin/python3
import json, sys, pathlib
root = pathlib.Path(__file__).parent
for line in sys.stdin:
    request = json.loads(line)
    if 'id' not in request: continue
    method = request['method']
    if method == 'initialize': result = {}
    elif method == 'account/read':
        result = {'account': {'type':'chatgpt', 'email':(root/'login').read_text(), 'planType':'pro'}}
    elif method == 'account/rateLimits/read':
        with (root/'calls').open('a') as f: f.write('fetch\n')
        if (root/'fail').exists():
            print(json.dumps({'id':request['id'], 'error':{'code':-1}}), flush=True)
            continue
        result = {'rateLimits':{'primary':{'usedPercent':25, 'windowDurationMins':300}}}
    else: raise Exception('unexpected method')
    print(json.dumps({'id':request['id'], 'result':result}), flush=True)
"#).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path.join("codex"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        Self(path)
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_quotio"));
        cmd.env("PATH", &self.0)
            .env("QUOTIO_CACHE_DIR", self.0.join("cache"));
        cmd
    }
    fn usage(&self, force: bool) -> std::process::Output {
        let mut cmd = self.command();
        cmd.args([
            "usage",
            "--format",
            "json",
            "--no-saved-accounts",
            "--config",
        ])
        .arg(self.0.join("config.toml"));
        if force {
            cmd.arg("--force");
        }
        cmd.output().unwrap()
    }
    fn calls(&self) -> usize {
        std::fs::read_to_string(self.0.join("calls"))
            .unwrap()
            .lines()
            .count()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn cli_reuses_disk_cache_force_refreshes_and_switching_login_fails_closed() {
    let f = Fixture::new();
    let first = f.usage(false);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let before: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert!(f.usage(false).status.success());
    assert_eq!(f.calls(), 1);
    assert!(f.usage(true).status.success());
    assert_eq!(f.calls(), 2);
    std::fs::write(f.0.join("fail"), "").unwrap();
    let failed = f.usage(true);
    assert_eq!(failed.status.code(), Some(1));
    let stale: serde_json::Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(
        stale.as_object().unwrap().len(),
        before.as_object().unwrap().len()
    );
    assert_eq!(stale["providers"].as_array().unwrap().len(), 1);
    assert!(String::from_utf8_lossy(&failed.stderr).contains("unavailable"));
    std::fs::write(f.0.join("login"), "second@example.test").unwrap();
    let switched = f.usage(false);
    assert_eq!(switched.status.code(), Some(3));
    let switched: serde_json::Value = serde_json::from_slice(&switched.stdout).unwrap();
    assert!(switched["providers"].as_array().unwrap().is_empty());
}
#[tokio::test]
async fn rest_refresh_reuses_the_cli_cache() {
    let f = Fixture::new();
    assert!(f.usage(false).status.success());
    assert_eq!(f.calls(), 1);
    let mut cmd = tokio::process::Command::from(f.command());
    let mut child = cmd
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--no-saved-accounts",
            "--config",
        ])
        .arg(f.0.join("config.toml"))
        .env_remove("QUOTIO_SERVER_TOKEN")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let line = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let base = line.strip_prefix("Quotio API listening on ").unwrap();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let response = client.get(format!("{base}/v1/usage")).send().await.unwrap();
            if response.status().is_success() {
                let value: serde_json::Value = response.json().await.unwrap();
                assert_eq!(value["providers"].as_array().unwrap().len(), 1);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(f.calls(), 1);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}
