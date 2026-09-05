use clap::Parser;
use quotio::cli::{Cli, Command, ServeArgs};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, BufReader};

struct Config(PathBuf);
impl Config {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("quotio-server-{}-{name}.toml", std::process::id()));
        std::fs::write(&path, "enabled_providers = []\n").unwrap();
        Self(path)
    }
}
impl Drop for Config {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn server_argument_contract() {
    let Command::Serve(args) = Cli::try_parse_from(["quotio", "serve"]).unwrap().command else {
        panic!()
    };
    assert_eq!(args.listen.to_string(), "127.0.0.1:8317");
    assert_eq!(args.refresh_interval, 60);
    for args in [
        vec!["--refresh-interval", "0"],
        vec!["--refresh-interval", "86401"],
        vec!["--timeout", "0"],
        vec!["--listen", "example.com:8317"],
        vec!["--token", "must-not-be-in-argv"],
    ] {
        assert!(Cli::try_parse_from(["quotio", "serve"].into_iter().chain(args)).is_err());
    }
}

#[tokio::test]
async fn startup_rejects_remote_bind_empty_selection_and_occupied_port() {
    let config = Config::new("startup");
    let args = || ServeArgs {
        listen: "127.0.0.1:0".parse().unwrap(),
        provider: vec![],
        config: Some(config.0.clone()),
        refresh_interval: 60,
        timeout: 1,
        no_saved_accounts: true,
    };
    assert!(matches!(
        quotio::server::run(args()).await,
        Err(quotio::server::ServerError::Providers)
    ));
    let mut remote = args();
    remote.listen = "0.0.0.0:8317".parse().unwrap();
    assert!(matches!(
        quotio::server::run(remote).await,
        Err(quotio::server::ServerError::Listen)
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut occupied = args();
    occupied.listen = listener.local_addr().unwrap();
    occupied.provider = vec![quotio::cli::Provider::Mock];
    assert!(matches!(
        quotio::server::run(occupied).await,
        Err(quotio::server::ServerError::Bind)
    ));
}

#[tokio::test]
async fn http_snapshots_security_and_process_shutdown() {
    let config = Config::new("http");
    let token = "synthetic-server-test-bearer-1234567890";
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_quotio"))
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--provider",
            "mock",
            "--no-saved-accounts",
            "--config",
        ])
        .arg(&config.0)
        .env("QUOTIO_SERVER_TOKEN", token)
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
    assert!(!line.contains(token));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let get = |path: &str| client.get(format!("{base}{path}")).bearer_auth(token);
    let mut ready = false;
    for _ in 0..100 {
        let value: serde_json::Value = get("/health").send().await.unwrap().json().await.unwrap();
        if value["ready"] == true {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(ready);
    let response = get("/v1/usage").send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(
        !response
            .headers()
            .contains_key("access-control-allow-origin")
    );
    let snapshot: serde_json::Value = response.json().await.unwrap();
    assert_eq!(snapshot["schema_version"], 1);
    assert_eq!(snapshot["providers"][0]["provider"], "mock");
    assert_eq!(snapshot["failures"].as_array().unwrap().len(), 0);
    let filtered: serde_json::Value = get("/v1/usage/mock")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(snapshot, filtered);
    let catalog: serde_json::Value = get("/v1/providers")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        catalog["providers"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["enabled"] == true)
            .count(),
        1
    );
    for (path, status) in [
        ("/v1/usage/codex", 404),
        ("/v1/usage/not-a-provider", 404),
        ("/missing", 404),
        ("/v1/usage?token=private", 400),
    ] {
        let response = get(path).send().await.unwrap();
        assert_eq!(response.status(), status);
        assert!(!response.text().await.unwrap().contains("private"));
    }
    assert_eq!(
        client
            .get(format!("{base}/health"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        get("/health")
            .header("origin", "https://untrusted.example")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        get("/health")
            .header("host", "untrusted.example")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        get("/health")
            .header("authorization", "Bearer wrong")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .post(format!("{base}/v1/usage"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status(),
        405
    );
    // Keep an idle TCP client open while shutting down, to exercise the drain bound.
    let _idle = tokio::net::TcpStream::connect(base.trim_start_matches("http://"))
        .await
        .unwrap();
    #[cfg(unix)]
    {
        assert_eq!(
            unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGTERM) },
            0
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(5), child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
    }
    #[cfg(not(unix))]
    child.kill().await.unwrap();
}
