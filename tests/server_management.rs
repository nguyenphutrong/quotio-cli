use serde_json::{Value, json};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, BufReader};
const TOKEN: &str = "synthetic-management-api-token-1234567890";
struct Server {
    child: tokio::process::Child,
    dir: PathBuf,
    base: String,
    client: reqwest::Client,
}
impl Server {
    async fn start(extra: &[&str]) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "quotio-management-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("config.toml"), "enabled_providers = []\n").unwrap();
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_quotio"))
            .args([
                "serve",
                "--listen",
                "127.0.0.1:0",
                "--no-saved-accounts",
                "--config",
            ])
            .arg(dir.join("config.toml"))
            .args(extra)
            .env("QUOTIO_SERVER_TOKEN", TOKEN)
            .env("QUOTIO_CACHE_DIR", dir.join("cache"))
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
        let base = line
            .strip_prefix("Quotio API listening on ")
            .unwrap()
            .into();
        Self {
            child,
            dir,
            base,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
        }
    }
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(TOKEN)
    }
    async fn get(&self, path: &str) -> Value {
        let r = self
            .request(reqwest::Method::GET, path)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        r.json().await.unwrap()
    }
    async fn done(&self, id: &str) -> Value {
        for _ in 0..100 {
            let op = self.get(&format!("/v1/operations/{id}")).await;
            if op["status"] != "running" {
                return op;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("operation timed out")
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
#[tokio::test]
async fn empty_onboarding_settings_refresh_and_revision_conflicts() {
    let server = Server::start(&["--manage"]).await;
    let settings = server.get("/v1/settings").await;
    assert_eq!(settings["enabled_providers"], json!([]));
    assert_eq!(settings["cache_ttl_seconds"], 300);
    let body = json!({"revision":settings["revision"],"enabled_providers":["mock"],"refresh_interval":3600,"cache_ttl_seconds":45});
    let response = server
        .request(reqwest::Method::PATCH, "/v1/settings")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let changed: Value = response.json().await.unwrap();
    assert_ne!(settings["revision"], changed["revision"]);
    assert_eq!(
        server
            .request(reqwest::Method::PATCH, "/v1/settings")
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert!(
        std::fs::read_to_string(server.dir.join("config.toml"))
            .unwrap()
            .contains("45")
    );
    let response = server
        .request(reqwest::Method::POST, "/v1/refresh")
        .json(&json!({"providers":["mock"],"force":true}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 202);
    let op: Value = response.json().await.unwrap();
    let done = server.done(op["id"].as_str().unwrap()).await;
    assert_eq!(done["status"], "completed");
    let usage = server.get("/v1/usage/mock").await;
    assert_eq!(usage["providers"][0]["provider"], "mock");
    assert_eq!(
        server
            .request(reqwest::Method::POST, "/v1/refresh")
            .json(&json!({"providers":["codex"]}))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        server
            .request(reqwest::Method::PATCH, "/v1/settings")
            .json(&json!({"revision":changed["revision"],"secret_field":"sentinel"}))
            .send()
            .await
            .unwrap()
            .status(),
        422
    );
}
#[tokio::test]
async fn remote_policy_preflight_limits_and_read_only() {
    let server = Server::start(&[
        "--manage",
        "--public-url",
        "https://quotio.example",
        "--allow-origin",
        "https://dashboard.example",
    ])
    .await;
    let response = server
        .client
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/v1/settings", server.base),
        )
        .header("host", "quotio.example")
        .header("origin", "https://dashboard.example")
        .header("access-control-request-method", "PATCH")
        .header(
            "access-control-request-headers",
            "authorization,content-type",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "https://dashboard.example"
    );
    assert_eq!(
        server
            .client
            .get(format!("{}/health", server.base))
            .header("origin", "https://dashboard.example")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        server
            .request(reqwest::Method::GET, "/health")
            .header("host", "quotio.example")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        server
            .request(reqwest::Method::GET, "/health")
            .header("host", "attacker.example")
            .header("x-forwarded-host", "quotio.example")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let large = server
        .request(reqwest::Method::POST, "/v1/refresh")
        .header("content-type", "application/json")
        .body(" ".repeat(65537))
        .send()
        .await
        .unwrap();
    assert_eq!(large.status(), 413);
    assert_eq!(
        large.json::<Value>().await.unwrap()["error"],
        "body_too_large"
    );
    let readonly = Server::start(&[]).await;
    assert_eq!(
        readonly
            .request(reqwest::Method::POST, "/v1/refresh")
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        405
    );
    let overridden = Server::start(&["--manage", "--provider", "mock"]).await;
    let settings = overridden.get("/v1/settings").await;
    assert_eq!(settings["overridden"], json!(["enabled_providers"]));
    assert_eq!(
        overridden
            .request(reqwest::Method::PATCH, "/v1/settings")
            .json(&json!({"revision":settings["revision"],"enabled_providers":[]}))
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
}

#[tokio::test]
async fn completed_refresh_history_does_not_exhaust_operation_capacity() {
    let server = Server::start(&[
        "--manage",
        "--provider",
        "mock",
        "--refresh-interval",
        "3600",
    ])
    .await;
    for _ in 0..140 {
        let response = server
            .request(reqwest::Method::POST, "/v1/refresh")
            .json(&json!({"force": false}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 202);
        let op: Value = response.json().await.unwrap();
        assert_eq!(
            server.done(op["id"].as_str().unwrap()).await["status"],
            "completed"
        );
    }
}
