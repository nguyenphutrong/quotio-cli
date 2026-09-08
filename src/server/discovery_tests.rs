use super::*;
use crate::accounts::{self, sources::QuotioDomain};

fn preferences(_: QuotioDomain) -> Result<Vec<u8>, accounts::AccountError> {
    Ok(br#"[{"id":"11111111-1111-1111-1111-111111111111","name":"planted-secret","type":"clinepass","is-enabled":true,"api-keys":[{"api-key":"planted-secret"}]},{"id":"22222222-2222-2222-2222-222222222222","name":"other","type":"glm-api-key","api-keys":[{"api-key":"not-selected"}]}]"#.to_vec())
}
#[tokio::test]
async fn discovery_rest_registers_opaque_exact_entries_without_credentials() {
    let (state, dir, _) = tests::fixture().await;
    let home = dir.canonicalize().unwrap();
    for (relative, contents) in [
        (
            ".grok/auth.json",
            r#"{"https://auth.x.ai::planted-secret":{"key":"planted-secret","expires_at":"2099-01-01T00:00:00Z"},"https://auth.x.ai::second":{"key":"second-fixture","expires_at":"2099-01-01T00:00:00Z"}}"#,
        ),
        (
            ".config/github-copilot/apps.json",
            r#"{"github.com:planted-secret":{"oauth_token":"planted-secret"}}"#,
        ),
    ] {
        let path = home.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    {
        let mut discovery = state.discovery.lock().unwrap();
        discovery.home = Some(home.clone());
        discovery.preferences = preferences;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let token = "synthetic-management-token-1234567890";
    let app = router(
        state.clone(),
        Arc::new(security::Policy::new(address, true, None, &[], Some(token.into())).unwrap()),
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let base = format!("http://{address}");
    let endpoint = format!("{base}/v1/account-sources/discover");
    assert_eq!(
        client
            .post(&endpoint)
            .json(&json!({"provider":"grok","kind":"grok_native","inspect":true}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    for (index, request) in [
        json!({"provider":"grok","kind":"grok_native","inspect":true}),
        json!({"provider":"copilot","kind":"copilot_native","location":"apps","inspect":true}),
        json!({"provider":"clinepass","kind":"quotio_custom_provider","domain":"production","inspect":true}),
    ].into_iter().enumerate() {
        let response = client.post(&endpoint).bearer_auth(token).json(&request).send().await.unwrap();
        assert_eq!(response.status(), 200);
        let discovered: Value = response.json().await.unwrap();
        assert_eq!(discovered["status"], "checked", "{discovered}");
        assert_eq!(discovered["candidates"].as_array().unwrap().len(), if index == 0 { 2 } else { 1 });
        assert_eq!(discovered["candidates"][0]["status"], "available");
        for forbidden in ["planted-secret", "11111111", "oauth_token", "entry_key", home.to_str().unwrap()] {
            assert!(!discovered.to_string().contains(forbidden));
        }
        for (candidate_index, candidate) in discovered["candidates"].as_array().unwrap().iter().enumerate() {
        let response = client.post(format!("{base}/v1/account-sources"))
            .bearer_auth(token).header("Idempotency-Key", format!("discovery-{index}-{candidate_index}"))
            .json(&candidate["source"]).send().await.unwrap();
        assert_eq!(response.status(), 202);
        let operation: Value = response.json().await.unwrap();
        let completed = serde_json::to_value(tests::done(&state, operation["id"].as_str().unwrap()).await).unwrap();
        assert_eq!(completed["status"], "completed", "{completed}");
        let id = completed["result"]["account_id"].as_str().unwrap();
        let account: Value = client.get(format!("{base}/v1/accounts/{id}")).bearer_auth(token).send().await.unwrap().json().await.unwrap();
        assert_eq!(account["provider"], request["provider"]);
        assert!(!account.to_string().contains("planted-secret"));
        }
    }
    for request in [
        json!({"provider":"grok","kind":"copilot_native","inspect":true}),
        json!({"provider":"copilot","kind":"copilot_native","inspect":true}),
        json!({"provider":"grok","kind":"grok_native","path":"/.cli-proxy-api","inspect":true}),
        json!({"provider":"clinepass","kind":"quotio_custom_provider","inspect":true}),
    ] {
        assert_eq!(
            client
                .post(&endpoint)
                .bearer_auth(token)
                .json(&request)
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
    }
    for (request, status) in [
        (
            json!({"provider":"claude","kind":"claude_native"}),
            "not_checked",
        ),
        (
            json!({"provider":"copilot","kind":"copilot_native","location":"gh_keychain","inspect":true}),
            "unsupported",
        ),
    ] {
        let value: Value = client
            .post(&endpoint)
            .bearer_auth(token)
            .json(&request)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(value["status"], status);
    }
    // A read-only server rejects inspection even with its valid bearer token.
    let readonly = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = readonly.local_addr().unwrap();
    let app = router(
        state.clone(),
        Arc::new(security::Policy::new(address, false, None, &[], Some(token.into())).unwrap()),
    );
    let read_server = tokio::spawn(async move { axum::serve(readonly, app).await.unwrap() });
    assert_eq!(
        client
            .post(format!("http://{address}/v1/account-sources/discover"))
            .bearer_auth(token)
            .json(&json!({"provider":"grok","kind":"grok_native","inspect":true}))
            .send()
            .await
            .unwrap()
            .status(),
        405
    );
    read_server.abort();
    server.abort();
    std::fs::remove_dir_all(dir).unwrap();
}
