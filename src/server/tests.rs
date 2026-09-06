use super::*;
use crate::accounts::{
    self, AccountError, Credential,
    vault::{Backend, Vault},
};
#[derive(Default)]
struct Memory(std::sync::Mutex<Option<Vec<u8>>>);
impl Backend for Memory {
    fn read(&self) -> Result<Option<Vec<u8>>, AccountError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn write(&self, bytes: &[u8]) -> Result<(), AccountError> {
        *self.0.lock().unwrap() = Some(bytes.into());
        Ok(())
    }
}
async fn fixture() -> (Arc<ApiState>, std::path::PathBuf, String) {
    let dir = std::env::temp_dir().join(format!(
        "quotio-api-test-{}",
        accounts::random_string().unwrap()
    ));
    std::fs::create_dir(&dir).unwrap();
    let vault = Vault::new(Arc::new(Memory::default()), dir.join("vault.lock"));
    let id = accounts::service::add(
        vault.clone(),
        Provider::Amp,
        "old label".into(),
        Credential::ApiKey {
            token: "synthetic-vault-secret".into(),
            region: None,
            organization: None,
        },
        "fake-identity".into(),
    )
    .await
    .unwrap();
    let store = SettingsStore::new(dir.join("config.toml"), Overrides::default());
    let view = store.load().unwrap();
    let context = ProviderContext {
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap(),
        clock: Arc::new(SystemClock),
        credentials: Arc::new(EnvironmentCredentials),
    };
    let generation = Arc::new(AtomicU64::new(0));
    let guard = Arc::new(Mutex::new(()));
    let manager = accounts::oauth::OAuthSessionManager::new(
        context.clone(),
        vault.clone(),
        guard.clone(),
        generation.clone(),
    );
    (
        Arc::new(ApiState {
            settings: RwLock::new(view),
            store,
            snapshot: RwLock::new(None),
            generation,
            commit_guard: guard,
            refresh_lock: Mutex::new(()),
            pending: Mutex::new(HashMap::new()),
            wake: Notify::new(),
            operations: Mutex::new(Operations::default()),
            jobs: std::sync::Mutex::new(vec![]),
            status: Mutex::new(RefreshStatus::default()),
            context,
            no_saved_accounts: true,
            manage: true,
            vault: Some(vault),
            oauth: Some(manager),
        }),
        dir,
        id,
    )
}
fn key(value: &str) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("idempotency-key", value.parse().unwrap());
    headers
}
async fn done(state: &ApiState, id: &str) -> Operation {
    for _ in 0..100 {
        let op = state.operations.lock().await.get(id).unwrap();
        if op.status != "running" {
            return op;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("operation timeout")
}
#[tokio::test]
async fn account_http_services_are_secret_free_idempotent_and_fenced() {
    let (state, dir, id) = fixture().await;
    let Json(accounts) = management::list(State(state.clone()))
        .await
        .unwrap_or_else(|_| panic!());
    assert!(!accounts.to_string().contains("synthetic-vault-secret"));
    assert!(!accounts.to_string().contains("credential"));
    let body = json!({"label":"new label","active":true});
    let (_, Json(op)) = management::patch(
        State(state.clone()),
        Path(id.clone()),
        key("change-1"),
        ApiJson(body.clone()),
    )
    .await
    .unwrap_or_else(|_| panic!());
    assert_eq!(done(&state, &op.id).await.status, "completed");
    assert_eq!(state.generation.load(Ordering::SeqCst), 1);
    let (_, Json(retry)) = management::patch(
        State(state.clone()),
        Path(id.clone()),
        key("change-1"),
        ApiJson(body),
    )
    .await
    .unwrap_or_else(|_| panic!());
    assert_eq!(op.id, retry.id);
    assert!(matches!(
        management::patch(
            State(state.clone()),
            Path(id.clone()),
            key("change-1"),
            ApiJson(json!({"label":"different"}))
        )
        .await,
        Err(ApiError(StatusCode::CONFLICT, _))
    ));
    let (_, Json(invalid)) = management::create(
        State(state.clone()),
        key("create-1"),
        ApiJson(json!({"provider":"amp","api_key":""})),
    )
    .await
    .unwrap_or_else(|_| panic!());
    assert_eq!(
        done(&state, &invalid.id).await.error,
        Some("invalid_credential")
    );
    let (_, Json(remove)) =
        management::remove(State(state.clone()), Path(id.clone()), key("remove-1"))
            .await
            .unwrap_or_else(|_| panic!());
    assert_eq!(done(&state, &remove.id).await.status, "completed");
    assert!(matches!(
        management::get_account(State(state.clone()), Path(id)).await,
        Err(ApiError(StatusCode::NOT_FOUND, _))
    ));
    // A late pre-delete refresh cannot be read even if its report arrives afterwards.
    *state.snapshot.write().await = Some((
        0,
        UsageReport {
            schema_version: 1,
            generated_at: state.context.clock.now(),
            providers: vec![],
            failures: vec![],
        },
    ));
    assert_eq!(
        usage_response(&state, None, None).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn external_config_conflict_recovers_and_refresh_requests_coalesce() {
    let (state, dir, _) = fixture().await;
    let initial = state.settings.read().await.revision.clone();
    std::fs::write(dir.join("config.toml"), "enabled_providers = [\"mock\"]\n").unwrap();
    let Json(view) = settings(State(state.clone()))
        .await
        .unwrap_or_else(|_| panic!());
    assert_ne!(initial, view.revision);
    assert_eq!(
        state.settings.read().await.values.enabled_providers,
        vec!["mock"]
    );
    let refresh_guard = state.refresh_lock.lock().await;
    let request = || RefreshRequest {
        providers: vec![Provider::Mock],
        account_id: None,
        force: true,
    };
    let (_, Json(first)) = manual_refresh(State(state.clone()), ApiJson(request()))
        .await
        .unwrap_or_else(|_| panic!());
    let (_, Json(second)) = manual_refresh(State(state.clone()), ApiJson(request()))
        .await
        .unwrap_or_else(|_| panic!());
    assert_eq!(first.id, second.id);
    // Change enabled scope while a queued refresh waits; it must not publish old scope.
    state
        .settings
        .write()
        .await
        .values
        .enabled_providers
        .clear();
    state.invalidate().await;
    drop(refresh_guard);
    assert_eq!(
        done(&state, &first.id).await.error,
        Some("refresh_scope_changed")
    );
    assert!(state.snapshot.read().await.is_none());
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn blocked_mutation_guard_returns_bounded_errors() {
    let (state, dir, _) = fixture().await;
    let held = state.commit_guard.lock().await;
    tokio::time::pause();
    assert_eq!(
        usage_response(&state, None, None).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(matches!(
        settings(State(state.clone())).await,
        Err(ApiError(StatusCode::CONFLICT, "settings_busy"))
    ));
    tokio::time::resume();
    drop(held);
    assert!(settings(State(state)).await.is_ok());
    std::fs::remove_dir_all(dir).unwrap();
}
