//! Quota-only queries using explicitly supplied, ephemeral credentials.
//! No native credential discovery, credential persistence or proxy mutations.
use super::*;
use crate::{
    domain::AccountRef,
    providers::{CredentialStore, FetchFuture, ProviderAdapter, Secret},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Query {
    pub provider: Provider,
    pub client_account_id: String,
    pub label: String,
    pub access_token: String,
    #[serde(default)]
    pub force: bool,
}
struct InputCredentials {
    token: String,
}
impl CredentialStore for InputCredentials {
    fn get(&self, key: &str) -> Option<Secret> {
        (key == "OPENROUTER_API_KEY").then(|| Secret(self.token.clone()))
    }
}
struct InputProvider {
    reference: AccountRef,
}
impl ProviderAdapter for InputProvider {
    fn id(&self) -> ProviderId {
        ProviderId("openrouter".into())
    }
    fn account_ref(&self) -> Option<AccountRef> {
        Some(self.reference.clone())
    }
    fn idempotent(&self) -> bool {
        true
    }
    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> FetchFuture<'a> {
        Box::pin(crate::providers::openrouter::fetch(context))
    }
}
fn validate(query: &Query) -> Result<(), ApiError> {
    if query.provider != Provider::OpenRouter {
        return Err(ApiError(StatusCode::BAD_REQUEST, "unsupported_usage_query"));
    }
    if query.client_account_id.is_empty()
        || query.client_account_id.len() > 256
        || query.client_account_id.chars().any(char::is_control)
        || query.label.is_empty()
        || query.label.len() > 512
        || query.label.chars().any(char::is_control)
        || query.access_token.trim().is_empty()
        || query.access_token.len() > 16384
        || query.access_token.chars().any(char::is_control)
    {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid_usage_query"));
    }
    Ok(())
}
pub(super) async fn start(
    State(state): State<Arc<ApiState>>,
    ApiJson(query): ApiJson<Query>,
) -> Result<(StatusCode, Json<Operation>), ApiError> {
    validate(&query)?;
    let ttl = state.settings.read().await.values.cache_ttl_seconds;
    let provider = Arc::new(InputProvider {
        reference: AccountRef {
            origin: None,
            id: query.client_account_id.clone(),
            label: query.label.clone(),
        },
    });
    enqueue(
        state,
        query,
        provider,
        crate::cache::UsageCache::platform(Duration::from_secs(ttl)),
    )
    .await
}
async fn enqueue(
    state: Arc<ApiState>,
    query: Query,
    provider: Arc<dyn ProviderAdapter>,
    cache: crate::cache::UsageCache,
) -> Result<(StatusCode, Json<Operation>), ApiError> {
    let timeout = Duration::from_secs(state.settings.read().await.values.provider_timeout);
    let (operation, _) = state
        .operations
        .lock()
        .await
        .start("usage_query", None, String::new())
        .map_err(operation_error)?;
    let work = state.clone();
    let id = operation.id.clone();
    if let Err(error) = state.spawn(async move {
        let collector = Collector {
            context: ProviderContext {
                http: work.context.http.clone(),
                clock: work.context.clock.clone(),
                credentials: Arc::new(InputCredentials {
                    token: query.access_token,
                }),
            },
        };
        let report = cache
            .collect(
                &collector,
                CollectRequest {
                    providers: vec![provider],
                    timeout,
                    cancellation: Cancellation::default(),
                },
                query.force,
            )
            .await;
        let result = serde_json::to_value(report)
            .map(|report| json!({"report":report}))
            .map_err(|_| "encoding_failed");
        work.operations.lock().await.finish(&id, result);
    }) {
        state
            .operations
            .lock()
            .await
            .finish(&operation.id, Err("server_busy"));
        return Err(error);
    }
    Ok((StatusCode::ACCEPTED, Json(operation)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    struct Probe {
        calls: Arc<AtomicUsize>,
    }
    impl ProviderAdapter for Probe {
        fn id(&self) -> ProviderId {
            ProviderId("openrouter".into())
        }
        fn account_ref(&self) -> Option<AccountRef> {
            Some(AccountRef {
                origin: None,
                id: "client-account".into(),
                label: "work".into(),
            })
        }
        fn fetch<'a>(&'a self, context: &'a ProviderContext) -> FetchFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                assert!(context.credentials.get("OPENROUTER_API_KEY").is_some());
                assert!(context.credentials.get("OTHER_SECRET").is_none());
                let mut usage = crate::providers::mock::MockProvider.fetch(context).await?;
                usage.provider = self.id();
                for window in &mut usage.windows {
                    window.fetched_at = context.clock.now();
                }
                Ok(usage)
            })
        }
    }
    fn query(token: &str, force: bool) -> Query {
        Query {
            provider: Provider::OpenRouter,
            client_account_id: "client-account".into(),
            label: "work".into(),
            access_token: token.into(),
            force,
        }
    }
    #[test]
    fn rejects_unknown_sources_and_control_characters() {
        assert!(validate(&query("fixture", false)).is_ok());
        assert!(validate(&query("fixture\n", false)).is_err());
        let mut unsupported = query("fixture", false);
        unsupported.provider = Provider::Codex;
        assert!(validate(&unsupported).is_err());
        assert!(serde_json::from_value::<Query>(json!({"provider":"openrouter","client_account_id":"x","label":"x","access_token":"fixture","credential_file":"/not-allowed"})).is_err());
    }
    #[tokio::test]
    async fn query_reuses_cache_respects_force_and_key_rotation_without_vault_writes() {
        let (state, directory, _) = super::super::tests::fixture().await;
        let before = crate::accounts::api::list(state.vault.clone().unwrap())
            .await
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let cache =
            crate::cache::UsageCache::new(directory.join("query-cache"), Duration::from_secs(300));
        for (token, force, expected) in [
            ("fixture-one", false, 1),
            ("fixture-one", false, 1),
            ("fixture-one", true, 2),
            ("fixture-two", false, 3),
        ] {
            let (_, Json(operation)) = enqueue(
                state.clone(),
                query(token, force),
                Arc::new(Probe {
                    calls: calls.clone(),
                }),
                cache.clone(),
            )
            .await
            .unwrap_or_else(|_| panic!());
            let completed = super::super::tests::done(&state, &operation.id).await;
            assert_eq!(completed.status, "completed");
            let encoded = serde_json::to_string(&completed).unwrap();
            assert!(!encoded.contains(token));
            assert_eq!(
                completed.result.unwrap()["report"]["providers"][0]["account_ref"]["id"],
                "client-account"
            );
            assert_eq!(calls.load(Ordering::SeqCst), expected);
        }
        let after = crate::accounts::api::list(state.vault.clone().unwrap())
            .await
            .unwrap();
        assert!(before == after);
        for file in std::fs::read_dir(directory.join("query-cache"))
            .unwrap()
            .flatten()
        {
            let bytes = std::fs::read(file.path()).unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains("fixture-one"));
            assert!(!String::from_utf8_lossy(&bytes).contains("fixture-two"));
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}
