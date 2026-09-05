use super::{
    Account, AccountError, Credential,
    vault::{Transaction, Vault},
};
use crate::{
    cli::Provider,
    domain::{ProviderId, ProviderUsage},
    error::ProviderError,
    providers::{
        CredentialStore, FetchFuture, ProviderAdapter, ProviderContext, Secret,
        amp::AmpApiProvider, codex_api, factory::FactoryProvider,
    },
};
use std::{collections::HashMap, sync::Arc};

pub struct Keys(HashMap<String, String>);
impl CredentialStore for Keys {
    fn get(&self, name: &str) -> Option<Secret> {
        self.0.get(name).cloned().map(Secret)
    }
}
fn scoped(
    context: &ProviderContext,
    provider: Provider,
    credential: &Credential,
) -> Result<ProviderContext, AccountError> {
    let mut keys = HashMap::new();
    if let Credential::ApiKey {
        token,
        region,
        organization,
    } = credential
    {
        let key = match provider {
            Provider::Amp => "AMP_API_KEY",
            Provider::Factory => "FACTORY_API_KEY",
            _ => return Err(AccountError::Unsupported),
        };
        keys.insert(key.into(), token.clone());
        if provider == Provider::Factory {
            if let Some(region) = region {
                keys.insert("FACTORY_REGION".into(), region.clone());
            }
            if let Some(org) = organization {
                keys.insert("FACTORY_ORG_ID".into(), org.clone());
            }
        }
    }
    Ok(ProviderContext {
        http: context.http.clone(),
        clock: context.clock.clone(),
        credentials: Arc::new(Keys(keys)),
    })
}
pub async fn validate(
    context: &ProviderContext,
    provider: Provider,
    credential: &Credential,
) -> Result<ProviderUsage, AccountError> {
    let ctx = scoped(context, provider, credential)?;
    let usage = match provider {
        Provider::Amp => AmpApiProvider.fetch(&ctx).await?,
        Provider::Factory => FactoryProvider.fetch(&ctx).await?,
        Provider::Codex => codex_api::fetch(&ctx, credential).await?,
        _ => return Err(AccountError::Unsupported),
    };
    if usage.windows.is_empty()
        || usage.account.id.is_empty()
        || usage.windows.iter().any(|w| !w.quota.is_valid())
    {
        return Err(ProviderError::InvalidData.into());
    }
    Ok(usage)
}
async fn begin(vault: Vault) -> Result<Transaction, AccountError> {
    loop {
        let copy = vault.clone();
        match tokio::task::spawn_blocking(move || copy.begin())
            .await
            .map_err(|_| AccountError::Storage)?
        {
            Err(AccountError::Busy) => {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await
            }
            result => return result,
        }
    }
}
async fn commit(tx: Transaction) -> Result<(), AccountError> {
    tokio::task::spawn_blocking(move || tx.commit())
        .await
        .map_err(|_| AccountError::Storage)?
}
pub async fn add(
    vault: Vault,
    provider: Provider,
    label: String,
    credential: Credential,
    identity: String,
) -> Result<String, AccountError> {
    let mut tx = begin(vault).await?;
    let id = tx.document.add(provider, &label, identity, credential)?;
    commit(tx).await?;
    Ok(id)
}
pub async fn list(vault: Vault) -> Result<Vec<Account>, AccountError> {
    Ok(begin(vault).await?.document.accounts.clone())
}
pub async fn select(vault: Vault, id: String) -> Result<(), AccountError> {
    let mut tx = begin(vault).await?;
    tx.document.select(&id)?;
    commit(tx).await
}
pub async fn remove(vault: Vault, id: String) -> Result<(), AccountError> {
    let mut tx = begin(vault).await?;
    tx.document.remove(&id)?;
    commit(tx).await
}

type OperationFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, AccountError>> + Send + 'a>>;
trait Operations: Send + Sync {
    fn quota<'a>(
        &'a self,
        context: &'a ProviderContext,
        provider: Provider,
        credential: &'a Credential,
    ) -> OperationFuture<'a, ProviderUsage>;
    fn refresh<'a>(
        &'a self,
        context: &'a ProviderContext,
        credential: &'a Credential,
    ) -> OperationFuture<'a, Credential>;
}
struct Network;
impl Operations for Network {
    fn quota<'a>(
        &'a self,
        c: &'a ProviderContext,
        p: Provider,
        k: &'a Credential,
    ) -> OperationFuture<'a, ProviderUsage> {
        Box::pin(validate(c, p, k))
    }
    fn refresh<'a>(
        &'a self,
        c: &'a ProviderContext,
        k: &'a Credential,
    ) -> OperationFuture<'a, Credential> {
        Box::pin(super::oauth::refresh(c, k))
    }
}
struct ManagedProvider {
    operations: Arc<dyn Operations>,
    vault: Vault,
    id: String,
    provider: Provider,
    provider_id: ProviderId,
}
impl ManagedProvider {
    async fn read(&self, context: &ProviderContext) -> Result<ProviderUsage, AccountError> {
        let tx = begin(self.vault.clone()).await?;
        let account = tx
            .document
            .accounts
            .iter()
            .find(|a| a.id == self.id && a.provider == self.provider)
            .ok_or(AccountError::NotFound)?
            .clone();
        drop(tx);
        let credential = account.credential;
        if self.provider != Provider::Codex {
            return self
                .operations
                .quota(context, self.provider, &credential)
                .await;
        }
        let needs_refresh = matches!(&credential,Credential::CodexOAuth{expires_at,..} if *expires_at<=context.clock.now().unix_timestamp()+60);
        if !needs_refresh {
            match self
                .operations
                .quota(context, self.provider, &credential)
                .await
            {
                Ok(usage) => return Ok(usage),
                Err(AccountError::Provider(ProviderError::Authentication)) => (),
                Err(error) => return Err(error),
            }
        }
        let mut tx = begin(self.vault.clone()).await?;
        let index = tx
            .document
            .accounts
            .iter()
            .position(|a| a.id == self.id && a.provider == self.provider)
            .ok_or(AccountError::NotFound)?;
        let latest = tx.document.accounts[index].credential.clone();
        let changed = matches!((&credential,&latest),(Credential::CodexOAuth{access_token:old,..},Credential::CodexOAuth{access_token:new,..}) if old!=new);
        if changed {
            drop(tx);
            return self.operations.quota(context, self.provider, &latest).await;
        }
        let updated = self.operations.refresh(context, &latest).await?;
        tx.document.accounts[index].credential = updated.clone();
        // Rotation must reach the vault before another quota request can succeed.
        commit(tx).await?;
        self.operations
            .quota(context, self.provider, &updated)
            .await
    }
}
impl ProviderAdapter for ManagedProvider {
    fn id(&self) -> ProviderId {
        self.provider_id.clone()
    }
    fn idempotent(&self) -> bool {
        self.provider != Provider::Codex
    }
    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> FetchFuture<'a> {
        Box::pin(async move {
            self.read(context).await.map_err(|e| match e {
                AccountError::Provider(e) => e,
                AccountError::Busy => ProviderError::Transient,
                AccountError::Storage | AccountError::Corrupt => ProviderError::CredentialStorage,
                _ => ProviderError::Authentication,
            })
        })
    }
}
struct FailedProvider {
    provider_id: ProviderId,
}
impl ProviderAdapter for FailedProvider {
    fn id(&self) -> ProviderId {
        self.provider_id.clone()
    }
    fn fetch<'a>(&'a self, _: &'a ProviderContext) -> FetchFuture<'a> {
        Box::pin(async { Err(ProviderError::CredentialStorage) })
    }
}
async fn discover(
    vault: Vault,
    timeout: std::time::Duration,
) -> Result<Vec<Account>, AccountError> {
    tokio::time::timeout(timeout, list(vault))
        .await
        .unwrap_or(Err(AccountError::Busy))
}
pub async fn adapters(
    providers: Vec<Provider>,
    saved: bool,
    timeout: std::time::Duration,
) -> Vec<Arc<dyn ProviderAdapter>> {
    if !saved
        || !cfg!(target_os = "macos")
        || !providers
            .iter()
            .any(|p| matches!(p, Provider::Amp | Provider::Codex | Provider::Factory))
    {
        return providers.into_iter().map(Provider::adapter).collect();
    }
    let vault = match Vault::system() {
        Ok(v) => v,
        Err(_) => {
            return providers
                .into_iter()
                .map(|p| {
                    if p == Provider::Mock {
                        p.adapter()
                    } else {
                        Arc::new(FailedProvider {
                            provider_id: p.adapter().id(),
                        }) as Arc<dyn ProviderAdapter>
                    }
                })
                .collect();
        }
    };
    let accounts = discover(vault.clone(), timeout).await;
    providers
        .into_iter()
        .map(|p| {
            if !matches!(p, Provider::Amp | Provider::Codex | Provider::Factory) {
                return p.adapter();
            }
            match &accounts {
                Err(_) => Arc::new(FailedProvider {
                    provider_id: p.adapter().id(),
                }) as Arc<dyn ProviderAdapter>,
                Ok(accounts) => match accounts.iter().find(|a| a.provider == p && a.active) {
                    Some(a) => Arc::new(ManagedProvider {
                        operations: Arc::new(Network),
                        vault: vault.clone(),
                        id: a.id.clone(),
                        provider: p,
                        provider_id: p.adapter().id(),
                    }) as Arc<dyn ProviderAdapter>,
                    None => p.adapter(),
                },
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        accounts::{
            random_string,
            vault::{Backend, tests::Memory},
        },
        fetch::{Cancellation, CollectRequest, Collector},
        providers::{http, mock::MockProvider},
    };
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    struct Fake {
        memory: Arc<Memory>,
        started: tokio::sync::Notify,
        delay: bool,
        refresh_fails: bool,
        quota_fails: bool,
        refreshes: AtomicUsize,
    }
    impl Operations for Fake {
        fn quota<'a>(
            &'a self,
            c: &'a ProviderContext,
            p: Provider,
            k: &'a Credential,
        ) -> OperationFuture<'a, ProviderUsage> {
            Box::pin(async move {
                if p == Provider::Codex && self.delay {
                    self.started.notify_one();
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                if let Credential::CodexOAuth { access_token, .. } = k
                    && access_token == "new"
                {
                    let doc: super::super::Document =
                        serde_json::from_slice(&self.memory.read().unwrap().unwrap()).unwrap();
                    assert!(
                        matches!(&doc.accounts[0].credential,Credential::CodexOAuth{refresh_token,..} if refresh_token=="rotated")
                    );
                }
                if self.quota_fails {
                    return Err(ProviderError::Unavailable.into());
                }
                let mut usage = MockProvider.fetch(c).await?;
                usage.provider = p.adapter().id();
                Ok(usage)
            })
        }
        fn refresh<'a>(
            &'a self,
            _: &'a ProviderContext,
            k: &'a Credential,
        ) -> OperationFuture<'a, Credential> {
            Box::pin(async move {
                self.refreshes.fetch_add(1, Ordering::SeqCst);
                if self.refresh_fails {
                    return Err(ProviderError::Transient.into());
                }
                let mut k = k.clone();
                if let Credential::CodexOAuth {
                    access_token,
                    refresh_token,
                    expires_at,
                    ..
                } = &mut k
                {
                    *access_token = "new".into();
                    *refresh_token = "rotated".into();
                    *expires_at = 3600;
                }
                Ok(k)
            })
        }
    }
    fn setup(
        expires_at: i64,
        delay: bool,
        refresh_fails: bool,
        quota_fails: bool,
    ) -> (Vault, Arc<Fake>, String, String, std::path::PathBuf) {
        let memory = Arc::new(Memory::default());
        let path = std::env::temp_dir().join(random_string().unwrap());
        let vault = Vault::new(memory.clone(), path.join("lock"));
        let mut tx = vault.begin().unwrap();
        let codex = tx
            .document
            .add(
                Provider::Codex,
                "Codex",
                "codex-id".into(),
                Credential::CodexOAuth {
                    access_token: "old".into(),
                    refresh_token: "refresh".into(),
                    id_token: "unused".into(),
                    account_id: "codex-id".into(),
                    email: "demo@example.com".into(),
                    expires_at,
                },
            )
            .unwrap();
        let amp = tx
            .document
            .add(
                Provider::Amp,
                "Amp",
                "amp-id".into(),
                Credential::ApiKey {
                    token: "api-key".into(),
                    region: None,
                    organization: None,
                },
            )
            .unwrap();
        tx.commit().unwrap();
        let fake = Arc::new(Fake {
            memory,
            started: tokio::sync::Notify::new(),
            delay,
            refresh_fails,
            quota_fails,
            refreshes: AtomicUsize::new(0),
        });
        (vault, fake, codex, amp, path)
    }
    fn managed(
        vault: Vault,
        operations: Arc<Fake>,
        id: String,
        provider: Provider,
    ) -> ManagedProvider {
        ManagedProvider {
            vault,
            operations,
            id,
            provider,
            provider_id: provider.adapter().id(),
        }
    }
    fn cleanup(path: std::path::PathBuf) {
        std::fs::remove_file(path.join("lock")).unwrap();
        std::fs::remove_dir(path).unwrap();
    }
    #[tokio::test]
    async fn ordinary_codex_fetch_does_not_lock_out_other_providers() {
        let (vault, fake, codex, amp, path) = setup(3600, true, false, false);
        let provider = managed(vault.clone(), fake.clone(), codex, Provider::Codex);
        let context = http::fixture::context();
        let running = tokio::spawn(async move { provider.read(&context).await });
        fake.started.notified().await;
        let amp = managed(vault, fake, amp, Provider::Amp);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(200),
                amp.read(&http::fixture::context())
            )
            .await
            .unwrap()
            .is_ok()
        );
        assert!(running.await.unwrap().is_ok());
        cleanup(path);
    }
    #[tokio::test]
    async fn uncertain_refresh_is_not_replayed() {
        let (vault, fake, id, _, path) = setup(0, false, true, false);
        let provider = managed(vault, fake.clone(), id, Provider::Codex);
        assert!(!provider.idempotent());
        let report = Collector {
            context: http::fixture::context(),
        }
        .collect(CollectRequest {
            providers: vec![Arc::new(provider)],
            timeout: Duration::from_secs(2),
            cancellation: Cancellation::default(),
        })
        .await;
        assert_eq!(report.exit_code(), 3);
        assert_eq!(fake.refreshes.load(Ordering::SeqCst), 1);
        cleanup(path);
    }
    #[tokio::test]
    async fn rotation_is_saved_before_failed_quota_and_storage_errors_fail_closed() {
        for fail_write in [false, true] {
            let (vault, fake, id, _, path) = setup(0, false, false, true);
            fake.memory.fail.store(fail_write, Ordering::SeqCst);
            let provider = managed(vault.clone(), fake.clone(), id, Provider::Codex);
            let result = provider.read(&http::fixture::context()).await;
            if fail_write {
                assert!(matches!(result, Err(AccountError::Storage)));
            } else {
                assert!(matches!(
                    result,
                    Err(AccountError::Provider(ProviderError::Unavailable))
                ));
            }
            let tx = begin(vault.clone()).await.unwrap();
            assert!(
                matches!(&tx.document.accounts[0].credential,Credential::CodexOAuth{access_token,..} if access_token==if fail_write{"old"}else{"new"})
            );
            drop(tx);
            cleanup(path);
        }
    }
    #[tokio::test]
    async fn discovery_obeys_timeout_while_another_transaction_holds_lock() {
        let (vault, _, _, _, path) = setup(3600, false, false, false);
        let held = vault.begin().unwrap();
        assert!(matches!(
            discover(vault, std::time::Duration::from_millis(30)).await,
            Err(AccountError::Busy)
        ));
        drop(held);
        cleanup(path);
    }
}
