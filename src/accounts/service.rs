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
async fn refresh_lock(vault: Vault, id: String) -> Result<std::fs::File, AccountError> {
    loop {
        let copy = vault.clone();
        let account = id.clone();
        match tokio::task::spawn_blocking(move || copy.refresh_lock(&account))
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
    label: String,
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
        let guard = refresh_lock(self.vault.clone(), self.id.clone()).await?;
        let tx = begin(self.vault.clone()).await?;
        let latest = tx
            .document
            .accounts
            .iter()
            .find(|a| a.id == self.id && a.provider == self.provider)
            .ok_or(AccountError::NotFound)?
            .credential
            .clone();
        drop(tx);
        if credential != latest {
            drop(guard);
            return self.operations.quota(context, self.provider, &latest).await;
        }
        let updated = self.operations.refresh(context, &latest).await?;
        let mut tx = begin(self.vault.clone()).await?;
        let account = tx
            .document
            .accounts
            .iter_mut()
            .find(|a| a.id == self.id && a.provider == self.provider)
            .ok_or(AccountError::NotFound)?;
        if account.credential != latest {
            return Err(AccountError::Busy);
        }
        account.credential = updated.clone();
        // Persist rotation without holding the global vault lock during network IO.
        commit(tx).await?;
        drop(guard);
        self.operations
            .quota(context, self.provider, &updated)
            .await
    }
}
impl ProviderAdapter for ManagedProvider {
    fn account_ref(&self) -> Option<crate::domain::AccountRef> {
        Some(crate::domain::AccountRef {
            id: self.id.clone(),
            label: self.label.clone(),
        })
    }
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
    account_ref: Option<crate::domain::AccountRef>,
    provider_id: ProviderId,
}
impl ProviderAdapter for FailedProvider {
    fn account_ref(&self) -> Option<crate::domain::AccountRef> {
        self.account_ref.clone()
    }
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
fn local_codex_available() -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| {
            let path = dir.join(if cfg!(windows) { "codex.exe" } else { "codex" });
            path.metadata().is_ok_and(|m| {
                if !m.is_file() {
                    return false;
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    m.permissions().mode() & 0o111 != 0
                }
                #[cfg(not(unix))]
                {
                    true
                }
            })
        })
    })
}
fn managed(vault: &Vault, account: &Account) -> Arc<dyn ProviderAdapter> {
    Arc::new(ManagedProvider {
        label: account.label.clone(),
        operations: Arc::new(Network),
        vault: vault.clone(),
        id: account.id.clone(),
        provider: account.provider,
        provider_id: account.provider.adapter().id(),
    })
}
fn choose(
    providers: Vec<Provider>,
    filter: Option<&str>,
    accounts: Result<Vec<Account>, AccountError>,
    vault: &Vault,
    has_local_codex: bool,
) -> Result<Vec<Arc<dyn ProviderAdapter>>, AccountError> {
    if let Some(id) = filter {
        let accounts = accounts?;
        let account = accounts
            .iter()
            .find(|a| a.id == id && providers.contains(&a.provider))
            .ok_or(AccountError::NotFound)?;
        return Ok(vec![managed(vault, account)]);
    }
    let mut selected = Vec::new();
    for provider in providers {
        if !matches!(
            provider,
            Provider::Codex | Provider::Amp | Provider::Factory
        ) {
            selected.push(provider.adapter());
            continue;
        }
        match &accounts {
            Ok(accounts) => {
                let matching: Vec<_> = accounts
                    .iter()
                    .filter(|a| a.provider == provider && (provider == Provider::Codex || a.active))
                    .collect();
                if provider == Provider::Codex {
                    if has_local_codex || matching.is_empty() {
                        selected.push(provider.adapter());
                    }
                    selected.extend(matching.into_iter().map(|a| managed(vault, a)));
                } else if let Some(account) = matching.first() {
                    selected.push(managed(vault, account));
                } else {
                    selected.push(provider.adapter());
                }
            }
            Err(_) => {
                if provider == Provider::Codex && has_local_codex {
                    selected.push(provider.adapter());
                }
                selected.push(Arc::new(FailedProvider {
                    provider_id: provider.adapter().id(),
                    account_ref: Some(crate::domain::AccountRef {
                        id: "saved".into(),
                        label: "Saved accounts".into(),
                    }),
                }));
            }
        }
    }
    Ok(selected)
}
pub async fn adapters(
    providers: Vec<Provider>,
    saved: bool,
    timeout: std::time::Duration,
    filter: Option<&str>,
) -> Result<Vec<Arc<dyn ProviderAdapter>>, AccountError> {
    if filter.is_some() && providers.len() != 1 {
        return Err(AccountError::Unsupported);
    }
    if filter == Some("local") {
        return Ok(providers.into_iter().map(Provider::adapter).collect());
    }
    if !saved || !cfg!(target_os = "macos") {
        if filter.is_some() {
            return Err(AccountError::Unsupported);
        }
        return Ok(providers.into_iter().map(Provider::adapter).collect());
    }
    if !providers
        .iter()
        .any(|p| matches!(p, Provider::Codex | Provider::Amp | Provider::Factory))
    {
        if filter.is_some() {
            return Err(AccountError::NotFound);
        }
        return Ok(providers.into_iter().map(Provider::adapter).collect());
    }
    let vault = Vault::for_usage()?;
    let accounts = discover(vault.clone(), timeout).await;
    choose(providers, filter, accounts, &vault, local_codex_available())
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
        stall_first_refresh: std::sync::atomic::AtomicBool,
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
                        doc.accounts.iter().any(|a| matches!((&a.credential,k),(Credential::CodexOAuth{refresh_token,account_id:stored,..},Credential::CodexOAuth{account_id:expected,..}) if refresh_token=="rotated" && stored==expected))
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
                if self.stall_first_refresh.load(Ordering::SeqCst)
                    && matches!(k,Credential::CodexOAuth{account_id,..} if account_id=="codex-id")
                {
                    self.started.notify_one();
                    std::future::pending::<()>().await;
                }
                if self.delay {
                    tokio::time::sleep(Duration::from_millis(75)).await;
                }
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
            stall_first_refresh: std::sync::atomic::AtomicBool::new(false),
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
            label: "Test account".into(),
            vault,
            operations,
            id,
            provider,
            provider_id: provider.adapter().id(),
        }
    }
    fn cleanup(path: std::path::PathBuf) {
        for entry in std::fs::read_dir(&path).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
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
    #[test]
    fn codex_selection_includes_inactive_accounts_and_filters_by_id() {
        let (vault, _, first, amp, path) = setup(3600, false, false, false);
        let mut tx = vault.begin().unwrap();
        let mut credential = tx.document.accounts[0].credential.clone();
        if let Credential::CodexOAuth {
            account_id, email, ..
        } = &mut credential
        {
            *account_id = "second-id".into();
            *email = "second@example.com".into();
        }
        let second = tx
            .document
            .add(Provider::Codex, "Second", "second-id".into(), credential)
            .unwrap();
        assert!(!tx.document.accounts[2].active);
        let accounts = tx.document.accounts.clone();
        drop(tx);
        let refs = |adapters: Vec<Arc<dyn ProviderAdapter>>| {
            adapters
                .iter()
                .map(|a| a.account_ref().unwrap().id)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            refs(
                choose(
                    vec![Provider::Codex],
                    None,
                    Ok(accounts.clone()),
                    &vault,
                    true
                )
                .unwrap()
            ),
            vec!["local".to_owned(), first.clone(), second.clone()]
        );
        assert_eq!(
            refs(
                choose(
                    vec![Provider::Codex],
                    None,
                    Ok(accounts.clone()),
                    &vault,
                    false
                )
                .unwrap()
            ),
            vec![first, second.clone()]
        );
        assert_eq!(
            refs(
                choose(
                    vec![Provider::Codex],
                    Some(&second),
                    Ok(accounts.clone()),
                    &vault,
                    true
                )
                .unwrap()
            ),
            vec![second]
        );
        assert!(matches!(
            choose(
                vec![Provider::Codex],
                Some(&amp),
                Ok(accounts.clone()),
                &vault,
                true
            ),
            Err(AccountError::NotFound)
        ));
        assert!(matches!(
            choose(
                vec![Provider::Codex],
                Some("missing"),
                Ok(accounts),
                &vault,
                true
            ),
            Err(AccountError::NotFound)
        ));
        assert_eq!(
            refs(
                choose(
                    vec![Provider::Codex],
                    None,
                    Err(AccountError::Storage),
                    &vault,
                    true
                )
                .unwrap()
            ),
            vec!["local", "saved"]
        );
        cleanup(path);
    }
    #[tokio::test]
    async fn stalled_refresh_does_not_block_another_saved_account() {
        for expiry in [3600, 0] {
            let (vault, fake, first, _, path) = setup(0, false, false, false);
            let mut tx = vault.begin().unwrap();
            let mut credential = tx.document.accounts[0].credential.clone();
            if let Credential::CodexOAuth {
                account_id,
                email,
                expires_at,
                ..
            } = &mut credential
            {
                *account_id = "second-id".into();
                *email = "second@example.com".into();
                *expires_at = expiry;
            }
            let second = tx
                .document
                .add(Provider::Codex, "Second", "second-id".into(), credential)
                .unwrap();
            tx.commit().unwrap();
            fake.stall_first_refresh.store(true, Ordering::SeqCst);
            let slow = managed(vault.clone(), fake.clone(), first, Provider::Codex);
            let running = tokio::spawn(async move { slow.read(&http::fixture::context()).await });
            fake.started.notified().await;
            let other = managed(vault, fake, second, Provider::Codex);
            let result = tokio::time::timeout(
                Duration::from_millis(300),
                other.read(&http::fixture::context()),
            )
            .await;
            running.abort();
            let _ = running.await;
            cleanup(path);
            assert!(
                result.is_ok_and(|r| r.is_ok()),
                "one account's refresh blocked another account"
            );
        }
    }
    #[tokio::test]
    async fn concurrent_reads_of_one_expired_account_refresh_only_once() {
        let (vault, fake, id, _, path) = setup(0, true, false, false);
        let first = managed(vault.clone(), fake.clone(), id.clone(), Provider::Codex);
        let second = managed(vault, fake.clone(), id, Provider::Codex);
        let context = http::fixture::context();
        let (a, b) = tokio::join!(first.read(&context), second.read(&context));
        assert!(a.is_ok());
        assert!(b.is_ok());
        assert_eq!(fake.refreshes.load(Ordering::SeqCst), 1);
        cleanup(path);
    }
}
