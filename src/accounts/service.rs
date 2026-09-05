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
    if let Credential::CatalogKey { token, settings } = credential {
        let definition = provider
            .catalog()
            .filter(|d| d.auth == crate::providers::catalog::AuthKind::ApiKey)
            .ok_or(AccountError::Unsupported)?;
        keys.insert(definition.key_env.into(), token.clone());
        for (name, value) in settings {
            let setting = definition
                .settings
                .iter()
                .find(|s| s.name == name)
                .ok_or(AccountError::Settings)?;
            keys.insert(setting.env.into(), value.clone());
        }
        if definition
            .settings
            .iter()
            .any(|s| s.required && !settings.contains_key(s.name))
        {
            return Err(AccountError::Settings);
        }
    }
    if let Credential::ApiKey {
        token,
        region,
        organization,
    } = credential
    {
        let key = provider.api_key_name().ok_or(AccountError::Unsupported)?;
        if let Some(name) = provider.key_api().and_then(|k| k.region_key())
            && let Some(region) = region
        {
            keys.insert(name.into(), region.clone());
        }
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
        provider if provider.key_api().is_some() || provider.catalog().is_some() => {
            provider.adapter().fetch(&ctx).await?
        }
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
pub async fn get(vault: Vault, id: String) -> Result<Account, AccountError> {
    begin(vault)
        .await?
        .document
        .accounts
        .into_iter()
        .find(|account| account.id == id)
        .ok_or(AccountError::NotFound)
}
pub async fn rename(vault: Vault, id: String, label: String) -> Result<(), AccountError> {
    let mut tx = begin(vault).await?;
    tx.document.rename(&id, &label)?;
    commit(tx).await
}
pub async fn patch(
    vault: Vault,
    id: String,
    label: Option<String>,
    active: Option<bool>,
) -> Result<Account, AccountError> {
    let mut tx = begin(vault).await?;
    tx.document.patch(&id, label.as_deref(), active)?;
    let account = tx
        .document
        .accounts
        .iter()
        .find(|account| account.id == id)
        .cloned()
        .ok_or(AccountError::NotFound)?;
    commit(tx).await?;
    Ok(account)
}
pub fn provider_settings(
    provider: Provider,
    mut values: std::collections::BTreeMap<String, String>,
    context: &ProviderContext,
) -> Result<std::collections::BTreeMap<String, String>, AccountError> {
    let Some(definition) = provider.catalog() else {
        return if values.is_empty() {
            Ok(values)
        } else {
            Err(AccountError::Settings)
        };
    };
    for (name, value) in &values {
        if !definition
            .settings
            .iter()
            .any(|setting| setting.name == name)
            || value.is_empty()
            || value.len() > 2048
            || value.chars().any(char::is_control)
        {
            return Err(AccountError::Settings);
        }
    }
    for setting in definition.settings {
        if !values.contains_key(setting.name)
            && let Some(value) = context.credentials.get(setting.env)
        {
            if value.0.is_empty() || value.0.len() > 2048 || value.0.chars().any(char::is_control) {
                return Err(AccountError::Settings);
            }
            values.insert(setting.name.into(), value.0);
        }
        if setting.required && !values.contains_key(setting.name) {
            return Err(AccountError::Settings);
        }
    }
    Ok(values)
}
pub fn default_label(
    explicit: Option<&str>,
    credential: &Credential,
) -> Result<String, AccountError> {
    if let Some(label) = explicit {
        return super::validate_label(label);
    }
    match credential {
        Credential::CodexOAuth { email, .. } => super::validate_label(email),
        Credential::ApiKey { token, .. } | Credential::CatalogKey { token, .. } => {
            let suffix =
                if token.len() > 8 && token.is_ascii() && !token.chars().any(char::is_control) {
                    &token[token.len() - 4..]
                } else {
                    ""
                };
            Ok(format!("API key ****{suffix}"))
        }
    }
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
    fn cache_identity<'a>(
        &'a self,
        _: &'a ProviderContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send + 'a>> {
        Box::pin(async move {
            let tx = begin(self.vault.clone()).await.ok()?;
            let account = tx
                .document
                .accounts
                .iter()
                .find(|a| a.id == self.id && a.provider == self.provider)?;
            let scope = match &account.credential {
                Credential::CodexOAuth { account_id, .. } => account_id.clone(),
                credential => serde_json::to_string(credential).ok()?,
            };
            Some(crate::cache::fingerprint(&[
                &account.id,
                &account.identity,
                &scope,
            ]))
        })
    }

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
fn executable_available(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| {
            let path = dir.join(if cfg!(windows) {
                format!("{name}.exe")
            } else {
                name.into()
            });
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
async fn local_sources(requested: &[Provider], timeout: std::time::Duration) -> Vec<Provider> {
    let mut sources: Vec<_> = requested
        .iter()
        .copied()
        .filter(|p| {
            (p.key_api().is_some()
                || p.catalog()
                    .is_some_and(|d| d.auth == crate::providers::catalog::AuthKind::ApiKey))
                && p.api_key_name()
                    .is_some_and(|name| std::env::var_os(name).is_some())
        })
        .collect();
    if requested.contains(&Provider::Codex) && executable_available("codex") {
        sources.push(Provider::Codex);
    }
    if !requested.contains(&Provider::Amp) {
        return sources;
    }
    if executable_available("amp") {
        sources.push(Provider::Amp);
        return sources;
    }
    let public_amp = std::env::var("AMP_URL").map_or(true, |url| {
        url.trim_end_matches('/') == "https://ampcode.com"
    });
    if public_amp {
        let has_key = if std::env::var_os("AMP_API_KEY").is_some() {
            true
        } else {
            // Reuse the bounded parser so unrelated custom-host keys do not create
            // a local account. Unreadable/malformed credentials remain visible errors.
            tokio::time::timeout(
                timeout,
                tokio::task::spawn_blocking(|| {
                    crate::providers::amp::AmpProvider::default().has_local_key()
                }),
            )
            .await
            .ok()
            .and_then(Result::ok)
            .and_then(Result::ok)
            .unwrap_or(true)
        };
        if has_key {
            sources.push(Provider::Amp);
        }
    }
    sources
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
    local_sources: &[Provider],
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
        if !provider.supports_accounts() {
            selected.push(provider.adapter());
            continue;
        }
        match &accounts {
            Ok(accounts) => {
                let matching: Vec<_> = accounts
                    .iter()
                    .filter(|a| {
                        a.provider == provider && (provider != Provider::Factory || a.active)
                    })
                    .collect();
                if provider != Provider::Factory {
                    if local_sources.contains(&provider) || matching.is_empty() {
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
                if local_sources.contains(&provider) {
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
    if !providers.iter().any(|p| p.supports_accounts()) {
        if filter.is_some() {
            return Err(AccountError::NotFound);
        }
        return Ok(providers.into_iter().map(Provider::adapter).collect());
    }
    let vault = Vault::for_usage()?;
    let (accounts, local_sources) = tokio::join!(discover(vault.clone(), timeout), async {
        if filter.is_none() {
            local_sources(&providers, timeout).await
        } else {
            Vec::new()
        }
    });
    choose(providers, filter, accounts, &vault, &local_sources)
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
    fn added_key_providers_scope_credentials_and_select_all_accounts() {
        for provider in [
            Provider::Synthetic,
            Provider::OpenRouter,
            Provider::Zai,
            Provider::MiniMax,
        ] {
            let (vault, _, _, _, path) = setup(3600, false, false, false);
            let credential = Credential::ApiKey {
                token: "saved-test-key".into(),
                region: provider
                    .key_api()
                    .unwrap()
                    .region_key()
                    .map(|_| "cn".into()),
                organization: None,
            };
            let ctx = scoped(&http::fixture::context(), provider, &credential).unwrap();
            assert_eq!(
                ctx.credentials
                    .get(provider.api_key_name().unwrap())
                    .unwrap()
                    .0,
                "saved-test-key"
            );
            assert!(ctx.credentials.get("FACTORY_API_KEY").is_none());
            if let Some(name) = provider.key_api().unwrap().region_key() {
                assert_eq!(ctx.credentials.get(name).unwrap().0, "cn");
            }
            let mut tx = vault.begin().unwrap();
            let first = tx
                .document
                .add(provider, "First", "key:first".into(), credential.clone())
                .unwrap();
            let second = tx
                .document
                .add(provider, "Second", "key:second".into(), credential)
                .unwrap();
            let accounts = tx.document.accounts.clone();
            drop(tx);
            let selected = choose(
                vec![provider],
                None,
                Ok(accounts.clone()),
                &vault,
                &[provider],
            )
            .unwrap();
            assert_eq!(
                selected
                    .iter()
                    .map(|p| p.account_ref().unwrap().id)
                    .collect::<Vec<_>>(),
                vec!["local".to_owned(), first, second.clone()]
            );
            let selected = choose(
                vec![provider],
                Some(&second),
                Ok(accounts),
                &vault,
                &[provider],
            )
            .unwrap();
            assert_eq!(selected.len(), 1);
            assert_eq!(selected[0].account_ref().unwrap().id, second);
            cleanup(path);
        }
    }
    #[test]
    fn amp_selection_keeps_local_and_all_saved_accounts() {
        let (vault, _, _, first, path) = setup(3600, false, false, false);
        let mut tx = vault.begin().unwrap();
        let second = tx
            .document
            .add(
                Provider::Amp,
                "Second Amp",
                "second@example.invalid".into(),
                Credential::ApiKey {
                    token: "synthetic-second".into(),
                    region: None,
                    organization: None,
                },
            )
            .unwrap();
        let accounts = tx.document.accounts.clone();
        drop(tx);
        let selected = choose(
            vec![Provider::Amp],
            None,
            Ok(accounts.clone()),
            &vault,
            &[Provider::Amp],
        )
        .unwrap();
        let refs: Vec<_> = selected
            .iter()
            .map(|p| p.account_ref().map(|a| a.id))
            .collect();
        assert_eq!(
            refs,
            vec![
                Some("local".into()),
                Some(first.clone()),
                Some(second.clone())
            ]
        );
        let only_saved =
            choose(vec![Provider::Amp], None, Ok(accounts.clone()), &vault, &[]).unwrap();
        assert_eq!(only_saved.len(), 2);
        assert!(
            only_saved
                .iter()
                .all(|p| p.account_ref().unwrap().id != "local")
        );
        let filtered = choose(
            vec![Provider::Amp],
            Some(&second),
            Ok(accounts),
            &vault,
            &[Provider::Amp],
        )
        .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].account_ref().unwrap().id, second);
        let denied = choose(
            vec![Provider::Amp],
            None,
            Err(AccountError::Storage),
            &vault,
            &[Provider::Amp],
        )
        .unwrap();
        assert_eq!(
            denied
                .iter()
                .map(|p| p.account_ref().unwrap().id)
                .collect::<Vec<_>>(),
            vec!["local", "saved"]
        );
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
                    &[Provider::Codex]
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
                    &[]
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
                    &[Provider::Codex]
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
                &[Provider::Codex]
            ),
            Err(AccountError::NotFound)
        ));
        assert!(matches!(
            choose(
                vec![Provider::Codex],
                Some("missing"),
                Ok(accounts),
                &vault,
                &[Provider::Codex]
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
                    &[Provider::Codex]
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

#[cfg(test)]
mod catalog_credential_tests {
    use super::*;
    #[test]
    fn saved_catalog_settings_are_isolated_and_roundtrip() {
        for definition in crate::providers::catalog::definitions()
            .filter(|d| d.auth == crate::providers::catalog::AuthKind::ApiKey)
        {
            let settings = definition
                .settings
                .iter()
                .map(|s| (s.name.to_owned(), "scope-value".to_owned()))
                .collect();
            let credential = Credential::CatalogKey {
                token: "saved-synthetic-key".into(),
                settings,
            };
            let serialized = serde_json::to_string(&credential).unwrap();
            let decoded: Credential = serde_json::from_str(&serialized).unwrap();
            assert!(decoded == credential);
            let context = scoped(
                &crate::providers::http::fixture::context(),
                Provider::Catalog(definition.id),
                &credential,
            )
            .unwrap();
            assert_eq!(
                context.credentials.get(definition.key_env).unwrap().0,
                "saved-synthetic-key"
            );
            assert!(context.credentials.get("FACTORY_API_KEY").is_none());
            for setting in definition.settings {
                assert_eq!(
                    context.credentials.get(setting.env).unwrap().0,
                    "scope-value"
                );
            }
            let invalid = Credential::CatalogKey {
                token: "saved-synthetic-key".into(),
                settings: [("unknown".into(), "private-value".into())]
                    .into_iter()
                    .collect(),
            };
            assert!(matches!(
                scoped(&context, Provider::Catalog(definition.id), &invalid),
                Err(AccountError::Settings)
            ));
        }
    }
}
