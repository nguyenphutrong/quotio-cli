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
    if let Credential::FactoryOAuth {
        refresh_pending: true,
        ..
    } = credential
    {
        return Err(AccountError::CommitUncertain);
    }
    if let Credential::GrokOAuth {
        access_token,
        refresh_pending,
        ..
    } = credential
    {
        if provider != Provider::Catalog("grok") {
            return Err(AccountError::Unsupported);
        }
        if *refresh_pending {
            return Err(AccountError::CommitUncertain);
        }
        keys.insert("GROK_OAUTH_TOKEN".into(), access_token.clone());
    }
    if let Credential::CatalogKey { token, settings } = credential {
        let definition = provider
            .catalog()
            .filter(|d| {
                d.auth == crate::providers::catalog::AuthKind::ApiKey
                    || matches!(
                        provider,
                        Provider::Catalog("cursor" | "grok" | "claude" | "copilot")
                    )
            })
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
    validate_with_endpoint(context, provider, credential, None).await
}
async fn validate_with_endpoint(
    context: &ProviderContext,
    provider: Provider,
    credential: &Credential,
    endpoint_override: Option<&str>,
) -> Result<ProviderUsage, AccountError> {
    let reference = credential;
    let resolved = reference.resolve_reference(provider).await?;
    let credentials = resolved
        .as_ref()
        .map_or_else(|| vec![credential.clone()], |r| r.credentials.clone());
    let mut usage =
        validate_credentials(context, provider, &credentials, endpoint_override).await?;
    if resolved.is_some()
        && reference.resolve_reference(provider).await?.as_ref() != resolved.as_ref()
    {
        return Err(AccountError::Busy);
    }
    if provider == Provider::Catalog("cursor")
        && let Some(resolved) = resolved
    {
        usage.account.label = resolved.label;
        if usage.account.plan.is_none() {
            usage.account.plan = resolved.plan;
        }
        usage.account.subscription_status = resolved.subscription_status;
    }
    Ok(usage)
}
async fn validate_credentials(
    context: &ProviderContext,
    provider: Provider,
    credentials: &[Credential],
    endpoint_override: Option<&str>,
) -> Result<ProviderUsage, AccountError> {
    if credentials.len() == 1 {
        return validate_credential(context, provider, &credentials[0], endpoint_override).await;
    }
    let budget =
        crate::providers::remaining_fetch_time().unwrap_or(std::time::Duration::from_secs(30));
    let reserve = (budget / 10).min(std::time::Duration::from_millis(100));
    let deadline = tokio::time::Instant::now() + budget.saturating_sub(reserve);
    let mut selected = None;
    let mut failures = Vec::new();
    let mut last_error = AccountError::Input;
    for (index, credential) in credentials.iter().enumerate() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let key_deadline =
            tokio::time::Instant::now() + remaining / ((credentials.len() - index) as u32);
        let result = tokio::time::timeout_at(
            key_deadline,
            crate::providers::FETCH_DEADLINE.scope(
                key_deadline,
                validate_credential(context, provider, credential, endpoint_override),
            ),
        )
        .await
        .unwrap_or(Err(AccountError::Provider(ProviderError::Timeout)));
        match result {
            Ok(mut usage) => {
                if credentials.len() > 1 {
                    for mut diagnostic in std::mem::take(&mut usage.diagnostics) {
                        diagnostic.source =
                            format!("{}_key_{}:{}", provider.id(), index + 1, diagnostic.source);
                        failures.push(diagnostic);
                    }
                }
                selected = Some(usage);
            }
            Err(error) => {
                let code = match &error {
                    AccountError::Provider(code) => *code,
                    _ => ProviderError::Authentication,
                };
                failures.push(crate::domain::UsageDiagnostic {
                    source: format!("{}_key_{}", provider.id(), index + 1),
                    code,
                });
                last_error = error;
            }
        }
    }
    let mut usage = selected.ok_or(last_error)?;
    usage.diagnostics.extend(failures);
    Ok(usage)
}
async fn validate_credential(
    context: &ProviderContext,
    provider: Provider,
    credential: &Credential,
    endpoint_override: Option<&str>,
) -> Result<ProviderUsage, AccountError> {
    let ctx = scoped(context, provider, credential)?;
    let usage = match provider {
        Provider::Amp => match endpoint_override {
            Some(endpoint) => AmpApiProvider.fetch_api(&ctx, endpoint).await?,
            None => AmpApiProvider.fetch(&ctx).await?,
        },
        Provider::Catalog("cursor") if endpoint_override.is_some() => {
            let endpoint = endpoint_override.unwrap();
            crate::providers::catalog::oauth_editors::fetch_cursor_complete_at(
                &ctx, endpoint, endpoint,
            )
            .await?
        }
        Provider::Catalog("grok") if endpoint_override.is_some() => {
            crate::providers::catalog::oauth_editors::fetch_grok_complete_at(
                &ctx,
                endpoint_override.unwrap(),
                None,
            )
            .await?
        }
        Provider::Catalog("claude") if endpoint_override.is_some() => {
            crate::providers::catalog::oauth_primary::fetch_claude_at(
                &ctx,
                endpoint_override.unwrap(),
            )
            .await?
        }
        Provider::Catalog("copilot") if endpoint_override.is_some() => {
            crate::providers::catalog::oauth_primary::fetch_copilot_at(
                &ctx,
                endpoint_override.unwrap(),
            )
            .await?
        }
        Provider::Factory if matches!(credential, Credential::FactoryOAuth { .. }) => {
            crate::providers::factory::fetch_oauth_at(
                context,
                credential,
                endpoint_override.unwrap_or("https://api.factory.ai/api/billing/limits"),
            )
            .await?
        }
        Provider::Factory => FactoryProvider.fetch(&ctx).await?,
        Provider::Codex if endpoint_override.is_some() => {
            let endpoint = endpoint_override.unwrap();
            codex_api::fetch_at(&ctx, credential, endpoint, endpoint, endpoint).await?
        }
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
pub(crate) async fn mutation_guard(
    guard: &tokio::sync::Mutex<()>,
) -> Result<tokio::sync::MutexGuard<'_, ()>, AccountError> {
    tokio::time::timeout(std::time::Duration::from_secs(10), guard.lock())
        .await
        .map_err(|_| AccountError::Busy)
}
async fn begin(vault: Vault) -> Result<Transaction, AccountError> {
    begin_with_timeout(vault, std::time::Duration::from_secs(10)).await
}
async fn begin_with_timeout(
    vault: Vault,
    timeout: std::time::Duration,
) -> Result<Transaction, AccountError> {
    // Only reads are cancellable here. A detached native read cannot commit credentials.
    tokio::time::timeout(timeout, async move {
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
    })
    .await
    .map_err(|_| AccountError::Busy)?
}
async fn refresh_lock(vault: Vault, id: String) -> Result<super::vault::VaultLock, AccountError> {
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
/// Intent fingerprints are stored only in the protected vault, atomically with the write.
#[derive(Clone)]
pub struct MutationIntent {
    key: String,
    fingerprint: String,
}
impl MutationIntent {
    pub fn new(key: &str, fingerprint: String) -> Result<Self, AccountError> {
        if key.is_empty() || key.len() > 128 || !key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(AccountError::Input);
        }
        Ok(Self {
            key: crate::cache::fingerprint(&[key]),
            fingerprint,
        })
    }
    fn receipt(&self, document: &super::Document) -> Result<Option<String>, AccountError> {
        match document.mutation_receipts.get(&self.key) {
            Some(receipt) if receipt.fingerprint == self.fingerprint => {
                Ok(Some(receipt.account_id.clone()))
            }
            Some(_) => Err(AccountError::IdempotencyConflict),
            None => Ok(None),
        }
    }
}
pub async fn mutation_receipt(
    vault: Vault,
    intent: &MutationIntent,
) -> Result<Option<String>, AccountError> {
    let tx = begin(vault).await?;
    intent.receipt(&tx.document)
}
pub async fn commit_once(
    vault: Vault,
    intent: MutationIntent,
    mutation: impl FnOnce(&mut super::Document) -> Result<String, AccountError> + Send,
) -> Result<String, AccountError> {
    let mut tx = begin(vault).await?;
    if let Some(id) = intent.receipt(&tx.document)? {
        return Ok(id);
    }
    if tx.document.mutation_receipts.len() >= 4096 {
        return Err(AccountError::IdempotencyFull);
    }
    let id = mutation(&mut tx.document)?;
    tx.document.mutation_receipts.insert(
        intent.key,
        super::MutationReceipt {
            fingerprint: intent.fingerprint,
            account_id: id.clone(),
        },
    );
    // Older binaries must reject the document instead of silently discarding receipts.
    tx.document.version = tx.document.version.max(2);
    commit(tx).await?;
    Ok(id)
}

pub async fn add_persisted(
    vault: Vault,
    provider: Provider,
    label: String,
    credential: Credential,
    identity: String,
) -> Result<Account, AccountError> {
    let mut tx = begin(vault).await?;
    let id = tx.document.add(provider, &label, identity, credential)?;
    let account = tx
        .document
        .accounts
        .iter()
        .find(|account| account.id == id)
        .cloned()
        .ok_or(AccountError::Corrupt)?;
    commit(tx).await?;
    Ok(account)
}
pub async fn add(
    vault: Vault,
    provider: Provider,
    label: String,
    credential: Credential,
    identity: String,
) -> Result<String, AccountError> {
    Ok(add_persisted(vault, provider, label, credential, identity)
        .await?
        .id)
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
    enabled: Option<bool>,
) -> Result<Account, AccountError> {
    let mut tx = begin(vault).await?;
    tx.document.patch(&id, label.as_deref(), active, enabled)?;
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
        Credential::QuotioCustomProvider { .. }
        | Credential::AmpNative { .. }
        | Credential::CodexNative { .. }
        | Credential::ClaudeNative { .. }
        | Credential::CopilotNative { .. }
        | Credential::GrokNative { .. }
        | Credential::CursorNative { .. } => Err(AccountError::Input),
        Credential::GrokOAuth { .. } => Ok("Grok owned account".into()),
        Credential::FactoryOAuth { .. } => Ok("Factory owned account".into()),
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
        Box::pin(async move {
            if matches!(k, Credential::FactoryOAuth { .. }) {
                crate::providers::factory::refresh(c, k).await
            } else if matches!(k, Credential::GrokOAuth { .. }) {
                crate::providers::catalog::oauth_editors::refresh_grok(c, k).await
            } else {
                super::oauth::refresh(c, k).await
            }
        })
    }
}
struct ManagedProvider {
    origin: super::AccountOrigin,
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
        if !account.enabled() {
            return Err(AccountError::SourceDisabled);
        }
        let credential = account.credential;
        if matches!(
            credential,
            Credential::GrokOAuth {
                refresh_pending: true,
                ..
            } | Credential::FactoryOAuth {
                refresh_pending: true,
                ..
            }
        ) {
            return Err(AccountError::CommitUncertain);
        }
        if !matches!(
            credential,
            Credential::CodexOAuth { .. }
                | Credential::GrokOAuth { .. }
                | Credential::FactoryOAuth { .. }
        ) {
            let usage = self
                .operations
                .quota(context, self.provider, &credential)
                .await?;
            return self.verify_current(&credential, usage).await;
        }
        let refresh_margin = if self.provider == Provider::Catalog("grok") {
            300
        } else {
            60
        };
        let needs_refresh = matches!(&credential,Credential::CodexOAuth{expires_at,..} | Credential::GrokOAuth{expires_at,..} | Credential::FactoryOAuth{expires_at,..} if *expires_at<=context.clock.now().unix_timestamp()+refresh_margin);
        if !needs_refresh {
            match self
                .operations
                .quota(context, self.provider, &credential)
                .await
            {
                Ok(usage) => return self.verify_current(&credential, usage).await,
                Err(AccountError::Provider(ProviderError::Authentication)) => (),
                Err(error) => return Err(error),
            }
        }
        let guard = refresh_lock(self.vault.clone(), self.id.clone()).await?;
        let tx = begin(self.vault.clone()).await?;
        let account = tx
            .document
            .accounts
            .iter()
            .find(|a| a.id == self.id && a.provider == self.provider)
            .ok_or(AccountError::NotFound)?;
        if !account.enabled() {
            return Err(AccountError::SourceDisabled);
        }
        let latest = account.credential.clone();
        drop(tx);
        if credential != latest {
            drop(guard);
            let usage = self
                .operations
                .quota(context, self.provider, &latest)
                .await?;
            return self.verify_current(&latest, usage).await;
        }
        // A refresh can consume its token even if the response or vault commit is lost.
        // Persist a fence first so later reads cannot replay that request.
        let mut latest = latest;
        if let Credential::GrokOAuth {
            refresh_pending, ..
        }
        | Credential::FactoryOAuth {
            refresh_pending, ..
        } = &mut latest
        {
            *refresh_pending = true;
            let mut tx = begin(self.vault.clone()).await?;
            let account = tx
                .document
                .accounts
                .iter_mut()
                .find(|a| a.id == self.id)
                .ok_or(AccountError::NotFound)?;
            if !account.enabled() || account.credential != credential {
                return Err(AccountError::Busy);
            }
            account.credential = latest.clone();
            commit(tx).await?;
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
        let enabled = account.enabled();
        // Persist rotation without holding the global vault lock during network IO.
        commit(tx).await?;
        drop(guard);
        if !enabled {
            return Err(AccountError::SourceDisabled);
        }
        let usage = self
            .operations
            .quota(context, self.provider, &updated)
            .await?;
        self.verify_current(&updated, usage).await
    }
    async fn verify_current(
        &self,
        credential: &Credential,
        usage: ProviderUsage,
    ) -> Result<ProviderUsage, AccountError> {
        let tx = begin(self.vault.clone()).await?;
        let current = tx
            .document
            .accounts
            .iter()
            .find(|a| a.id == self.id && a.provider == self.provider)
            .ok_or(AccountError::NotFound)?;
        if !current.enabled() || current.credential != *credential {
            return Err(AccountError::Busy);
        }
        Ok(usage)
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
            if !account.enabled() {
                return None;
            }
            let account = account.clone();
            drop(tx);
            let scope = match &account.credential {
                Credential::GrokOAuth {
                    refresh_pending: true,
                    ..
                }
                | Credential::FactoryOAuth {
                    refresh_pending: true,
                    ..
                } => return None,
                Credential::QuotioCustomProvider { .. }
                | Credential::AmpNative { .. }
                | Credential::CodexNative { .. }
                | Credential::ClaudeNative { .. }
                | Credential::CopilotNative { .. }
                | Credential::GrokNative { .. }
                | Credential::CursorNative { .. } => serde_json::to_string(
                    &account
                        .credential
                        .resolve_reference(self.provider)
                        .await
                        .ok()??,
                )
                .ok()?,
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
            origin: Some(self.origin),
            id: self.id.clone(),
            label: self.label.clone(),
        })
    }
    fn id(&self) -> ProviderId {
        self.provider_id.clone()
    }
    fn idempotent(&self) -> bool {
        self.provider != Provider::Codex
            && !(matches!(self.provider, Provider::Factory | Provider::Catalog("grok"))
                && self.origin == super::AccountOrigin::Owned)
    }
    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> FetchFuture<'a> {
        Box::pin(async move {
            self.read(context).await.map_err(|e| match e {
                AccountError::Provider(ProviderError::Authentication)
                    if self.origin == super::AccountOrigin::BorrowedNative =>
                {
                    ProviderError::OwnerRefreshRequired
                }
                AccountError::Provider(e) => e,
                AccountError::Busy => ProviderError::Transient,
                AccountError::SourceDisabled => ProviderError::SourceDisabled,
                AccountError::Storage | AccountError::Corrupt | AccountError::CommitUncertain => {
                    ProviderError::CredentialStorage
                }
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
    for (provider, token) in [
        (Provider::Catalog("cursor"), "CURSOR_ACCESS_TOKEN"),
        (Provider::Catalog("claude"), "CLAUDE_OAUTH_ACCESS_TOKEN"),
        (Provider::Catalog("copilot"), "COPILOT_API_TOKEN"),
    ] {
        if requested.contains(&provider) && std::env::var_os(token).is_some() {
            sources.push(provider);
        }
    }
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
        origin: account.origin(),
        label: account.label.clone(),
        operations: Arc::new(Network),
        vault: vault.clone(),
        id: account.id.clone(),
        provider: account.provider,
        provider_id: account.provider.adapter().id(),
    })
}
fn native_amp_selection(has_key: bool, url: Option<&str>) -> bool {
    !has_key
        && url.is_none_or(|url| {
            reqwest::Url::parse(url)
                .ok()
                .and_then(|url| {
                    url.host_str()
                        .map(|host| host.eq_ignore_ascii_case("ampcode.com"))
                })
                .unwrap_or(true)
        })
}
pub(crate) fn uses_native_amp_source() -> bool {
    native_amp_selection(
        std::env::var_os("AMP_API_KEY").is_some(),
        std::env::var("AMP_URL").ok().as_deref(),
    )
}
pub(crate) fn native_reference_replaces_local(provider: Provider, credential: &Credential) -> bool {
    match credential {
        Credential::CopilotNative { .. } => {
            provider == Provider::Catalog("copilot")
                && std::env::var_os("COPILOT_API_TOKEN").is_none()
        }
        Credential::ClaudeNative { .. } => {
            provider == Provider::Catalog("claude")
                && std::env::var_os("CLAUDE_OAUTH_ACCESS_TOKEN").is_none()
        }
        Credential::CodexNative { source } => {
            provider == Provider::Codex
                && super::sources::CodexNativeReference::system(
                    if std::env::var_os("CODEX_HOME").is_some() {
                        super::sources::CodexLocation::CodexHome
                    } else {
                        super::sources::CodexLocation::Default
                    },
                )
                .is_ok_and(|local| local == *source)
        }
        Credential::AmpNative { .. } => provider == Provider::Amp && uses_native_amp_source(),
        Credential::GrokNative { .. } => {
            provider == Provider::Catalog("grok") && std::env::var_os("GROK_OAUTH_TOKEN").is_none()
        }
        Credential::CursorNative { .. } => {
            provider == Provider::Catalog("cursor")
                && std::env::var_os("CURSOR_ACCESS_TOKEN").is_none()
        }
        _ => false,
    }
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
                    if (local_sources.contains(&provider) || matching.is_empty())
                        && !matching
                            .iter()
                            .any(|a| native_reference_replaces_local(provider, &a.credential))
                    {
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
                        origin: None,
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
    adapters_with_vault(providers, saved, timeout, filter, Vault::for_usage).await
}
async fn adapters_with_vault(
    providers: Vec<Provider>,
    saved: bool,
    timeout: std::time::Duration,
    filter: Option<&str>,
    vault: impl Fn() -> Result<Vault, AccountError>,
) -> Result<Vec<Arc<dyn ProviderAdapter>>, AccountError> {
    if filter.is_some() && providers.len() != 1 {
        return Err(AccountError::Unsupported);
    }
    if filter == Some("local") {
        if saved
            && providers.iter().any(|p| {
                matches!(
                    p,
                    Provider::Codex
                        | Provider::Amp
                        | Provider::Catalog("cursor" | "grok" | "claude" | "copilot")
                )
            })
        {
            let accounts = discover(vault()?, timeout).await?;
            if accounts.iter().any(|a| {
                providers.contains(&a.provider)
                    && native_reference_replaces_local(a.provider, &a.credential)
            }) {
                return Err(AccountError::Unsupported);
            }
        }
        return Ok(providers.into_iter().map(Provider::adapter).collect());
    }
    if !saved || !cfg!(any(target_os = "macos", target_os = "linux")) {
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
    let vault = vault()?;
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
    #[tokio::test]
    async fn vault_contention_times_out_before_mutation_and_recovers() {
        let path = std::env::temp_dir().join(format!(
            "quotio-contention-{}.lock",
            random_string().unwrap()
        ));
        let vault = Vault::new(Arc::new(Memory::default()), path.clone());
        let held = vault.begin().unwrap();
        assert!(matches!(
            begin_with_timeout(vault.clone(), Duration::from_millis(50)).await,
            Err(AccountError::Busy)
        ));
        drop(held);
        assert!(
            begin_with_timeout(vault, Duration::from_secs(1))
                .await
                .is_ok()
        );
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn mutation_guard_has_a_deadline() {
        let lock = tokio::sync::Mutex::new(());
        let held = lock.lock().await;
        assert!(matches!(
            mutation_guard(&lock).await,
            Err(AccountError::Busy)
        ));
        drop(held);
        assert!(mutation_guard(&lock).await.is_ok());
    }
    struct Fake {
        memory: Arc<Memory>,
        started: tokio::sync::Notify,
        delay: bool,
        refresh_fails: bool,
        quota_fails: bool,
        refreshes: AtomicUsize,
        quota_calls: AtomicUsize,
        wait_for_refresh: std::sync::atomic::AtomicBool,
        release_refresh: tokio::sync::Notify,
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
                self.quota_calls.fetch_add(1, Ordering::SeqCst);
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
                if let Credential::GrokOAuth { access_token, .. }
                | Credential::FactoryOAuth { access_token, .. } = k
                {
                    assert_eq!(access_token, "new");
                    let doc: super::super::Document =
                        serde_json::from_slice(&self.memory.read().unwrap().unwrap()).unwrap();
                    assert!(doc.accounts.iter().any(|a| a.credential == *k));
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
                if self.wait_for_refresh.load(Ordering::SeqCst) {
                    self.started.notify_one();
                    self.release_refresh.notified().await;
                }
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
                if let Credential::GrokOAuth {
                    access_token,
                    refresh_token,
                    expires_at,
                    refresh_pending,
                }
                | Credential::FactoryOAuth {
                    access_token,
                    refresh_token,
                    expires_at,
                    refresh_pending,
                    ..
                } = &mut k
                {
                    assert!(*refresh_pending);
                    let doc: super::super::Document =
                        serde_json::from_slice(&self.memory.read().unwrap().unwrap()).unwrap();
                    assert!(doc.accounts.iter().any(|a| matches!(
                        a.credential,
                        Credential::GrokOAuth {
                            refresh_pending: true,
                            ..
                        } | Credential::FactoryOAuth {
                            refresh_pending: true,
                            ..
                        }
                    )));
                    *access_token = "new".into();
                    *refresh_token = "rotated".into();
                    *expires_at = 3600;
                    *refresh_pending = false;
                }
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

    #[test]
    fn claude_and_copilot_selection_uses_isolated_environment() {
        let dir = std::env::temp_dir().join(random_string().unwrap());
        std::fs::create_dir(&dir).unwrap();
        for independent in [false, true] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "accounts::service::tests::claude_and_copilot_selection_child",
                    "--nocapture",
                ])
                .env("HOME", &dir)
                .env("QUOTIO_SELECTION_FIXTURE", &dir)
                .env_remove("CLAUDE_OAUTH_ACCESS_TOKEN")
                .env_remove("COPILOT_API_TOKEN");
            if independent {
                command
                    .env("CLAUDE_OAUTH_ACCESS_TOKEN", "independent-claude-fixture")
                    .env("COPILOT_API_TOKEN", "independent-copilot-fixture");
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn claude_and_copilot_selection_child() {
        let Ok(dir) = std::env::var("QUOTIO_SELECTION_FIXTURE") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        let missing = dir.join("missing-native-credentials");
        assert!(!missing.exists());
        for (provider, token, credential) in [
            (
                Provider::Catalog("claude"),
                "CLAUDE_OAUTH_ACCESS_TOKEN",
                Credential::ClaudeNative {
                    source: super::super::sources::ClaudeNativeReference {
                        location: super::super::sources::ClaudeLocation::CodeFile,
                        path: Some(missing.clone()),
                    },
                },
            ),
            (
                Provider::Catalog("copilot"),
                "COPILOT_API_TOKEN",
                Credential::CopilotNative {
                    source: super::super::sources::CopilotNativeReference {
                        location: super::super::sources::CopilotLocation::Apps,
                        path: Some(missing.clone()),
                        entry_key: "github.com:fixture".into(),
                    },
                },
            ),
        ] {
            let independent = std::env::var_os(token).is_some();
            for enabled in [false, true] {
                let vault = Vault::new(Arc::new(Memory::default()), dir.join("selection.lock"));
                let mut tx = vault.begin().unwrap();
                let id = tx
                    .document
                    .add(provider, "Native", "source".into(), credential.clone())
                    .unwrap();
                tx.document.patch(&id, None, None, Some(enabled)).unwrap();
                tx.commit().unwrap();

                // A disabled reference must block the local alias before native reads,
                // even when its source is missing. An independent token remains usable.
                let local = adapters_with_vault(
                    vec![provider],
                    true,
                    Duration::from_secs(1),
                    Some("local"),
                    || Ok(vault.clone()),
                )
                .await;
                if independent {
                    let local = local.unwrap();
                    assert_eq!(local.len(), 1);
                    assert_eq!(local[0].account_ref().unwrap().id, "local");
                } else {
                    assert!(matches!(local, Err(AccountError::Unsupported)));
                }

                let selected =
                    adapters_with_vault(vec![provider], true, Duration::from_secs(1), None, || {
                        Ok(vault.clone())
                    })
                    .await
                    .unwrap();
                let ids: Vec<_> = selected
                    .iter()
                    .map(|a| a.account_ref().unwrap().id)
                    .collect();
                assert_eq!(ids.contains(&"local".to_string()), independent);
                assert_eq!(ids.len(), if independent { 2 } else { 1 });
                assert!(ids.contains(&id));
            }
        }
    }

    #[test]
    fn native_selection_preserves_independent_environment_and_custom_host_sources() {
        assert!(native_amp_selection(false, None));
        assert!(native_amp_selection(false, Some("https://ampcode.com/")));
        assert!(native_amp_selection(
            false,
            Some("HTTPS://AMPCODE.COM:443/")
        ));
        assert!(native_amp_selection(
            false,
            Some("https://ampcode.com/path")
        ));
        assert!(native_amp_selection(false, Some("invalid-url")));
        assert!(!native_amp_selection(true, None));
        assert!(!native_amp_selection(false, Some("https://custom.example")));
    }
    #[tokio::test]
    async fn copilot_native_http_fences_rotation_and_disable() {
        for rotate in [false, true] {
            let dir = std::env::temp_dir().join(random_string().unwrap());
            std::fs::create_dir(&dir).unwrap();
            let path = dir.join("apps.json");
            let original = br#"{"github.com:fixture":{"oauth_token":"native-first-fixture","refresh_token":"owner-only"},"github.com:other":{"oauth_token":"unselected"}}"#;
            std::fs::write(&path, original).unwrap();
            let credential = Credential::CopilotNative {
                source: super::super::sources::CopilotNativeReference {
                    location: super::super::sources::CopilotLocation::Apps,
                    path: Some(path.clone()),
                    entry_key: "github.com:fixture".into(),
                },
            };
            let provider = Provider::Catalog("copilot");
            let vault = Vault::new(Arc::new(Memory::default()), dir.join("lock"));
            let mut tx = vault.begin().unwrap();
            let id = tx
                .document
                .add(provider, "Fixture", "source".into(), credential.clone())
                .unwrap();
            let account = tx.document.accounts[0].clone();
            assert_eq!(
                account.origin(),
                crate::domain::AccountOrigin::BorrowedNative
            );
            let stored = serde_json::to_string(&tx.document).unwrap();
            assert!(!stored.contains("owner-only") && !stored.contains("native-first-fixture"));
            tx.commit().unwrap();
            let adapter = super::managed(&vault, &account);
            let context = http::fixture::context();
            let before = adapter.cache_identity(&context).await.unwrap();
            let changed = path.clone();
            let (endpoint, server) = http::fixture::server_status_with_action(vec![(200, serde_json::json!({"quota_snapshots":{"premium_interactions":{"entitlement":300,"remaining":250,"unlimited":false}}}))], move |_| {
                if rotate { std::fs::write(&changed, br#"{"github.com:fixture":{"oauth_token":"native-second-fixture"}}"#).unwrap(); }
            }).await;
            let result =
                validate_with_endpoint(&context, provider, &credential, Some(&endpoint)).await;
            if rotate {
                assert!(matches!(result, Err(AccountError::Busy)));
                assert_ne!(adapter.cache_identity(&context).await.unwrap(), before);
            } else {
                assert!(result.is_ok());
                assert_eq!(std::fs::read(&path).unwrap(), original);
            }
            let requests = server.await.unwrap();
            assert_eq!(requests.len(), 1);
            assert!(requests[0].starts_with("GET "));
            assert!(requests[0].contains("native-first-fixture"));
            assert!(!requests[0].contains("owner-only") && !requests[0].contains("unselected"));
            let mut tx = vault.begin().unwrap();
            tx.document.patch(&id, None, None, Some(false)).unwrap();
            tx.commit().unwrap();
            assert!(adapter.cache_identity(&context).await.is_none());
            std::fs::remove_file(&path).unwrap();
            assert!(credential.resolve_reference(provider).await.is_err());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
    #[tokio::test]
    async fn claude_native_http_fences_rotation_and_disable() {
        for rotate in [false, true] {
            let dir = std::env::temp_dir().join(random_string().unwrap());
            std::fs::create_dir(&dir).unwrap();
            let path = dir.join("credentials.json");
            let original = br#"{"claudeAiOauth":{"accessToken":"native-first-fixture","refreshToken":"owner-only","scopes":["user:profile"]}}"#;
            std::fs::write(&path, original).unwrap();
            let credential = Credential::ClaudeNative {
                source: super::super::sources::ClaudeNativeReference {
                    location: super::super::sources::ClaudeLocation::CodeFile,
                    path: Some(path.clone()),
                },
            };
            let provider = Provider::Catalog("claude");
            let vault = Vault::new(Arc::new(Memory::default()), dir.join("lock"));
            let mut tx = vault.begin().unwrap();
            let id = tx
                .document
                .add(provider, "Fixture", "source".into(), credential.clone())
                .unwrap();
            let account = tx.document.accounts[0].clone();
            assert_eq!(
                account.origin(),
                crate::domain::AccountOrigin::BorrowedNative
            );
            assert!(
                !serde_json::to_string(&tx.document)
                    .unwrap()
                    .contains("owner-only")
            );
            tx.commit().unwrap();
            let adapter = super::managed(&vault, &account);
            let context = http::fixture::context();
            let before = adapter.cache_identity(&context).await.unwrap();
            let changed = path.clone();
            let (endpoint, server) = http::fixture::server_status_with_action(
                vec![(200, serde_json::json!({"five_hour":{"utilization":25}}))],
                move |_| {
                    if rotate {
                        std::fs::write(
                            &changed,
                            br#"{"claudeAiOauth":{"accessToken":"native-second-fixture"}}"#,
                        )
                        .unwrap();
                    }
                },
            )
            .await;
            let result =
                validate_with_endpoint(&context, provider, &credential, Some(&endpoint)).await;
            if rotate {
                assert!(matches!(result, Err(AccountError::Busy)));
                assert_ne!(adapter.cache_identity(&context).await.unwrap(), before);
            } else {
                assert!(result.is_ok());
                assert_eq!(std::fs::read(&path).unwrap(), original);
            }
            let requests = server.await.unwrap();
            assert_eq!(requests.len(), 1);
            assert!(requests[0].starts_with("GET "));
            assert!(requests[0].contains("Bearer native-first-fixture"));
            assert!(!requests[0].contains("owner-only"));
            let mut tx = vault.begin().unwrap();
            tx.document.patch(&id, None, None, Some(false)).unwrap();
            tx.commit().unwrap();
            assert!(adapter.cache_identity(&context).await.is_none());
            std::fs::remove_file(&path).unwrap();
            assert!(credential.resolve_reference(provider).await.is_err());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
    #[tokio::test]
    async fn codex_native_http_is_read_only_and_fences_source_and_account_changes() {
        for rotate in [false, true] {
            let dir = std::env::temp_dir().join(random_string().unwrap());
            std::fs::create_dir(&dir).unwrap();
            let path = dir.join("auth.json");
            let original = br#"{"tokens":{"access_token":"native-first-fixture","account_id":"fixture-account","refresh_token":"owner-only"}}"#;
            std::fs::write(&path, original).unwrap();
            let credential = Credential::CodexNative {
                source: super::super::sources::CodexNativeReference { path: path.clone() },
            };
            let vault = Vault::new(Arc::new(Memory::default()), dir.join("lock"));
            let mut tx = vault.begin().unwrap();
            let id = tx
                .document
                .add(
                    Provider::Codex,
                    "Fixture",
                    "source".into(),
                    credential.clone(),
                )
                .unwrap();
            let account = tx.document.accounts[0].clone();
            assert!(
                !serde_json::to_string(&tx.document)
                    .unwrap()
                    .contains("native-first-fixture")
            );
            tx.commit().unwrap();
            let adapter = super::managed(&vault, &account);
            let context = http::fixture::context();
            let before = adapter.cache_identity(&context).await.unwrap();
            let change_path = path.clone();
            let (endpoint, server) = http::fixture::server_status_with_action(vec![
                (200, serde_json::json!({"rate_limit":{"primary_window":{"used_percent":25,"limit_window_seconds":18000}}})),
                (200, serde_json::json!({})), (200, serde_json::json!({})),
            ], move |_| {
                if rotate {
                    std::fs::write(&change_path, br#"{"tokens":{"access_token":"native-second-fixture","account_id":"fixture-account"}}"#).unwrap();
                }
            }).await;
            let result =
                validate_with_endpoint(&context, Provider::Codex, &credential, Some(&endpoint))
                    .await;
            if rotate {
                assert!(matches!(result, Err(AccountError::Busy)));
                assert_ne!(adapter.cache_identity(&context).await.unwrap(), before);
            } else {
                let usage = result.unwrap();
                assert_eq!(usage.account.id, "fixture-account");
                assert_eq!(std::fs::read(&path).unwrap(), original);
                let managed = ManagedProvider {
                    origin: account.origin(),
                    label: account.label.clone(),
                    operations: Arc::new(Network),
                    vault: vault.clone(),
                    id: id.clone(),
                    provider: Provider::Codex,
                    provider_id: Provider::Codex.adapter().id(),
                };
                let mut tx = vault.begin().unwrap();
                tx.document.remove(&id).unwrap();
                tx.commit().unwrap();
                assert!(matches!(
                    managed.verify_current(&credential, usage).await,
                    Err(AccountError::NotFound)
                ));
            }
            let requests = server.await.unwrap();
            assert_eq!(requests.len(), 3);
            for request in requests {
                assert!(request.starts_with("GET "));
                assert!(request.contains("Bearer native-first-fixture"));
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("chatgpt-account-id: fixture-account")
                );
                assert!(!request.contains("owner-only"));
            }
            if rotate {
                let mut tx = vault.begin().unwrap();
                tx.document.patch(&id, None, None, Some(false)).unwrap();
                tx.commit().unwrap();
            }
            assert!(adapter.cache_identity(&context).await.is_none());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
    #[tokio::test]
    async fn amp_native_resolution_reaches_http_and_rejects_rotation_during_response() {
        for rotate in [false, true] {
            let dir = std::env::temp_dir().join(random_string().unwrap());
            std::fs::create_dir(&dir).unwrap();
            let path = dir.join("secrets.json");
            std::fs::write(
                &path,
                br#"{"apiKey@https://ampcode.com/":"native-first-fixture"}"#,
            )
            .unwrap();
            let credential = Credential::AmpNative {
                source: super::super::sources::AmpNativeReference {
                    path: path.clone(),
                    enabled: true,
                },
            };
            let vault = Vault::new(Arc::new(Memory::default()), dir.join("lock"));
            let mut tx = vault.begin().unwrap();
            let id = tx
                .document
                .add(
                    Provider::Amp,
                    "Fixture",
                    "native-source".into(),
                    credential.clone(),
                )
                .unwrap();
            let account = tx.document.accounts[0].clone();
            tx.commit().unwrap();
            let adapter = super::managed(&vault, &account);
            let context = http::fixture::context();
            let before = adapter.cache_identity(&context).await.unwrap();
            let change_path = path.clone();
            let (endpoint, server) = http::fixture::server_status_with_action(vec![(200, serde_json::json!({"ok":true,"result":{"displayText":"Signed in as demo@example.com (Pro)\nAmp Free: 75% remaining today (resets daily)"}}))], move |_| {
                if rotate { std::fs::write(&change_path, br#"{"apiKey@https://ampcode.com/":"native-second-fixture"}"#).unwrap(); }
            }).await;
            let result =
                validate_with_endpoint(&context, Provider::Amp, &credential, Some(&endpoint)).await;
            if rotate {
                assert!(matches!(result, Err(AccountError::Busy)));
                assert_ne!(adapter.cache_identity(&context).await.unwrap(), before);
            } else {
                let usage = result.unwrap();
                assert_eq!(usage.account.id, "demo@example.com");
                assert_eq!(usage.windows[0].metric_id.as_deref(), Some("amp-free"));
            }
            let requests = server.await.unwrap();
            assert!(requests[0].contains("Bearer native-first-fixture"));
            let mut tx = vault.begin().unwrap();
            tx.document.patch(&id, None, None, Some(false)).unwrap();
            tx.commit().unwrap();
            assert!(adapter.cache_identity(&context).await.is_none());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn cursor_reference_scopes_requests_and_invalidates_changed_native_login() {
        for rotate in [false, true] {
            let dir = std::env::temp_dir().join(random_string().unwrap());
            std::fs::create_dir(&dir).unwrap();
            let path = dir.join("state.vscdb");
            let status = std::process::Command::new("/usr/bin/sqlite3").arg(&path).arg("CREATE TABLE ItemTable (key TEXT, value TEXT); INSERT INTO ItemTable VALUES ('cursorAuth/accessToken','native-first-fixture'),('cursorAuth/cachedEmail','cursor@example.com'),('cursorAuth/stripeMembershipType','pro'),('cursorAuth/stripeSubscriptionStatus','active');").status().unwrap();
            assert!(status.success());
            let original = std::fs::read(&path).unwrap();
            let source = super::super::sources::CursorNativeReference { path: path.clone() };
            let credential = Credential::CursorNative {
                source: source.clone(),
            };
            assert!(matches!(
                credential.resolve_reference(Provider::Amp).await,
                Err(AccountError::Unsupported)
            ));
            let vault = Vault::new(Arc::new(Memory::default()), dir.join("lock"));
            let mut tx = vault.begin().unwrap();
            let id = tx
                .document
                .add(
                    Provider::Catalog("cursor"),
                    "Cursor",
                    source.identity().unwrap(),
                    credential.clone(),
                )
                .unwrap();
            let account = tx.document.accounts[0].clone();
            tx.commit().unwrap();
            let adapter = super::managed(&vault, &account);
            let context = http::fixture::context();
            let before = adapter.cache_identity(&context).await.unwrap();
            let changed_path = path.clone();
            let payload = serde_json::json!({"membershipType":"pro","isUnlimited":true,"planUsage":{"totalPercentUsed":20}});
            let (endpoint, server) = http::fixture::server_status_with_action(vec![(200,payload.clone()),(200,payload)], move |_| {
                if rotate {
                    assert!(std::process::Command::new("/usr/bin/sqlite3").arg(&changed_path).arg("UPDATE ItemTable SET value='native-second-fixture' WHERE key='cursorAuth/accessToken';").status().unwrap().success());
                }
            }).await;
            let result = validate_with_endpoint(
                &context,
                Provider::Catalog("cursor"),
                &credential,
                Some(&endpoint),
            )
            .await;
            if rotate {
                assert!(matches!(result, Err(AccountError::Busy)));
                assert_ne!(adapter.cache_identity(&context).await.unwrap(), before);
            } else {
                let usage = result.unwrap();
                assert_eq!(usage.account.label, "cursor@example.com");
                assert_eq!(usage.account.subscription_status.as_deref(), Some("active"));
                assert_eq!(original, std::fs::read(&path).unwrap());
                let encoded = serde_json::to_string(&usage).unwrap();
                assert!(!encoded.contains("native-first-fixture"));
            }
            for request in server.await.unwrap() {
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("authorization: bearer native-first-fixture")
                );
                assert!(
                    !request
                        .lines()
                        .next()
                        .unwrap()
                        .contains("native-first-fixture")
                );
            }
            let mut tx = vault.begin().unwrap();
            tx.document.patch(&id, None, None, Some(false)).unwrap();
            assert_eq!(
                tx.document.accounts[0].origin(),
                super::super::AccountOrigin::BorrowedNative
            );
            assert!(
                !serde_json::to_string(&tx.document)
                    .unwrap()
                    .contains("native-first-fixture")
            );
            tx.commit().unwrap();
            assert!(adapter.cache_identity(&context).await.is_none());
            assert_eq!(
                adapter.fetch(&context).await.unwrap_err(),
                ProviderError::SourceDisabled
            );
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[tokio::test]
    async fn grok_references_fence_rotation_and_keep_entries_separate() {
        for rotate in [false, true] {
            let dir = std::env::temp_dir().join(random_string().unwrap());
            std::fs::create_dir(&dir).unwrap();
            let path = dir.join("auth.json");
            let data = serde_json::json!({
                "https://auth.x.ai::first": {"key":"fixture-first", "expires_at":"2099-01-01T00:00:00Z"},
                "https://auth.x.ai::second": {"key":"fixture-second", "expires_at":"2099-01-01T00:00:00Z"}
            });
            std::fs::write(&path, data.to_string()).unwrap();
            let source = super::super::sources::GrokNativeReference {
                path: path.clone(),
                entry_key: "https://auth.x.ai::first".into(),
            };
            let mut second = source.clone();
            second.entry_key = "https://auth.x.ai::second".into();
            assert_ne!(source.identity().unwrap(), second.identity().unwrap());
            assert!(
                source.resolve().await.unwrap().credentials
                    != second.resolve().await.unwrap().credentials
            );
            let credential = Credential::GrokNative {
                source: source.clone(),
            };
            let vault = Vault::new(Arc::new(Memory::default()), dir.join("lock"));
            let mut tx = vault.begin().unwrap();
            let id = tx
                .document
                .add(
                    Provider::Catalog("grok"),
                    "First",
                    source.identity().unwrap(),
                    credential.clone(),
                )
                .unwrap();
            let account = tx.document.accounts[0].clone();
            tx.commit().unwrap();
            let adapter = super::managed(&vault, &account);
            let context = http::fixture::context();
            let before = adapter.cache_identity(&context).await.unwrap();
            let changed = path.clone();
            let original = std::fs::read(&path).unwrap();
            let (endpoint, server) = http::fixture::server_status_with_action(
                vec![(200, serde_json::json!({"config":{"creditUsagePercent":20}}))],
                move |_| {
                    if rotate {
                        let mut data = data.clone();
                        data["https://auth.x.ai::first"]["key"] = "fixture-rotated".into();
                        std::fs::write(&changed, data.to_string()).unwrap();
                    }
                },
            )
            .await;
            let result = validate_with_endpoint(
                &context,
                Provider::Catalog("grok"),
                &credential,
                Some(&endpoint),
            )
            .await;
            if rotate {
                assert!(matches!(result, Err(AccountError::Busy)));
                assert_ne!(adapter.cache_identity(&context).await.unwrap(), before);
            } else {
                assert!(result.is_ok());
                assert_eq!(original, std::fs::read(&path).unwrap());
            }
            assert!(server.await.unwrap()[0].contains("Bearer fixture-first"));
            let mut tx = vault.begin().unwrap();
            assert!(
                !serde_json::to_string(&tx.document)
                    .unwrap()
                    .contains("fixture-first")
            );
            tx.document.patch(&id, None, None, Some(false)).unwrap();
            tx.commit().unwrap();
            assert!(adapter.cache_identity(&context).await.is_none());
            assert_eq!(
                adapter.fetch(&context).await.unwrap_err(),
                ProviderError::SourceDisabled
            );
            std::fs::remove_file(&path).unwrap();
            assert!(source.resolve().await.is_err());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[tokio::test]
    async fn credential_group_keeps_last_success_and_reports_later_key_failure() {
        let (endpoint, server) = http::fixture::server_status(vec![
            (200, serde_json::json!({"ok":true,"result":{"displayText":"Signed in as first@example.com\nAmp Free: 20% remaining"}})),
            (200, serde_json::json!({"ok":true,"result":{"displayText":"Signed in as last@example.com\nAmp Free: 80% remaining"}})),
            (401, serde_json::json!({"error":"fixture"})),
        ]).await;
        let credentials = ["first", "last", "rejected"].map(|token| Credential::ApiKey {
            token: token.into(),
            region: None,
            organization: None,
        });
        let result = validate_credentials(
            &http::fixture::context(),
            Provider::Amp,
            &credentials,
            Some(&endpoint),
        )
        .await
        .unwrap();
        assert_eq!(result.account.id, "last@example.com");
        assert_eq!(result.diagnostics.len(), 1);
        assert_eq!(result.diagnostics[0].source, "amp_key_3");
        assert_eq!(server.await.unwrap().len(), 3);
    }
    #[tokio::test]
    async fn group_retains_success_when_a_later_key_exceeds_collector_budget() {
        struct GroupFixture(String);
        impl ProviderAdapter for GroupFixture {
            fn id(&self) -> ProviderId {
                ProviderId("amp".into())
            }
            fn fetch<'a>(&'a self, context: &'a ProviderContext) -> FetchFuture<'a> {
                Box::pin(async move {
                    let credentials = ["first", "slow"].map(|token| Credential::ApiKey {
                        token: token.into(),
                        region: None,
                        organization: None,
                    });
                    validate_credentials(context, Provider::Amp, &credentials, Some(&self.0))
                        .await
                        .map_err(|e| match e {
                            AccountError::Provider(e) => e,
                            _ => ProviderError::Internal,
                        })
                })
            }
        }
        let response = serde_json::json!({"ok":true,"result":{"displayText":"Signed in as demo@example.com\nAmp Free: 70% remaining"}});
        let (endpoint, server) = http::fixture::server_status_with_async_action(
            vec![(200, response.clone()), (200, response)],
            |index| async move {
                if index == 1 {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                }
            },
        )
        .await;
        let report = Collector {
            context: http::fixture::context(),
        }
        .collect(CollectRequest {
            providers: vec![Arc::new(GroupFixture(endpoint))],
            timeout: std::time::Duration::from_millis(600),
            cancellation: Cancellation::default(),
        })
        .await;
        server.abort();
        let _ = server.await;
        assert_eq!(report.providers.len(), 1);
        assert_eq!(report.providers[0].account.id, "demo@example.com");
        assert_eq!(report.failures[0].code, ProviderError::Timeout);
        assert_eq!(report.providers[0].diagnostics[0].source, "amp_key_2");
    }
    struct MutateDuringQuota {
        vault: Vault,
        id: String,
        remove: bool,
    }
    impl Operations for MutateDuringQuota {
        fn quota<'a>(
            &'a self,
            context: &'a ProviderContext,
            _: Provider,
            _: &'a Credential,
        ) -> OperationFuture<'a, ProviderUsage> {
            Box::pin(async move {
                let mut tx = self.vault.begin()?;
                if self.remove {
                    tx.document.remove(&self.id)?;
                } else {
                    tx.document
                        .accounts
                        .iter_mut()
                        .find(|a| a.id == self.id)
                        .unwrap()
                        .credential = Credential::ApiKey {
                        token: "rotated-fixture".into(),
                        region: None,
                        organization: None,
                    };
                }
                tx.commit()?;
                Ok(MockProvider.fetch(context).await?)
            })
        }
        fn refresh<'a>(
            &'a self,
            _: &'a ProviderContext,
            _: &'a Credential,
        ) -> OperationFuture<'a, Credential> {
            panic!("borrowed source must never refresh")
        }
    }
    #[tokio::test]
    async fn borrowed_results_are_rejected_after_account_removal_or_replacement() {
        for remove in [true, false] {
            let path = std::env::temp_dir().join(random_string().unwrap());
            let vault = Vault::new(Arc::new(Memory::default()), path.join("lock"));
            let source = super::super::sources::CustomProviderReference {
                domain: super::super::sources::QuotioDomain::Production,
                record_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            };
            let mut tx = vault.begin().unwrap();
            let id = tx
                .document
                .add(
                    Provider::Catalog("clinepass"),
                    "Fixture",
                    source.identity().unwrap(),
                    Credential::QuotioCustomProvider { source },
                )
                .unwrap();
            tx.commit().unwrap();
            let adapter = ManagedProvider {
                origin: super::super::AccountOrigin::BorrowedProxy,
                label: "Fixture".into(),
                operations: Arc::new(MutateDuringQuota {
                    vault: vault.clone(),
                    id: id.clone(),
                    remove,
                }),
                vault,
                id,
                provider: Provider::Catalog("clinepass"),
                provider_id: ProviderId("clinepass".into()),
            };
            let result = adapter.read(&http::fixture::context()).await;
            assert!(matches!(
                result,
                Err(AccountError::NotFound | AccountError::Busy)
            ));
            cleanup(path);
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
            quota_calls: AtomicUsize::new(0),
            wait_for_refresh: std::sync::atomic::AtomicBool::new(false),
            release_refresh: tokio::sync::Notify::new(),
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
            origin: super::super::AccountOrigin::Owned,
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
    async fn factory_rotation_and_uncertain_writes_never_replay() {
        struct FailingWrite {
            memory: Arc<Memory>,
            mode: u8,
        }
        impl Backend for FailingWrite {
            fn read(&self) -> Result<Option<Vec<u8>>, AccountError> {
                self.memory.read()
            }
            fn write(&self, bytes: &[u8]) -> Result<(), AccountError> {
                let rotated = String::from_utf8_lossy(bytes).contains("rotated");
                if (self.mode == 1 && !rotated) || (self.mode >= 2 && rotated) {
                    if self.mode == 3 {
                        self.memory.write(bytes)?;
                    }
                    return Err(AccountError::CommitUncertain);
                }
                self.memory.write(bytes)
            }
        }
        for mode in 0..=4 {
            let (vault, fake, id, _, path) = setup(0, false, mode == 4, true);
            let mut tx = vault.begin().unwrap();
            tx.document.accounts[0].provider = Provider::Factory;
            tx.document.accounts[0].credential = Credential::FactoryOAuth {
                access_token: "old".into(),
                refresh_token: "refresh".into(),
                organization_id: Some("org".into()),
                expires_at: 0,
                refresh_pending: false,
            };
            tx.commit().unwrap();
            let failing = Vault::new(
                Arc::new(FailingWrite {
                    memory: fake.memory.clone(),
                    mode,
                }),
                path.join("lock"),
            );
            let adapter = managed(failing, fake.clone(), id.clone(), Provider::Factory);
            assert!(!adapter.idempotent());
            let context = http::fixture::context();
            assert!(adapter.read(&context).await.is_err());
            assert_eq!(
                fake.refreshes.load(Ordering::SeqCst),
                usize::from(mode != 1)
            );
            assert_eq!(
                fake.quota_calls.load(Ordering::SeqCst),
                usize::from(mode == 0)
            );
            if mode != 1 {
                let restarted = managed(
                    Vault::new(fake.memory.clone(), path.join("lock")),
                    fake.clone(),
                    id,
                    Provider::Factory,
                );
                assert!(restarted.read(&context).await.is_err());
                assert_eq!(fake.refreshes.load(Ordering::SeqCst), 1);
                if mode == 2 || mode == 4 {
                    assert!(restarted.cache_identity(&context).await.is_none());
                }
            }
            cleanup(path);
        }
    }

    #[tokio::test]
    async fn grok_owned_rotation_persists_before_quota_and_uncertainty_blocks_replay() {
        for refresh_fails in [false, true] {
            let (vault, fake, id, _, path) = setup(0, true, refresh_fails, true);
            let mut tx = vault.begin().unwrap();
            let account = &mut tx.document.accounts[0];
            account.provider = Provider::Catalog("grok");
            account.credential = Credential::GrokOAuth {
                access_token: "old".into(),
                refresh_token: "refresh".into(),
                expires_at: 0,
                refresh_pending: false,
            };
            tx.commit().unwrap();
            let adapter = managed(
                vault.clone(),
                fake.clone(),
                id.clone(),
                Provider::Catalog("grok"),
            );
            assert!(!adapter.idempotent());
            let context = http::fixture::context();
            let (a, b) = tokio::join!(adapter.read(&context), adapter.read(&context));
            assert!(a.is_err() && b.is_err());
            assert_eq!(fake.refreshes.load(Ordering::SeqCst), 1);
            let tx = vault.begin().unwrap();
            assert!(
                matches!(&tx.document.accounts[0].credential, Credential::GrokOAuth { refresh_pending, refresh_token, .. } if *refresh_pending == refresh_fails && refresh_token == if refresh_fails {"refresh"} else {"rotated"})
            );
            drop(tx);
            let restarted = managed(
                Vault::new(fake.memory.clone(), path.join("lock")),
                fake.clone(),
                id,
                Provider::Catalog("grok"),
            );
            assert!(restarted.read(&context).await.is_err());
            assert_eq!(fake.refreshes.load(Ordering::SeqCst), 1);
            if refresh_fails {
                assert_eq!(fake.quota_calls.load(Ordering::SeqCst), 0);
                assert!(restarted.cache_identity(&context).await.is_none());
            }
            cleanup(path);
        }
    }

    #[tokio::test]
    async fn grok_uncertain_rotation_commit_never_replays_refresh_or_starts_quota() {
        struct Uncertain {
            memory: Arc<Memory>,
            persisted: bool,
        }
        impl Backend for Uncertain {
            fn read(&self) -> Result<Option<Vec<u8>>, AccountError> {
                self.memory.read()
            }
            fn write(&self, bytes: &[u8]) -> Result<(), AccountError> {
                if String::from_utf8_lossy(bytes).contains("rotated") {
                    if self.persisted {
                        self.memory.write(bytes)?;
                    }
                    return Err(AccountError::CommitUncertain);
                }
                self.memory.write(bytes)
            }
        }
        for persisted in [false, true] {
            let (vault, fake, id, _, path) = setup(0, false, false, false);
            let mut tx = vault.begin().unwrap();
            tx.document.accounts[0].provider = Provider::Catalog("grok");
            tx.document.accounts[0].credential = Credential::GrokOAuth {
                access_token: "old".into(),
                refresh_token: "refresh".into(),
                expires_at: 0,
                refresh_pending: false,
            };
            tx.commit().unwrap();
            let vault = Vault::new(
                Arc::new(Uncertain {
                    memory: fake.memory.clone(),
                    persisted,
                }),
                path.join("lock"),
            );
            let adapter = managed(vault, fake.clone(), id.clone(), Provider::Catalog("grok"));
            assert!(matches!(
                adapter.read(&http::fixture::context()).await,
                Err(AccountError::CommitUncertain)
            ));
            assert_eq!(fake.quota_calls.load(Ordering::SeqCst), 0);
            let restarted = managed(
                Vault::new(fake.memory.clone(), path.join("lock")),
                fake.clone(),
                id,
                Provider::Catalog("grok"),
            );
            assert_eq!(
                restarted.read(&http::fixture::context()).await.is_ok(),
                persisted
            );
            assert_eq!(fake.refreshes.load(Ordering::SeqCst), 1);
            cleanup(path);
        }
    }

    #[tokio::test]
    async fn disabled_owned_accounts_skip_quota_cache_and_refresh() {
        let (vault, fake, codex, amp, path) = setup(0, false, false, false);
        for (id, provider) in [(codex, Provider::Codex), (amp, Provider::Amp)] {
            let mut tx = vault.begin().unwrap();
            tx.document.patch(&id, None, None, Some(false)).unwrap();
            tx.commit().unwrap();
            let adapter = managed(vault.clone(), fake.clone(), id, provider);
            let context = http::fixture::context();
            assert!(adapter.cache_identity(&context).await.is_none());
            assert!(matches!(
                adapter.read(&context).await,
                Err(AccountError::SourceDisabled)
            ));
        }
        assert_eq!(fake.refreshes.load(Ordering::SeqCst), 0);
        cleanup(path);
    }
    #[tokio::test]
    async fn disabling_during_refresh_preserves_rotation_without_starting_quota() {
        let (vault, fake, id, _, path) = setup(0, false, false, false);
        fake.wait_for_refresh.store(true, Ordering::SeqCst);
        let adapter = managed(vault.clone(), fake.clone(), id.clone(), Provider::Codex);
        let running = tokio::spawn(async move { adapter.read(&http::fixture::context()).await });
        fake.started.notified().await;
        patch(vault.clone(), id, None, None, Some(false))
            .await
            .unwrap();
        fake.release_refresh.notify_one();
        assert!(matches!(
            running.await.unwrap(),
            Err(AccountError::SourceDisabled)
        ));
        assert_eq!(fake.quota_calls.load(Ordering::SeqCst), 0);
        let tx = vault.begin().unwrap();
        assert!(!tx.document.accounts[0].enabled());
        assert!(
            matches!(&tx.document.accounts[0].credential, Credential::CodexOAuth { refresh_token, .. } if refresh_token == "rotated")
        );
        drop(tx);
        cleanup(path);
    }
    #[tokio::test]
    async fn disabling_during_quota_discards_the_result() {
        let (vault, fake, id, _, path) = setup(3600, true, false, false);
        let adapter = managed(vault.clone(), fake.clone(), id.clone(), Provider::Codex);
        let running = tokio::spawn(async move { adapter.read(&http::fixture::context()).await });
        fake.started.notified().await;
        patch(vault, id, None, None, Some(false)).await.unwrap();
        assert!(matches!(running.await.unwrap(), Err(AccountError::Busy)));
        assert_eq!(fake.refreshes.load(Ordering::SeqCst), 0);
        cleanup(path);
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

#[cfg(test)]
mod receipt_tests {
    use super::*;
    use crate::accounts::vault::{Backend, tests::Memory};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture() -> (Vault, Arc<Memory>, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "quotio-receipt-{}.lock",
            crate::accounts::random_string().unwrap()
        ));
        let backend = Arc::new(Memory::default());
        (Vault::new(backend.clone(), path.clone()), backend, path)
    }
    fn intent(key: &str, body: &str) -> MutationIntent {
        MutationIntent::new(key, crate::cache::fingerprint(&[body])).unwrap()
    }
    fn create(document: &mut crate::accounts::Document) -> Result<String, AccountError> {
        document.add(
            Provider::Amp,
            "label",
            "identity".into(),
            Credential::ApiKey {
                token: "fixture-private-credential".into(),
                region: None,
                organization: None,
            },
        )
    }

    struct UncertainWrite(Memory);
    impl crate::accounts::vault::Backend for UncertainWrite {
        fn read(&self) -> Result<Option<Vec<u8>>, AccountError> {
            self.0.read()
        }
        fn write(&self, bytes: &[u8]) -> Result<(), AccountError> {
            self.0.write(bytes)?;
            Err(AccountError::CommitUncertain)
        }
    }
    #[tokio::test]
    async fn uncertain_commit_preserves_receipt_for_recovery_without_second_write() {
        let path = std::env::temp_dir().join(format!(
            "quotio-uncertain-{}",
            crate::accounts::random_string().unwrap()
        ));
        let vault = Vault::new(Arc::new(UncertainWrite(Memory::default())), path.clone());
        let intent = intent("uncertain-fixture", "create");
        assert!(matches!(
            commit_once(vault.clone(), intent.clone(), create).await,
            Err(AccountError::CommitUncertain)
        ));
        let id = mutation_receipt(vault.clone(), &intent)
            .await
            .unwrap()
            .unwrap();
        let retry = commit_once(vault.clone(), intent, |_| {
            panic!("must recover committed receipt")
        })
        .await
        .unwrap();
        assert_eq!(id, retry);
        assert_eq!(list(vault).await.unwrap().len(), 1);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn replay_after_reopening_vault_does_not_repeat_write_or_resurrect_deleted_account() {
        let (vault, backend, path) = fixture();
        let id = commit_once(vault.clone(), intent("intent", "create"), create)
            .await
            .unwrap();
        assert_eq!(vault.begin().unwrap().document.version, 2);
        remove(vault, id.clone()).await.unwrap();
        let reopened = Vault::new(backend, path.clone());
        let replay = commit_once(reopened.clone(), intent("intent", "create"), |_| {
            panic!("replayed mutation")
        })
        .await
        .unwrap();
        assert_eq!(replay, id);
        assert!(list(reopened.clone()).await.unwrap().is_empty());
        assert!(matches!(
            mutation_receipt(reopened, &intent("intent", "other body")).await,
            Err(AccountError::IdempotencyConflict)
        ));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn failed_native_write_commits_neither_account_nor_receipt_and_retry_recovers() {
        let (vault, backend, path) = fixture();
        backend.fail.store(true, Ordering::SeqCst);
        assert!(matches!(
            commit_once(vault.clone(), intent("intent", "create"), create).await,
            Err(AccountError::Storage)
        ));
        assert!(
            mutation_receipt(vault.clone(), &intent("intent", "create"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(list(vault.clone()).await.unwrap().is_empty());
        backend.fail.store(false, Ordering::SeqCst);
        commit_once(vault.clone(), intent("intent", "create"), create)
            .await
            .unwrap();
        assert_eq!(list(vault).await.unwrap().len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn concurrent_retries_commit_once_and_keep_keys_out_of_serialized_receipts() {
        let (vault, backend, path) = fixture();
        let writes = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let vault = vault.clone();
            let writes = writes.clone();
            tasks.push(tokio::spawn(async move {
                commit_once(vault, intent("private-retry-key", "body"), |document| {
                    writes.fetch_add(1, Ordering::SeqCst);
                    create(document)
                })
                .await
                .unwrap()
            }));
        }
        let first = tasks.remove(0).await.unwrap();
        for task in tasks {
            assert_eq!(task.await.unwrap(), first);
        }
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        let bytes = backend.read().unwrap().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let receipts = value["mutation_receipts"].to_string();
        assert!(!receipts.contains("private-retry-key"));
        assert!(!receipts.contains("fixture-private-credential"));
        let _ = std::fs::remove_file(path);
    }
}
