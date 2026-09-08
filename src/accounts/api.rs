//! API-neutral account operations. These types deliberately exclude credentials.
use super::{AccountError, Credential, service, vault::Vault};
use crate::{cli::Provider, providers::ProviderContext};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct AccountDto {
    pub id: String,
    pub provider: Provider,
    pub label: String,
    pub active: bool,
    pub origin: super::AccountOrigin,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<&'static str>,
}
impl From<&super::Account> for AccountDto {
    fn from(account: &super::Account) -> Self {
        Self {
            id: account.id.clone(),
            provider: account.provider,
            label: account.label.clone(),
            active: account.active,
            origin: account.origin(),
            enabled: account.enabled(),
            source_kind: match account.credential {
                Credential::GrokNative { .. } => Some("grok_native"),
                Credential::CursorNative { .. } => Some("cursor_native"),
                Credential::AmpNative { .. } => Some("amp_native"),
                Credential::CodexNative { .. } => Some("codex_native"),
                Credential::ClaudeNative { .. } => Some("claude_native"),
                Credential::QuotioCustomProvider { .. } => Some("quotio_custom_provider"),
                _ => None,
            },
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyInput {
    pub provider: Provider,
    pub label: Option<String>,
    pub api_key: String,
    #[serde(default)]
    pub settings: BTreeMap<String, String>,
    pub region: Option<String>,
    pub organization: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountPatch {
    pub enabled: Option<bool>,
    pub label: Option<String>,
    pub active: Option<bool>,
}
fn credential(input: ApiKeyInput, context: &ProviderContext) -> Result<Credential, AccountError> {
    let ApiKeyInput {
        provider,
        api_key,
        region,
        organization,
        settings,
        ..
    } = input;
    let token = api_key.trim();
    if token.is_empty() || token.len() > 16_384 || token.chars().any(char::is_control) {
        return Err(AccountError::Input);
    }
    let region_valid = matches!(
        (provider, region.as_deref()),
        (_, None)
            | (Provider::Factory, Some("global" | "eu"))
            | (Provider::Zai | Provider::MiniMax, Some("global" | "cn"))
    );
    if !region_valid || (provider != Provider::Factory && organization.is_some()) {
        return Err(AccountError::Unsupported);
    }
    if let Some(definition) = provider.catalog()
        && definition.auth == crate::providers::catalog::AuthKind::OAuth
    {
        return Err(AccountError::NativeOAuth(definition.key_env));
    }
    if provider.catalog().is_some() {
        Ok(Credential::CatalogKey {
            token: token.into(),
            settings: service::provider_settings(provider, settings, context)?,
        })
    } else if provider.api_key_name().is_some() {
        if !settings.is_empty() {
            return Err(AccountError::Settings);
        };
        Ok(Credential::ApiKey {
            token: token.into(),
            region,
            organization,
        })
    } else {
        Err(AccountError::Unsupported)
    }
}
#[derive(Deserialize)]
#[serde(untagged)]
pub enum AccountCreateInput {
    ApiKey(ApiKeyInput),
    GrokOwned(GrokOwnedInput),
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrokOwnedKind {
    GrokOwned,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrokOwnedInput {
    pub kind: GrokOwnedKind,
    pub label: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
}
pub fn prepare_grok_owned(input: GrokOwnedInput) -> Result<PreparedAccount, AccountError> {
    let valid = |s: &str| {
        !s.is_empty()
            && s.len() <= 16_384
            && !s.chars().any(|c| c.is_control() || c.is_whitespace())
    };
    if !valid(&input.access_token) || !valid(&input.refresh_token) || input.expires_at < 0 {
        return Err(AccountError::Input);
    }
    Ok(PreparedAccount {
        provider: Provider::Catalog("grok"),
        label: super::validate_label(&input.label)?,
        identity: crate::cache::fingerprint(&["grok_owned", &input.refresh_token]),
        credential: Credential::GrokOAuth {
            access_token: crate::providers::catalog::oauth_editors::grok_oauth_token(
                crate::providers::Secret(input.access_token),
            )?
            .0,
            refresh_token: input.refresh_token,
            expires_at: input.expires_at,
            refresh_pending: false,
        },
    })
}

pub struct PreparedAccount {
    provider: Provider,
    label: String,
    credential: Credential,
    identity: String,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceInput {
    ClaudeNative {
        location: super::sources::ClaudeLocation,
    },
    CodexNative {
        #[serde(default)]
        location: super::sources::CodexLocation,
    },
    GrokNative {
        entry_key: String,
    },
    CursorNative {},
    AmpNative {},
    QuotioCustomProvider {
        source: super::sources::CustomProviderReference,
    },
}
pub async fn prepare_source(input: SourceInput) -> Result<PreparedAccount, AccountError> {
    let (identity, credential, resolved) = match input {
        SourceInput::ClaudeNative { location } => {
            let source = super::sources::ClaudeNativeReference::system(location)?;
            let resolved = source.resolve().await?;
            (
                source.identity()?,
                Credential::ClaudeNative { source },
                resolved,
            )
        }
        SourceInput::CodexNative { location } => {
            let source = super::sources::CodexNativeReference::system(location)?;
            let resolved = source.resolve().await?;
            (
                source.identity()?,
                Credential::CodexNative { source },
                resolved,
            )
        }
        SourceInput::QuotioCustomProvider { source } => {
            let resolved = source.resolve().await?;
            (
                source.identity()?,
                Credential::QuotioCustomProvider { source },
                resolved,
            )
        }
        SourceInput::GrokNative { entry_key } => {
            let source = super::sources::GrokNativeReference::system(entry_key)?;
            let resolved = source.resolve().await?;
            (
                source.identity()?,
                Credential::GrokNative { source },
                resolved,
            )
        }
        SourceInput::CursorNative {} => {
            let source = super::sources::CursorNativeReference::system()?;
            let resolved = source.resolve().await?;
            (
                source.identity()?,
                Credential::CursorNative { source },
                resolved,
            )
        }
        SourceInput::AmpNative {} => {
            let source = super::sources::AmpNativeReference::system()?;
            let resolved = source.resolve().await?;
            (
                source.identity()?,
                Credential::AmpNative { source },
                resolved,
            )
        }
    };
    let provider = resolved.provider;
    let label = if provider == Provider::Catalog("cursor")
        && super::validate_label(&resolved.label).is_err()
    {
        "Local Cursor account".into()
    } else {
        resolved.label
    };
    Ok(PreparedAccount {
        provider,
        label,
        identity,
        credential,
    })
}

pub async fn prepare(
    context: &ProviderContext,
    input: ApiKeyInput,
) -> Result<PreparedAccount, AccountError> {
    let provider = input.provider;
    let requested_label = input.label.clone();
    let credential = credential(input, context)?;
    let usage = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        service::validate(context, provider, &credential),
    )
    .await
    .map_err(|_| AccountError::Cancelled)??;
    let label = service::default_label(requested_label.as_deref(), &credential)?;
    Ok(PreparedAccount {
        provider,
        label,
        credential,
        identity: usage.account.id,
    })
}
pub async fn save(vault: Vault, prepared: PreparedAccount) -> Result<AccountDto, AccountError> {
    let account = service::add_persisted(
        vault,
        prepared.provider,
        prepared.label,
        prepared.credential,
        prepared.identity,
    )
    .await?;
    Ok(AccountDto::from(&account))
}
pub async fn save_once(
    vault: Vault,
    prepared: PreparedAccount,
    intent: service::MutationIntent,
) -> Result<String, AccountError> {
    service::commit_once(vault, intent, move |document| {
        document.add(
            prepared.provider,
            &prepared.label,
            prepared.identity,
            prepared.credential,
        )
    })
    .await
}
pub async fn update_once(
    vault: Vault,
    id: String,
    patch: AccountPatch,
    intent: service::MutationIntent,
) -> Result<String, AccountError> {
    service::commit_once(vault, intent, move |document| {
        document.patch(&id, patch.label.as_deref(), patch.active, patch.enabled)?;
        Ok(id)
    })
    .await
}
pub async fn remove_once(
    vault: Vault,
    id: String,
    intent: service::MutationIntent,
) -> Result<String, AccountError> {
    service::commit_once(vault, intent, move |document| {
        document.remove(&id)?;
        Ok(id)
    })
    .await
}

pub async fn create(
    vault: Vault,
    context: &ProviderContext,
    input: ApiKeyInput,
) -> Result<AccountDto, AccountError> {
    save(vault, prepare(context, input).await?).await
}
pub async fn list(vault: Vault) -> Result<Vec<AccountDto>, AccountError> {
    Ok(service::list(vault)
        .await?
        .iter()
        .map(AccountDto::from)
        .collect())
}
pub async fn get(vault: Vault, id: String) -> Result<AccountDto, AccountError> {
    let account = service::get(vault, id).await?;
    Ok(AccountDto::from(&account))
}
pub async fn update(
    vault: Vault,
    id: String,
    patch: AccountPatch,
) -> Result<AccountDto, AccountError> {
    let account = service::patch(vault, id, patch.label, patch.active, patch.enabled).await?;
    Ok(AccountDto::from(&account))
}
pub async fn remove(vault: Vault, id: String) -> Result<(), AccountError> {
    service::remove(vault, id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_input_rejects_unknown_fields_and_never_accepts_identity() {
        let input: ApiKeyInput = serde_json::from_str(
            r#"{"provider":"amp","api_key":"secret","settings":{},"region":null,"organization":null}"#,
        )
        .unwrap();
        assert_eq!(input.provider, Provider::Amp);
        assert!(
            serde_json::from_str::<ApiKeyInput>(
                r#"{"provider":"amp","api_key":"secret","identity":"caller-controlled"}"#,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn save_returns_committed_dto_without_post_write_read() {
        use crate::accounts::vault::Backend;
        use std::sync::{Arc, Mutex};
        struct ReadFailsAfterWrite(Mutex<bool>);
        impl Backend for ReadFailsAfterWrite {
            fn read(&self) -> Result<Option<Vec<u8>>, AccountError> {
                if *self.0.lock().unwrap() {
                    Err(AccountError::Storage)
                } else {
                    Ok(None)
                }
            }
            fn write(&self, _: &[u8]) -> Result<(), AccountError> {
                *self.0.lock().unwrap() = true;
                Ok(())
            }
        }
        let path = std::env::temp_dir().join(format!(
            "quotio-api-save-{}.lock",
            crate::accounts::random_string().unwrap()
        ));
        let vault = Vault::new(Arc::new(ReadFailsAfterWrite(Mutex::new(false))), path);
        let account = save(
            vault,
            PreparedAccount {
                provider: Provider::Amp,
                label: "saved".into(),
                credential: Credential::ApiKey {
                    token: "secret".into(),
                    region: None,
                    organization: None,
                },
                identity: "verified".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(account.provider, Provider::Amp);
        assert_eq!(account.label, "saved");
        assert!(account.active);
    }

    #[tokio::test]
    async fn save_write_failure_preserves_existing_storage() {
        use crate::accounts::vault::Backend;
        use std::sync::{Arc, Mutex};
        struct WriteFails(Mutex<Option<Vec<u8>>>);
        impl Backend for WriteFails {
            fn read(&self) -> Result<Option<Vec<u8>>, AccountError> {
                Ok(self.0.lock().unwrap().clone())
            }
            fn write(&self, _: &[u8]) -> Result<(), AccountError> {
                Err(AccountError::Storage)
            }
        }
        let backend = Arc::new(WriteFails(Mutex::new(Some(
            serde_json::to_vec(&crate::accounts::Document::empty()).unwrap(),
        ))));
        let path = std::env::temp_dir().join(format!(
            "quotio-api-write-{}.lock",
            crate::accounts::random_string().unwrap()
        ));
        let vault = Vault::new(backend.clone(), path);
        let result = save(
            vault,
            PreparedAccount {
                provider: Provider::Amp,
                label: "saved".into(),
                credential: Credential::ApiKey {
                    token: "secret".into(),
                    region: None,
                    organization: None,
                },
                identity: "verified".into(),
            },
        )
        .await;
        assert!(matches!(result, Err(AccountError::Storage)));
        assert_eq!(
            *backend.0.lock().unwrap(),
            Some(serde_json::to_vec(&crate::accounts::Document::empty()).unwrap())
        );
    }

    #[tokio::test]
    async fn patch_is_one_transaction_when_label_conflicts() {
        use crate::accounts::vault::tests::Memory;
        use std::sync::Arc;
        let path = std::env::temp_dir().join(format!(
            "quotio-api-{}.lock",
            crate::accounts::random_string().unwrap()
        ));
        let vault = Vault::new(Arc::new(Memory::default()), path);
        let key = |token: &str| Credential::ApiKey {
            token: token.into(),
            region: None,
            organization: None,
        };
        let first = service::add(
            vault.clone(),
            Provider::Amp,
            "first".into(),
            key("one"),
            "one".into(),
        )
        .await
        .unwrap();
        let second = service::add(
            vault.clone(),
            Provider::Amp,
            "second".into(),
            key("two"),
            "two".into(),
        )
        .await
        .unwrap();
        assert!(matches!(
            update(
                vault.clone(),
                second.clone(),
                AccountPatch {
                    enabled: None,
                    label: Some("first".into()),
                    active: Some(true)
                }
            )
            .await,
            Err(AccountError::Duplicate)
        ));
        let accounts = list(vault).await.unwrap();
        assert!(
            accounts
                .iter()
                .any(|account| account.id == first && account.active)
        );
        assert!(
            accounts
                .iter()
                .any(|account| account.id == second && !account.active)
        );
    }

    #[test]
    fn patch_rejects_unknown_fields() {
        assert!(
            serde_json::from_str::<AccountPatch>(r#"{"active":true,"credential":"secret"}"#)
                .is_err()
        );
    }
}
