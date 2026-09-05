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
}
impl From<&super::Account> for AccountDto {
    fn from(account: &super::Account) -> Self {
        Self {
            id: account.id.clone(),
            provider: account.provider,
            label: account.label.clone(),
            active: account.active,
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
pub struct PreparedAccount {
    provider: Provider,
    label: String,
    credential: Credential,
    identity: String,
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
    let account = service::patch(vault, id, patch.label, patch.active).await?;
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
