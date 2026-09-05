//! Provider metadata safe to expose through the local API.
use crate::cli::Provider;
use serde::Serialize;

#[derive(Clone, Copy, Serialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    ApiKey,
    OAuth,
    Native,
}
#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct SettingMetadata {
    pub name: &'static str,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<&'static [&'static str]>,
}
#[derive(Clone, Copy, Serialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Usage,
    AddAccount,
    RenameAccount,
    SelectAccount,
    RemoveAccount,
    StartOAuth,
}
#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct ProviderCapability {
    pub provider: Provider,
    pub auth: Vec<AuthMethod>,
    pub settings: Vec<SettingMetadata>,
    /// Usage collection works on every supported platform; saved accounts use macOS Keychain.
    pub usage_platform: &'static str,
    pub account_storage_platform: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_instructions: Option<&'static str>,
    pub operations: Vec<Operation>,
}
const FACTORY_REGIONS: &[&str] = &["global", "eu"];
const ASIA_REGIONS: &[&str] = &["global", "cn"];
pub fn capability(provider: Provider) -> ProviderCapability {
    let mut settings: Vec<SettingMetadata> = provider
        .catalog()
        .map(|definition| {
            definition
                .settings
                .iter()
                .map(|setting| SettingMetadata {
                    name: setting.name,
                    required: setting.required,
                    values: None,
                })
                .collect()
        })
        .unwrap_or_default();
    match provider {
        Provider::Factory => {
            settings.push(SettingMetadata {
                name: "region",
                required: false,
                values: Some(FACTORY_REGIONS),
            });
            settings.push(SettingMetadata {
                name: "organization",
                required: false,
                values: None,
            });
        }
        Provider::Zai | Provider::MiniMax => settings.push(SettingMetadata {
            name: "region",
            required: false,
            values: Some(ASIA_REGIONS),
        }),
        _ => (),
    }
    let native = match provider {
        Provider::Antigravity => Some(
            "Sign in with the Antigravity CLI, then authorize Quotio to read its existing local login.",
        ),
        Provider::Catalog(id)
            if provider.catalog().is_some_and(|definition| {
                definition.auth == crate::providers::catalog::AuthKind::OAuth
            }) =>
        {
            match id {
                "claude" => {
                    Some("Sign in with Claude Code or set its supported local access token.")
                }
                "gemini" => {
                    Some("Sign in with Gemini CLI or set its supported local access token.")
                }
                "copilot" => {
                    Some("Sign in with GitHub Copilot CLI or set its supported local access token.")
                }
                "cursor" => Some("Sign in with Cursor to make its local login available."),
                "grok" => Some("Sign in with the supported Grok editor integration."),
                _ => Some("Sign in with the provider's supported local CLI or application."),
            }
        }
        _ => None,
    };
    let auth = match provider {
        Provider::Codex => vec![AuthMethod::OAuth],
        Provider::Antigravity => vec![AuthMethod::Native],
        Provider::Catalog(_) if native.is_some() => vec![AuthMethod::Native],
        _ if provider.api_key_name().is_some() => vec![AuthMethod::ApiKey],
        _ => Vec::new(),
    };
    let mut operations = vec![Operation::Usage];
    if provider.supports_accounts() {
        operations.extend([
            Operation::AddAccount,
            Operation::RenameAccount,
            Operation::SelectAccount,
            Operation::RemoveAccount,
        ]);
    }
    if provider == Provider::Codex {
        operations.push(Operation::StartOAuth);
    }
    ProviderCapability {
        provider,
        auth,
        settings,
        usage_platform: "all",
        account_storage_platform: provider.supports_accounts().then_some("macos"),
        native_instructions: native,
        operations,
    }
}
pub fn all() -> Vec<ProviderCapability> {
    clap::ValueEnum::value_variants()
        .iter()
        .copied()
        .map(capability)
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_metadata_and_core_settings_are_exposed_without_environment_names() {
        let factory = capability(Provider::Factory);
        assert_eq!(factory.auth, vec![AuthMethod::ApiKey]);
        assert!(
            factory
                .settings
                .iter()
                .any(|setting| setting.name == "organization")
        );
        assert_eq!(capability(Provider::Codex).auth, vec![AuthMethod::OAuth]);
        for definition in crate::providers::catalog::definitions() {
            let capability = capability(Provider::Catalog(definition.id));
            assert_eq!(capability.settings.len(), definition.settings.len());
        }
    }
}
