use super::{AccountError, Credential, service, vault::Vault};
use crate::{
    cli::{AccountCommand, Format, Provider},
    providers::ProviderContext,
};
use clap::ValueEnum;

pub async fn run(
    command: AccountCommand,
    context: &ProviderContext,
) -> Result<String, AccountError> {
    if !cfg!(target_os = "macos") {
        return Err(AccountError::Unsupported);
    }
    let vault = Vault::system()?;
    match command {
        AccountCommand::Authorize { provider } => {
            if provider != Provider::Antigravity {
                return Err(AccountError::Unsupported);
            }
            crate::providers::antigravity_auth::authorize().await?;
            Ok(
                "Antigravity credentials are readable. Run quotio usage --provider antigravity.\n"
                    .into(),
            )
        }
        AccountCommand::List { format } => {
            let accounts = service::list(vault).await?;
            match format {
                Format::Json => serde_json::to_string_pretty(
                    &accounts.iter().map(|a| a.info()).collect::<Vec<_>>(),
                )
                .map(|s| format!("{s}\n"))
                .map_err(|_| AccountError::Corrupt),
                Format::Text => {
                    if accounts.is_empty() {
                        return Ok("No saved accounts. Run quotio accounts add --help.\n".into());
                    }
                    Ok(accounts
                        .iter()
                        .map(|a| {
                            format!(
                                "{} {}  {}  {}\n",
                                if a.active { "*" } else { " " },
                                a.id,
                                a.provider.to_possible_value().expect("provider").get_name(),
                                a.label
                            )
                        })
                        .collect())
                }
            }
        }
        AccountCommand::Use { id } => {
            service::select(vault, id).await?;
            Ok("Active account updated.\n".into())
        }
        AccountCommand::Remove { id } => {
            service::remove(vault, id).await?;
            Ok("Account removed from Quotio.\n".into())
        }
        AccountCommand::Add {
            provider,
            label,
            token_stdin,
            no_browser,
            region,
            organization,
            settings,
        } => {
            if let Some(label) = &label {
                super::validate_label(label)?;
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
            let metadata = parse_settings(provider, &settings, context)?;
            let credential = match provider {
                Provider::Codex if !token_stdin => {
                    super::oauth::login(context, !no_browser).await?
                }
                provider if provider.api_key_name().is_some() && !no_browser => {
                    let name = provider.to_possible_value().expect("provider");
                    let name = match provider {
                        Provider::Amp => "Amp",
                        Provider::Factory => "Factory",
                        Provider::MiniMax => "MiniMax Token Plan",
                        _ => name.get_name(),
                    };
                    let token = super::input::read_api_key(name, token_stdin).await?;
                    let token = token.trim();
                    if token.is_empty()
                        || token.len() > 16384
                        || token.chars().any(char::is_control)
                    {
                        return Err(AccountError::Input);
                    }
                    if provider.catalog().is_some() {
                        Credential::CatalogKey {
                            token: token.into(),
                            settings: metadata,
                        }
                    } else {
                        Credential::ApiKey {
                            token: token.into(),
                            region,
                            organization,
                        }
                    }
                }
                _ => return Err(AccountError::Unsupported),
            };
            let usage = service::validate(context, provider, &credential).await?;
            let label = service::default_label(label.as_deref(), &credential)?;
            let id = service::add(vault, provider, label, credential, usage.account.id).await?;
            Ok(format!("Account validated and saved: {id}\n"))
        }
    }
}

fn parse_settings(
    provider: Provider,
    args: &[String],
    context: &ProviderContext,
) -> Result<std::collections::BTreeMap<String, String>, AccountError> {
    let mut values = std::collections::BTreeMap::new();
    for arg in args {
        let (name, value) = arg.split_once('=').ok_or(AccountError::Settings)?;
        if values.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(AccountError::Settings);
        }
    }
    service::provider_settings(provider, values, context)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn key(token: &str) -> Credential {
        Credential::ApiKey {
            token: token.into(),
            region: None,
            organization: None,
        }
    }
    #[test]
    fn defaults_to_email_or_masked_key_and_respects_override() {
        let oauth = Credential::CodexOAuth {
            access_token: "secret-access".into(),
            refresh_token: "secret-refresh".into(),
            id_token: "secret-id".into(),
            account_id: "account".into(),
            email: "demo@example.com".into(),
            expires_at: 0,
        };
        assert_eq!(
            service::default_label(None, &oauth).unwrap(),
            "demo@example.com"
        );
        assert_eq!(
            service::default_label(None, &key("synthetic-key-ABCD")).unwrap(),
            "API key ****ABCD"
        );
        assert_eq!(
            service::default_label(Some(" Work "), &oauth).unwrap(),
            "Work"
        );
        assert_eq!(
            service::default_label(Some(" Work "), &key("synthetic-key-ABCD")).unwrap(),
            "Work"
        );
        assert!(service::default_label(Some(" "), &oauth).is_err());
    }
    #[test]
    fn short_and_non_ascii_keys_are_fully_masked() {
        for token in ["abcd", "12345678", "ééééééééé", "secret\nvalue"] {
            assert_eq!(
                service::default_label(None, &key(token)).unwrap(),
                "API key ****"
            );
        }
    }
}

#[cfg(test)]
mod catalog_setting_tests {
    use super::*;
    #[test]
    fn settings_are_allowlisted_and_required_before_key_input() {
        let context = crate::providers::http::fixture::context();
        for definition in crate::providers::catalog::definitions() {
            let provider = Provider::Catalog(definition.id);
            assert!(matches!(
                parse_settings(provider, &["unknown=never-echo-this".into()], &context),
                Err(AccountError::Settings)
            ));
            let args: Vec<_> = definition
                .settings
                .iter()
                .map(|s| format!("{}=example-value", s.name))
                .collect();
            let parsed = parse_settings(provider, &args, &context).unwrap();
            assert_eq!(parsed.len(), definition.settings.len());
            if definition.settings.iter().any(|s| s.required) {
                assert!(matches!(
                    parse_settings(provider, &[], &context),
                    Err(AccountError::Settings)
                ));
            }
            if let Some(setting) = definition.settings.first() {
                assert!(
                    parse_settings(
                        provider,
                        &[
                            format!("{}=first", setting.name),
                            format!("{}=second", setting.name)
                        ],
                        &context
                    )
                    .is_err()
                );
            }
        }
    }
}
