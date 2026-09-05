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
        } => {
            if let Some(label) = &label {
                validate_label(label)?;
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
                    Credential::ApiKey {
                        token: token.into(),
                        region,
                        organization,
                    }
                }
                _ => return Err(AccountError::Unsupported),
            };
            let usage = service::validate(context, provider, &credential).await?;
            let label = resolve_label(label.as_deref(), &credential)?;
            let id = service::add(vault, provider, label, credential, usage.account.id).await?;
            Ok(format!("Account validated and saved: {id}\n"))
        }
    }
}

fn validate_label(label: &str) -> Result<String, AccountError> {
    let label = label.trim();
    if label.is_empty() || label.chars().count() > 80 || label.chars().any(char::is_control) {
        return Err(AccountError::Label);
    }
    Ok(label.to_owned())
}
fn resolve_label(explicit: Option<&str>, credential: &Credential) -> Result<String, AccountError> {
    if let Some(label) = explicit {
        return validate_label(label);
    }
    match credential {
        Credential::CodexOAuth { email, .. } => validate_label(email),
        Credential::ApiKey { token, .. } => {
            // Never reveal a short key in full or expose arbitrary Unicode/control text.
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
        assert_eq!(resolve_label(None, &oauth).unwrap(), "demo@example.com");
        assert_eq!(
            resolve_label(None, &key("synthetic-key-ABCD")).unwrap(),
            "API key ****ABCD"
        );
        assert_eq!(resolve_label(Some(" Work "), &oauth).unwrap(), "Work");
        assert_eq!(
            resolve_label(Some(" Work "), &key("synthetic-key-ABCD")).unwrap(),
            "Work"
        );
        assert!(resolve_label(Some(" "), &oauth).is_err());
    }
    #[test]
    fn short_and_non_ascii_keys_are_fully_masked() {
        for token in ["abcd", "12345678", "ééééééééé", "secret\nvalue"] {
            assert_eq!(resolve_label(None, &key(token)).unwrap(), "API key ****");
        }
    }
}
