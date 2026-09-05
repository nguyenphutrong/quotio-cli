use super::{AccountError, Credential, service, vault::Vault};
use crate::{
    cli::{AccountCommand, Format, Provider},
    providers::ProviderContext,
};
use clap::ValueEnum;
use std::io::IsTerminal;

pub async fn run(
    command: AccountCommand,
    context: &ProviderContext,
) -> Result<String, AccountError> {
    if !cfg!(target_os = "macos") {
        return Err(AccountError::Unsupported);
    }
    let vault = Vault::system()?;
    match command {
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
            let label = label.trim().to_owned();
            if label.is_empty() || label.chars().count() > 80 || label.chars().any(char::is_control)
            {
                return Err(AccountError::Label);
            }
            if provider != Provider::Factory && (region.is_some() || organization.is_some()) {
                return Err(AccountError::Unsupported);
            }
            let credential = match provider {
                Provider::Codex if !token_stdin => {
                    super::oauth::login(context, !no_browser).await?
                }
                Provider::Amp | Provider::Factory if token_stdin && !no_browser => {
                    if std::io::stdin().is_terminal() {
                        return Err(AccountError::Input);
                    }
                    let token = super::input::read_stdin().await?;
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
            let id = service::add(vault, provider, label, credential, usage.account.id).await?;
            Ok(format!("Account validated and saved: {id}\n"))
        }
    }
}
