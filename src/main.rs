use clap::{Parser, ValueEnum};
use quotio::{
    cli::{Cli, Command, Format, Provider},
    config::Config,
    fetch::{Cancellation, CollectRequest, Collector},
    output,
    providers::{EnvironmentCredentials, ProviderContext, SystemClock},
};
use std::{
    io::{self, Write},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};
use tracing_subscriber::{filter::Targets, layer::SubscriberExt, util::SubscriberInitExt};

fn account_timeout(command: &quotio::cli::AccountCommand) -> Option<Duration> {
    if matches!(
        command,
        quotio::cli::AccountCommand::Add {
            provider: Provider::Catalog("claude"),
            token_stdin: false,
            ..
        }
    ) {
        // Manual OAuth bounds input and exchange separately. Once claimed, a
        // durable credential commit must not be dropped at the input deadline.
        None
    } else if matches!(
        command,
        quotio::cli::AccountCommand::Add {
            provider: Provider::Catalog("copilot"),
            ..
        }
    ) {
        // Device expiry is at most one hour, plus startup and persistence time.
        Some(Duration::from_secs(3720))
    } else {
        Some(Duration::from_secs(180))
    }
}

async fn within_account_deadline<T>(
    timeout: Option<Duration>,
    operation: impl std::future::Future<Output = Result<T, quotio::accounts::AccountError>>,
) -> Result<T, quotio::accounts::AccountError> {
    match timeout {
        Some(timeout) => tokio::time::timeout(timeout, operation)
            .await
            .unwrap_or(Err(quotio::accounts::AccountError::Cancelled)),
        None => operation.await,
    }
}

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("Could not initialize runtime.");
            return ExitCode::from(3);
        }
    };
    let result = runtime.block_on(run());
    // Native Keychain calls cannot be cancelled by dropping a Rust future.
    // Do not wait for a blocked native call after the command deadline has expired.
    runtime.shutdown_background();
    result
}
async fn run() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            return if error.print().is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(3)
            };
        }
        Err(_) => {
            // Clap's default diagnostics echo input, which may accidentally be a secret.
            eprintln!("Invalid arguments. Run quotio --help or quotio usage --help.");
            return ExitCode::from(2);
        }
    };
    let (text, code) = match cli.command {
        Command::MigrationInspect {
            piv_envelope,
            piv_fingerprint,
            stage_dir,
        } => {
            let result = (|| {
                let plan = quotio::accounts::staging::assess(&piv_envelope, &piv_fingerprint)?;
                let receipt_id = stage_dir
                    .as_deref()
                    .map(|dir| quotio::accounts::staging::stage(&plan, dir))
                    .transpose()?;
                Ok::<_, quotio::accounts::staging::StagingError>(serde_json::json!({
                    "plan": plan,
                    "receipt_id": receipt_id,
                    "credentials_staged": false,
                    "accounts_imported": 0
                }))
            })();
            match result {
                // Assessment completed, but migration is always blocked in this release.
                Ok(report) => (format!("{report}\n"), 2),
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::from(2);
                }
            }
        }
        Command::Serve(args) => {
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(io::stderr),
                )
                .with(Targets::new().with_target("quotio", tracing::Level::INFO))
                .init();
            return match quotio::server::run(args).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::from(error.exit_code())
                }
            };
        }
        Command::Providers => (
            Provider::value_variants()
                .iter()
                .map(|provider| {
                    let mut line = format!("{}  {}\n", provider.id(), provider.description());
                    if let Some(definition) = provider.catalog() {
                        line.push_str(&format!("  Credential: {}\n", definition.key_env));
                        for setting in definition.settings {
                            line.push_str(&format!(
                                "  --setting {}=VALUE  [{}; env {}]\n",
                                setting.name,
                                if setting.required {
                                    "required"
                                } else {
                                    "optional"
                                },
                                setting.env
                            ));
                        }
                    }
                    line
                })
                .collect(),
            0,
        ),
        Command::Accounts(args) => {
            let http = match reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
            {
                Ok(h) => h,
                Err(_) => {
                    eprintln!("Could not initialize HTTP client.");
                    return ExitCode::from(3);
                }
            };
            let context = ProviderContext {
                http,
                clock: Arc::new(SystemClock),
                credentials: Arc::new(EnvironmentCredentials),
            };
            let timeout = account_timeout(&args.command);
            let result = tokio::select! {
                // Register Ctrl-C before an account command can disable terminal echo.
                biased;
                _=tokio::signal::ctrl_c()=>Err(quotio::accounts::AccountError::Cancelled),
                result=within_account_deadline(timeout,quotio::accounts::command::run(args.command,&context))=>result,
            };
            match result {
                Ok(text) => (text, 0),
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::from(2);
                }
            }
        }
        Command::Usage(args) => {
            let level = if args.verbose {
                tracing::Level::DEBUG
            } else {
                tracing::Level::WARN
            };
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(io::stderr),
                )
                .with(Targets::new().with_target("quotio", level))
                .init();
            let config = match Config::load(args.config.as_deref()) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::from(2);
                }
            };
            let configured = match config.providers() {
                Ok(providers) => providers,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::from(2);
                }
            };
            let selected = if args.provider.is_empty() {
                configured
            } else {
                args.provider
            };
            let mut unique = Vec::new();
            for provider in selected {
                if !unique.contains(&provider) {
                    unique.push(provider);
                }
            }
            let providers = tokio::select! {
                providers=quotio::accounts::service::adapters(unique, !args.no_saved_accounts, Duration::from_secs(args.timeout), args.account.as_deref())=>providers,
                _=tokio::signal::ctrl_c()=>{eprintln!("Account discovery cancelled.");return ExitCode::from(3)},
            };
            let providers = match providers {
                Ok(providers) => providers,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::from(2);
                }
            };
            if providers.is_empty() {
                eprintln!(
                    "No providers selected. Use --provider mock or set enabled_providers in config."
                );
            }
            tracing::debug!(count = providers.len(), "collecting provider usage");
            let http = match reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
            {
                Ok(client) => client,
                Err(_) => {
                    eprintln!("Could not initialize HTTP client.");
                    return ExitCode::from(3);
                }
            };
            let collector = Collector {
                context: ProviderContext {
                    http,
                    clock: Arc::new(SystemClock),
                    credentials: Arc::new(EnvironmentCredentials),
                },
            };
            let cancellation = Cancellation::default();
            let request = CollectRequest {
                providers,
                timeout: Duration::from_secs(args.timeout),
                cancellation: cancellation.clone(),
            };
            let cache =
                quotio::cache::UsageCache::platform(Duration::from_secs(config.cache_ttl_seconds));
            let collection = cache.collect(&collector, request, args.force);
            tokio::pin!(collection);
            let report = tokio::select! {
                report = &mut collection => report,
                signal = tokio::signal::ctrl_c() => {
                    if signal.is_err() { eprintln!("Could not listen for Ctrl-C."); }
                    cancellation.cancel();
                    collection.await
                }
            };
            let code = report.exit_code();
            for failure in &report.failures {
                eprintln!("{}", output::text::failure(failure));
            }
            let text = match args.format {
                Format::Text => output::text::render(&report),
                Format::Json => match output::json::render(&report) {
                    Ok(json) => format!("{json}\n"),
                    Err(_) => {
                        eprintln!("Could not encode usage report.");
                        return ExitCode::from(3);
                    }
                },
            };
            (text, code)
        }
    };
    if io::stdout().lock().write_all(text.as_bytes()).is_err() {
        eprintln!("Could not write output.");
        return ExitCode::from(3);
    }
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn copilot_terminal_deadline_does_not_truncate_device_expiry() {
        for (provider, expected) in [("copilot", Some(3720)), ("codex", Some(180)), ("claude", None)] {
            let cli =
                Cli::try_parse_from(["quotio", "accounts", "add", "--provider", provider]).unwrap();
            let Command::Accounts(args) = cli.command else {
                panic!("account command");
            };
            assert_eq!(
                account_timeout(&args.command),
                expected.map(Duration::from_secs)
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn late_claude_input_keeps_exchange_and_commit_alive() {
        let cli = Cli::try_parse_from([
            "quotio", "accounts", "add", "--provider", "claude",
        ]).unwrap();
        let Command::Accounts(args) = cli.command else { panic!("account command") };
        let start = tokio::time::Instant::now();
        let result = within_account_deadline(account_timeout(&args.command), async {
            tokio::time::timeout(Duration::from_secs(180), async {
                tokio::time::sleep(Duration::from_secs(179)).await;
            }).await.unwrap();
            tokio::time::timeout(Duration::from_secs(30), async {
                tokio::time::sleep(Duration::from_secs(20)).await;
            }).await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok("persisted")
        }).await;
        assert_eq!(result.unwrap(), "persisted");
        assert_eq!(start.elapsed(), Duration::from_secs(204));
    }
}
