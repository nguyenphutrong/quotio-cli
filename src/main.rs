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

#[tokio::main]
async fn main() -> ExitCode {
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
        Command::Providers => (
            Provider::value_variants()
                .iter()
                .map(|provider| {
                    format!(
                        "{}  {}\n",
                        provider
                            .to_possible_value()
                            .expect("provider value")
                            .get_name(),
                        provider.description()
                    )
                })
                .collect(),
            0,
        ),
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
            let providers: Vec<_> = unique.into_iter().map(Provider::adapter).collect();
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
            let collection = collector.collect(request);
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
                eprintln!("{}: {}", failure.provider.0, failure.code);
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
