use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "quotio", version, about = "Check provider quota and usage", color = clap::ColorChoice::Never)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}
#[derive(Debug, Subcommand)]
pub enum Command {
    /// List supported providers
    Providers,
    /// Collect quota for selected or configured providers
    Usage(UsageArgs),
}
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum Format {
    #[default]
    Text,
    Json,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Provider {
    Mock,
    Codex,
    Amp,
    Antigravity,
    #[value(alias = "droid", alias = "factory-droid")]
    Factory,
}
#[derive(Debug, Args)]
pub struct UsageArgs {
    /// Select a provider; repeat to select more than one
    #[arg(long, value_enum)]
    pub provider: Vec<Provider>,
    #[arg(long, value_enum, default_value = "text")]
    pub format: Format,
    /// Total seconds allowed for each provider, including retries
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub timeout: u64,
    /// Read this TOML config instead of the platform default
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Disable terminal color (output is currently always plain)
    #[arg(long)]
    pub no_color: bool,
    /// Write diagnostic logs to stderr
    #[arg(long)]
    pub verbose: bool,
}

impl Provider {
    pub fn description(self) -> &'static str {
        match self {
            Self::Mock => "Deterministic demo data; no live requests",
            Self::Codex => "ChatGPT quota through installed Codex CLI",
            Self::Amp => "Quota and balances through installed Amp CLI",
            Self::Antigravity => "Google quota API; existing Antigravity OAuth token",
            Self::Factory => "Factory Droid billing limits API; FACTORY_API_KEY",
        }
    }
    pub fn adapter(self) -> std::sync::Arc<dyn crate::providers::ProviderAdapter> {
        use crate::providers::{
            amp::AmpProvider, antigravity::AntigravityProvider, codex::CodexProvider,
            factory::FactoryProvider, mock::MockProvider,
        };
        match self {
            Self::Mock => std::sync::Arc::new(MockProvider),
            Self::Codex => std::sync::Arc::new(CodexProvider::default()),
            Self::Amp => std::sync::Arc::new(AmpProvider::default()),
            Self::Antigravity => std::sync::Arc::new(AntigravityProvider::default()),
            Self::Factory => std::sync::Arc::new(FactoryProvider),
        }
    }
}
