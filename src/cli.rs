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
    /// Add, select, list or remove accounts managed by Quotio
    Accounts(AccountsArgs),
    /// Collect quota for selected or configured providers
    Usage(UsageArgs),
}
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum Format {
    #[default]
    Text,
    Json,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
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
    /// Use environment/local CLI sources without reading saved accounts
    #[arg(long)]
    pub no_saved_accounts: bool,
}

impl Provider {
    pub fn description(self) -> &'static str {
        match self {
            Self::Mock => "Deterministic demo data; no live requests",
            Self::Codex => "ChatGPT quota via saved OAuth or installed Codex CLI",
            Self::Amp => "Quota and balances via saved API key or installed Amp CLI",
            Self::Antigravity => "Google quota API; existing Antigravity OAuth token",
            Self::Factory => "Factory Droid quota via saved API key or FACTORY_API_KEY",
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

#[derive(Debug, Args)]
pub struct AccountsArgs {
    #[command(subcommand)]
    pub command: AccountCommand,
}
#[derive(Debug, Subcommand)]
pub enum AccountCommand {
    /// Validate and save a new account in the OS credential store
    Add {
        #[arg(long, value_enum)]
        provider: Provider,
        #[arg(long)]
        label: String,
        /// Read an Amp or Factory API key from a pipe; never put secrets in arguments
        #[arg(long)]
        token_stdin: bool,
        /// Print the Codex sign-in URL without opening a browser
        #[arg(long)]
        no_browser: bool,
        #[arg(long,value_parser=["global","eu"])]
        region: Option<String>,
        #[arg(long)]
        organization: Option<String>,
    },
    /// List saved account metadata without credentials
    List {
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
    /// Select the active account for its provider
    Use { id: String },
    /// Remove a Quotio-managed account; other apps remain signed in
    Remove { id: String },
}
