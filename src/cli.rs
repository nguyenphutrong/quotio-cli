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
