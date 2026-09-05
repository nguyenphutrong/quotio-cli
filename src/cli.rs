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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    Mock,
    Codex,
    Amp,
    Antigravity,
    Synthetic,
    OpenRouter,
    Zai,
    MiniMax,
    Factory,
    Catalog(&'static str),
}
impl Provider {
    pub fn id(self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Codex => "codex",
            Self::Amp => "amp",
            Self::Antigravity => "antigravity",
            Self::Synthetic => "synthetic",
            Self::OpenRouter => "openrouter",
            Self::Zai => "zai",
            Self::MiniMax => "minimax",
            Self::Factory => "factory",
            Self::Catalog(id) => id,
        }
    }
    pub fn catalog(self) -> Option<&'static crate::providers::catalog::Definition> {
        match self {
            Self::Catalog(id) => crate::providers::catalog::find(id),
            _ => None,
        }
    }
}
impl ValueEnum for Provider {
    fn value_variants<'a>() -> &'a [Self] {
        static VALUES: std::sync::OnceLock<Vec<Provider>> = std::sync::OnceLock::new();
        VALUES.get_or_init(|| {
            let mut values = vec![
                Self::Mock,
                Self::Codex,
                Self::Amp,
                Self::Antigravity,
                Self::Synthetic,
                Self::OpenRouter,
                Self::Zai,
                Self::MiniMax,
                Self::Factory,
            ];
            let mut catalog: Vec<_> = crate::providers::catalog::definitions()
                .map(|d| Self::Catalog(d.id))
                .collect();
            catalog.sort_by_key(|p| p.id());
            values.extend(catalog);
            values
        })
    }
    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        let value = clap::builder::PossibleValue::new(self.id());
        Some(match self {
            Self::Zai => value.alias("glm"),
            Self::Factory => value.alias("droid").alias("factory-droid"),
            _ => value,
        })
    }
}
impl serde::Serialize for Provider {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.id())
    }
}
impl<'de> serde::Deserialize<'de> for Provider {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let id = String::deserialize(deserializer)?;
        Self::from_str(&id, false).map_err(|_| serde::de::Error::custom("unsupported provider"))
    }
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
    /// Select one saved account ID, or local; requires exactly one provider
    #[arg(long, requires = "provider", conflicts_with = "no_saved_accounts")]
    pub account: Option<String>,
}

impl Provider {
    pub fn key_api(self) -> Option<crate::providers::key_api::Kind> {
        use crate::providers::key_api::Kind;
        match self {
            Self::Synthetic => Some(Kind::Synthetic),
            Self::OpenRouter => Some(Kind::OpenRouter),
            Self::Zai => Some(Kind::Zai),
            Self::MiniMax => Some(Kind::MiniMax),
            _ => None,
        }
    }
    pub fn api_key_name(self) -> Option<&'static str> {
        match self {
            Self::Amp => Some("AMP_API_KEY"),
            Self::Factory => Some("FACTORY_API_KEY"),
            Self::Catalog(id) => crate::providers::catalog::find(id)
                .filter(|d| d.auth == crate::providers::catalog::AuthKind::ApiKey)
                .map(|d| d.key_env),
            other => other.key_api().map(|k| k.key()),
        }
    }
    pub fn supports_accounts(self) -> bool {
        self == Self::Codex || self.api_key_name().is_some()
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Catalog(id) => match crate::providers::catalog::find(id).map(|d| d.auth) {
                Some(crate::providers::catalog::AuthKind::ApiKey) => {
                    "Usage via API key and provider-specific settings"
                }
                _ => "Usage via native OAuth login or explicit access token",
            },
            Self::Synthetic => "Subscription, rolling and search quota via Synthetic API key",
            Self::OpenRouter => "Key spending limits and USD usage via OpenRouter API key",
            Self::Zai => "Coding Plan quota via Z.ai or BigModel API key",
            Self::MiniMax => "Token Plan quota via MiniMax subscription key",
            Self::Mock => "Deterministic demo data; no live requests",
            Self::Codex => "ChatGPT quota via saved OAuth or installed Codex CLI",
            Self::Amp => "Quota and balances via saved API key or installed Amp CLI",
            Self::Antigravity => "Google quota API; existing Antigravity OAuth token",
            Self::Factory => "Factory Droid quota via saved API key or FACTORY_API_KEY",
        }
    }
    pub fn adapter(self) -> std::sync::Arc<dyn crate::providers::ProviderAdapter> {
        if let Self::Catalog(id) = self {
            return std::sync::Arc::new(crate::providers::catalog::CatalogProvider(id));
        }
        if let Some(kind) = self.key_api() {
            return std::sync::Arc::new(crate::providers::key_api::KeyApiProvider(kind));
        }
        use crate::providers::{
            amp::AmpProvider, antigravity::AntigravityProvider, codex::CodexProvider,
            factory::FactoryProvider, mock::MockProvider,
        };
        match self {
            Self::Mock => std::sync::Arc::new(MockProvider),
            Self::Codex => std::sync::Arc::new(CodexProvider::default()),
            Self::Amp => std::sync::Arc::new(AmpProvider::default()),
            Self::Antigravity => std::sync::Arc::new(AntigravityProvider),
            Self::Factory => std::sync::Arc::new(FactoryProvider),
            Self::Synthetic | Self::OpenRouter | Self::Zai | Self::MiniMax | Self::Catalog(_) => {
                unreachable!("key API provider handled above")
            }
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
    /// Allow Keychain to ask for access to the local Antigravity login
    Authorize {
        #[arg(long, value_enum)]
        provider: Provider,
    },
    /// Validate and save a new account in the OS credential store
    Add {
        #[arg(long, value_enum)]
        provider: Provider,
        /// Override the default email or masked API-key label
        #[arg(long)]
        label: Option<String>,
        /// Read an API key from a pipe instead of the hidden terminal prompt
        #[arg(long)]
        token_stdin: bool,
        /// Print the Codex sign-in URL without opening a browser
        #[arg(long)]
        no_browser: bool,
        /// Factory: global/eu; Z.ai and MiniMax: global/cn
        #[arg(long,value_parser=["global","eu","cn"])]
        region: Option<String>,
        #[arg(long)]
        organization: Option<String>,
        /// Provider metadata such as project or region; repeat NAME=VALUE, never secrets
        #[arg(long = "setting", value_name = "NAME=VALUE")]
        settings: Vec<String>,
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
