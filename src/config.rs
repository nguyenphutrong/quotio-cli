use crate::cli::Provider;
use clap::ValueEnum;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read config file")]
    Read,
    #[error(
        "invalid TOML config at line {line}, column {column}; expected enabled_providers = [\"provider-id\"]"
    )]
    Parse { line: usize, column: usize },
    #[error("config contains an unsupported provider; run quotio providers")]
    Unsupported,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub enabled_providers: Vec<String>,
    /// Maximum cache age in seconds; zero refreshes every time.
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_seconds: u64,
}
fn default_cache_ttl() -> u64 {
    300
}
impl Default for Config {
    fn default() -> Self {
        Self {
            enabled_providers: vec![],
            cache_ttl_seconds: default_cache_ttl(),
        }
    }
}
impl Config {
    pub fn default_path() -> Option<PathBuf> {
        directories::ProjectDirs::from("", "", "quotio")
            .map(|dirs| dirs.config_dir().join("config.toml"))
    }
    pub fn load(explicit: Option<&Path>) -> Result<Self, ConfigError> {
        let path = explicit.map(Path::to_path_buf).or_else(Self::default_path);
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let input = match std::fs::read_to_string(path) {
            Ok(input) => input,
            Err(error) if explicit.is_none() && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(_) => return Err(ConfigError::Read),
        };
        Self::parse(&input)
    }
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        toml::from_str(input).map_err(|error: toml::de::Error| {
            let prefix = &input[..error.span().map(|span| span.start).unwrap_or(0)];
            ConfigError::Parse {
                line: prefix.bytes().filter(|byte| *byte == b'\n').count() + 1,
                column: prefix.rsplit('\n').next().unwrap_or("").chars().count() + 1,
            }
        })
    }
    pub fn providers(&self) -> Result<Vec<Provider>, ConfigError> {
        let mut providers = Vec::new();
        for id in &self.enabled_providers {
            let provider = Provider::from_str(id, false).map_err(|_| ConfigError::Unsupported)?;
            if !providers.contains(&provider) {
                providers.push(provider);
            }
        }
        Ok(providers)
    }
}
