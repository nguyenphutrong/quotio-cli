pub mod vault;
use crate::{cli::Provider, error::ProviderError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AccountError {
    #[error("account storage is unavailable or access was denied")]
    Storage,
    #[error("saved account data is invalid; no changes were made")]
    Corrupt,
    #[error("another account operation is in progress; retry shortly")]
    Busy,
    #[error("account not found")]
    NotFound,
    #[error("this provider already has that label or account identity")]
    Duplicate,
    #[error("label must be 1–80 characters without control characters")]
    Label,
    #[error("this provider does not support the selected login method")]
    Unsupported,
    #[error("credential input is empty, too large, or invalid")]
    Input,
    #[error("credential validation failed: {0}")]
    Provider(#[from] ProviderError),
    #[error("login timed out or was cancelled")]
    Cancelled,
    #[error("OAuth callback or token response is invalid")]
    OAuth,
}

// These values are serialized only inside the OS-protected vault, never reports.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Credential {
    ApiKey {
        token: String,
        region: Option<String>,
        organization: Option<String>,
    },
    CodexOAuth {
        access_token: String,
        refresh_token: String,
        id_token: String,
        account_id: String,
        email: String,
        expires_at: i64,
    },
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub provider: Provider,
    pub label: String,
    pub identity: String,
    pub active: bool,
    pub credential: Credential,
}
#[derive(Serialize)]
pub struct AccountInfo<'a> {
    pub id: &'a str,
    pub provider: Provider,
    pub label: &'a str,
    pub active: bool,
}
impl Account {
    pub fn info(&self) -> AccountInfo<'_> {
        AccountInfo {
            id: &self.id,
            provider: self.provider,
            label: &self.label,
            active: self.active,
        }
    }
}
#[derive(Default, Serialize, Deserialize)]
pub struct Document {
    pub version: u8,
    pub accounts: Vec<Account>,
}
impl Document {
    pub fn empty() -> Self {
        Self {
            version: 1,
            accounts: vec![],
        }
    }
    pub fn add(
        &mut self,
        provider: Provider,
        label: &str,
        identity: String,
        credential: Credential,
    ) -> Result<String, AccountError> {
        let label = label.trim();
        if label.is_empty() || label.chars().count() > 80 || label.chars().any(char::is_control) {
            return Err(AccountError::Label);
        }
        if self
            .accounts
            .iter()
            .any(|a| a.provider == provider && (a.label == label || a.identity == identity))
        {
            return Err(AccountError::Duplicate);
        }
        let id = random_string()?;
        let active = !self
            .accounts
            .iter()
            .any(|a| a.provider == provider && a.active);
        self.accounts.push(Account {
            id: id.clone(),
            provider,
            label: label.into(),
            identity,
            active,
            credential,
        });
        Ok(id)
    }
    pub fn select(&mut self, id: &str) -> Result<(), AccountError> {
        let provider = self
            .accounts
            .iter()
            .find(|a| a.id == id)
            .ok_or(AccountError::NotFound)?
            .provider;
        for a in &mut self.accounts {
            if a.provider == provider {
                a.active = a.id == id;
            }
        }
        Ok(())
    }
    pub fn remove(&mut self, id: &str) -> Result<(), AccountError> {
        let index = self
            .accounts
            .iter()
            .position(|a| a.id == id)
            .ok_or(AccountError::NotFound)?;
        let removed = self.accounts.remove(index);
        if removed.active
            && let Some(next) = self
                .accounts
                .iter_mut()
                .find(|a| a.provider == removed.provider)
        {
            next.active = true;
        }
        Ok(())
    }
}
pub(crate) fn random_string() -> Result<String, AccountError> {
    use base64::Engine;
    use ring::rand::SecureRandom;
    let mut bytes = [0; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| AccountError::Storage)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}
