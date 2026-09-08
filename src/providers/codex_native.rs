//! Read-only Codex auth.json loading. Refresh credentials never leave the owning tool.
use crate::accounts::{AccountError, Credential};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use std::{io::Read, path::Path};

pub(crate) fn load(path: &Path) -> Result<Credential, AccountError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AccountError::NotFound
        } else {
            AccountError::Input
        }
    })?;
    let metadata = file.metadata().map_err(|_| AccountError::Input)?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(AccountError::Corrupt);
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AccountError::Input)?;
    parse(&bytes)
}
fn text(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str).filter(|value| {
        !value.trim().is_empty() && value.len() <= 16_384 && !value.chars().any(char::is_control)
    })
}
fn parse(bytes: &[u8]) -> Result<Credential, AccountError> {
    if bytes.len() > 1024 * 1024 {
        return Err(AccountError::Corrupt);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| AccountError::Corrupt)?;
    let tokens = value.get("tokens").ok_or(AccountError::Input)?;
    let access_token = text(tokens.get("access_token")).ok_or(AccountError::Input)?;
    // These claims supply display/account routing metadata, not proof of authentication.
    let claims: Option<Value> = text(tokens.get("id_token")).and_then(|token| {
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        URL_SAFE_NO_PAD
            .decode(parts[1])
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    });
    let account_id = text(tokens.get("account_id"))
        .or_else(|| {
            text(
                claims
                    .as_ref()?
                    .get("https://api.openai.com/auth")?
                    .get("chatgpt_account_id"),
            )
        })
        .ok_or(AccountError::Input)?;
    let email = claims
        .as_ref()
        .and_then(|claims| text(claims.get("email")))
        .filter(|email| crate::accounts::validate_label(email).is_ok())
        .unwrap_or("Local Codex account");
    Ok(Credential::CodexOAuth {
        access_token: access_token.into(),
        account_id: account_id.into(),
        email: email.into(),
        // Only the outer owned CodexOAuth variant can enter managed refresh.
        refresh_token: String::new(),
        id_token: String::new(),
        expires_at: i64::MAX,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_shape_uses_claims_without_retaining_refresh_credentials() {
        let claims = URL_SAFE_NO_PAD.encode(br#"{"email":"fixture@example.test","https://api.openai.com/auth":{"chatgpt_account_id":"account-fixture"}}"#);
        let bytes = serde_json::to_vec(&serde_json::json!({"tokens": {
            "access_token":"fixture-access", "id_token":format!("e30.{claims}.signature"),
            "refresh_token":"must-not-copy"
        }}))
        .unwrap();
        let credential = parse(&bytes).unwrap();
        assert!(
            matches!(&credential, Credential::CodexOAuth { account_id, email, refresh_token, id_token, .. }
            if account_id == "account-fixture" && email == "fixture@example.test" && refresh_token.is_empty() && id_token.is_empty())
        );
        assert!(
            !serde_json::to_string(&credential)
                .unwrap()
                .contains("must-not-copy")
        );
        for value in [
            serde_json::json!({"access_token":"legacy"}),
            serde_json::json!({"tokens":{"access_token":"key\n", "account_id":"id"}}),
            serde_json::json!({"tokens":{"access_token":"key", "account_id":"id\r"}}),
            serde_json::json!({"tokens":{"access_token":"key"}}),
        ] {
            assert!(parse(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }
}
