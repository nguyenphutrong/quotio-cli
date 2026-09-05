use super::{AccountError, Credential, random_string};
use crate::providers::{ProviderContext, http};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::digest::{SHA256, digest};
use serde::Deserialize;
use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const REDIRECT: &str = "http://localhost:1455/auth/callback";
#[derive(Deserialize)]
struct Tokens {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    expires_in: i64,
}
fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, verifier.as_bytes()).as_ref())
}
fn claims(token: &str) -> Result<Value, AccountError> {
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AccountError::OAuth);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AccountError::OAuth)?;
    serde_json::from_slice(&bytes).map_err(|_| AccountError::OAuth)
}
fn credential(
    tokens: Tokens,
    nonce: Option<&str>,
    previous: Option<&Credential>,
    now: i64,
) -> Result<Credential, AccountError> {
    if tokens.access_token.is_empty() || tokens.expires_in <= 0 {
        return Err(AccountError::OAuth);
    }
    let old = match previous {
        Some(Credential::CodexOAuth {
            refresh_token,
            id_token,
            account_id,
            email,
            ..
        }) => Some((refresh_token, id_token, account_id, email)),
        _ => None,
    };
    let id_token = tokens
        .id_token
        .or_else(|| old.map(|v| v.1.clone()))
        .ok_or(AccountError::OAuth)?;
    // Identity is read only from the response of the fixed TLS token endpoint.
    let claims = claims(&id_token)?;
    let audience = claims.get("aud").is_some_and(|v| {
        v.as_str() == Some(CLIENT_ID)
            || v.as_array()
                .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(CLIENT_ID)))
    });
    if claims.get("iss").and_then(Value::as_str) != Some("https://auth.openai.com") || !audience {
        return Err(AccountError::OAuth);
    }
    if let Some(nonce) = nonce
        && (claims.get("nonce").and_then(Value::as_str) != Some(nonce)
            || claims
                .get("exp")
                .and_then(Value::as_i64)
                .is_none_or(|e| e <= now))
    {
        return Err(AccountError::OAuth);
    }
    let email = claims
        .get("email")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(AccountError::OAuth)?
        .to_owned();
    let account_id = claims
        .pointer("/https:~1~1api.openai.com~1auth/chatgpt_account_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(AccountError::OAuth)?
        .to_owned();
    if old.is_some_and(|v| *v.2 != account_id || *v.3 != email) {
        return Err(AccountError::OAuth);
    }
    let refresh_token = tokens
        .refresh_token
        .or_else(|| old.map(|v| v.0.clone()))
        .filter(|s| !s.is_empty())
        .ok_or(AccountError::OAuth)?;
    Ok(Credential::CodexOAuth {
        access_token: tokens.access_token,
        refresh_token,
        id_token,
        account_id,
        email,
        expires_at: now
            .checked_add(tokens.expires_in)
            .ok_or(AccountError::OAuth)?,
    })
}
fn callback_code(target: &str, state: &str) -> Result<String, AccountError> {
    let url = reqwest::Url::parse(&format!("http://localhost{target}"))
        .map_err(|_| AccountError::OAuth)?;
    if url.path() != "/auth/callback" {
        return Err(AccountError::OAuth);
    }
    let pairs: Vec<_> = url.query_pairs().collect();
    let states: Vec<_> = pairs.iter().filter(|(k, _)| k == "state").collect();
    let codes: Vec<_> = pairs.iter().filter(|(k, _)| k == "code").collect();
    if states.len() != 1
        || states[0].1 != state
        || codes.len() != 1
        || codes[0].1.is_empty()
        || pairs.iter().any(|(k, _)| k == "error")
    {
        return Err(AccountError::OAuth);
    }
    Ok(codes[0].1.to_string())
}
async fn callback(listener: TcpListener, state: &str) -> Result<String, AccountError> {
    loop {
        let (socket, peer) = listener.accept().await.map_err(|_| AccountError::OAuth)?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let mut reader = BufReader::new(socket);
        let mut bytes = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            (&mut reader).take(8193).read_until(b'\n', &mut bytes),
        )
        .await
        .map_err(|_| AccountError::OAuth)?
        .map_err(|_| AccountError::OAuth)?;
        if bytes.len() > 8192 {
            return Err(AccountError::OAuth);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| AccountError::OAuth)?;
        let fields: Vec<_> = text.split_whitespace().collect();
        if fields.len() != 3 || fields[0] != "GET" || !fields[1].starts_with("/auth/callback?") {
            let _ = reader
                .get_mut()
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            continue;
        }
        let result = callback_code(fields[1], state);
        let body = if result.is_ok() {
            "Callback received. Return to Quotio."
        } else {
            "Login callback rejected. Return to Quotio."
        };
        let status = if result.is_ok() {
            "200 OK"
        } else {
            "400 Bad Request"
        };
        let _=reader.get_mut().write_all(format!("HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await;
        return result;
    }
}
pub async fn login(
    context: &ProviderContext,
    open_browser: bool,
) -> Result<Credential, AccountError> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 1455))
        .await
        .map_err(|_| AccountError::CallbackPort)?;
    let state = random_string()?;
    let verifier = random_string()?;
    let nonce = random_string()?;
    let mut url = reqwest::Url::parse("https://auth.openai.com/oauth/authorize")
        .map_err(|_| AccountError::OAuth)?;
    url.query_pairs_mut().extend_pairs([
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT),
        ("response_type", "code"),
        ("scope", "openid profile email offline_access"),
        ("state", &state),
        ("nonce", &nonce),
        ("code_challenge", &challenge(&verifier)),
        ("code_challenge_method", "S256"),
        ("codex_cli_simplified_flow", "true"),
        ("id_token_add_organizations", "true"),
        ("originator", "codex_cli_rs"),
    ]);
    eprintln!("Open this URL to sign in to Codex:\n{url}");
    if open_browser {
        #[cfg(target_os = "macos")]
        {
            let _ = tokio::process::Command::new("/usr/bin/open")
                .arg(url.as_str())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .status()
                .await;
        }
    }
    let code = callback(listener, &state).await?;
    let tokens: Tokens = http::json(
        context.http.post(TOKEN_URL).form(&[
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT_ID),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", &verifier),
        ]),
        context.clock.now(),
    )
    .await?;
    credential(
        tokens,
        Some(&nonce),
        None,
        context.clock.now().unix_timestamp(),
    )
}
pub async fn refresh(
    context: &ProviderContext,
    previous: &Credential,
) -> Result<Credential, AccountError> {
    refresh_at(context, previous, TOKEN_URL).await
}
async fn refresh_at(
    context: &ProviderContext,
    previous: &Credential,
    endpoint: &str,
) -> Result<Credential, AccountError> {
    let Credential::CodexOAuth { refresh_token, .. } = previous else {
        return Err(AccountError::Unsupported);
    };
    let tokens: Tokens = http::json(
        context.http.post(endpoint).form(&[
            ("grant_type", "refresh_token"),
            ("client_id", CLIENT_ID),
            ("refresh_token", refresh_token),
        ]),
        context.clock.now(),
    )
    .await?;
    credential(
        tokens,
        None,
        Some(previous),
        context.clock.now().unix_timestamp(),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn id_token(account: &str) -> String {
        format!("e30.{}.signature",URL_SAFE_NO_PAD.encode(json!({"iss":"https://auth.openai.com","aud":CLIENT_ID,"nonce":"nonce","exp":10000,"email":"demo@example.com","https://api.openai.com/auth":{"chatgpt_account_id":account}}).to_string()))
    }
    #[test]
    fn pkce_and_callback_security() {
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(
            callback_code("/auth/callback?state=s&code=c", "s").unwrap(),
            "c"
        );
        for target in [
            "/auth/callback?state=bad&code=c",
            "/auth/callback?state=s&state=s&code=c",
            "/auth/callback?state=s&error=denied",
            "/other?state=s&code=c",
        ] {
            assert!(callback_code(target, "s").is_err());
        }
    }
    #[tokio::test]
    async fn refresh_rotates_tokens_and_rejects_account_changes() {
        let old = Credential::CodexOAuth {
            access_token: "old".into(),
            refresh_token: "old-refresh".into(),
            id_token: id_token("a"),
            account_id: "a".into(),
            email: "demo@example.com".into(),
            expires_at: 0,
        };
        for account in ["a", "different"] {
            let (url,task)=http::fixture::server(vec![json!({"access_token":"new","refresh_token":"rotated","id_token":id_token(account),"expires_in":3600})]).await;
            let result = refresh_at(&http::fixture::context(), &old, &url).await;
            assert_eq!(result.is_ok(), account == "a");
            if let Ok(Credential::CodexOAuth { refresh_token, .. }) = result {
                assert_eq!(refresh_token, "rotated");
            }
            let requests = task.await.unwrap();
            assert!(requests[0].contains("grant_type=refresh_token"));
            assert!(requests[0].contains("old-refresh"));
        }
    }
    #[tokio::test]
    async fn callback_uses_loopback_and_rejects_wrong_state() {
        for state in ["expected", "wrong"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(async move { callback(listener, "expected").await });
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            stream.write_all(format!("GET /auth/callback?state={state}&code=synthetic-code HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes()).await.unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            let result = task.await.unwrap();
            assert_eq!(result.is_ok(), state == "expected");
            assert!(!response.contains("synthetic-code"));
        }
    }
    #[test]
    fn login_requires_matching_nonce_and_identity() {
        let tokens = || Tokens {
            access_token: "access".into(),
            refresh_token: Some("refresh".into()),
            id_token: Some(id_token("account")),
            expires_in: 3600,
        };
        assert!(credential(tokens(), Some("nonce"), None, 0).is_ok());
        assert!(credential(tokens(), Some("different"), None, 0).is_err());
        assert!(credential(tokens(), Some("nonce"), None, 20000).is_err());
    }
}
