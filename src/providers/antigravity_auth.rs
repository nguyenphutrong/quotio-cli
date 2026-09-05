use super::{ProviderContext, Secret, http};
use crate::error::ProviderError;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const MAX_CREDENTIAL_BYTES: usize = 1024 * 1024;
const REFRESH_URL: &str = "https://oauth2.googleapis.com/token";
const CACHE_SERVICE: &str = "dev.quotio.cli.antigravity";

#[derive(Clone, Deserialize)]
pub(crate) struct Credential {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expiry: Option<String>,
}
impl Credential {
    fn fingerprint(&self) -> String {
        let source = self.refresh_token.as_ref().or(self.access_token.as_ref());
        STANDARD.encode(ring::digest::digest(
            &ring::digest::SHA256,
            source.map_or(&[], |s| s.as_bytes()),
        ))
    }
    fn usable_token(&self, now: OffsetDateTime) -> Option<Secret> {
        if let Some(expiry) = &self.expiry {
            let expiry = OffsetDateTime::parse(expiry, &Rfc3339).ok()?;
            if expiry <= now + time::Duration::seconds(60) {
                return None;
            }
        }
        self.access_token.clone().map(Secret)
    }
}
#[derive(Deserialize, Serialize)]
pub(crate) struct CachedToken {
    fingerprint: String,
    access_token: String,
    expires_at: i64,
}
pub(crate) struct OAuthClient {
    id: String,
    secret: String,
}
pub(crate) trait Store: Send + Sync {
    fn credential(&self) -> Result<Credential, ProviderError>;
    fn cache(&self) -> Result<Option<CachedToken>, ProviderError>;
    fn save_cache(&self, cache: &CachedToken) -> Result<(), ProviderError>;
    fn clients(&self) -> Result<Vec<OAuthClient>, ProviderError>;
}
pub(crate) struct NativeStore;

pub(crate) async fn authorize() -> Result<(), ProviderError> {
    tokio::task::spawn_blocking(|| {
        #[cfg(target_os = "macos")]
        {
            let bytes =
                security_framework::passwords::get_generic_password("gemini", "antigravity")
                    .map_err(|_| ProviderError::LocalCredentialStorage)?;
            parse_credential(&bytes)?;
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(ProviderError::Unavailable)
        }
    })
    .await
    .map_err(|_| ProviderError::Internal)?
}

async fn keychain_task<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, ProviderError> + Send + 'static,
) -> Result<T, ProviderError> {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::task::spawn_blocking(operation),
    )
    .await
    .map_err(|_| ProviderError::LocalCredentialStorage)?
    .map_err(|_| ProviderError::Internal)?
}

async fn cache_task<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, ProviderError> + Send + 'static,
) -> Option<T> {
    match tokio::time::timeout(std::time::Duration::from_secs(1), keychain_task(operation)).await {
        Ok(Ok(value)) => Some(value),
        _ => {
            tracing::warn!("Antigravity token cache unavailable; continuing without cache");
            None
        }
    }
}

fn parse_credential(bytes: &[u8]) -> Result<Credential, ProviderError> {
    if bytes.len() > MAX_CREDENTIAL_BYTES {
        return Err(ProviderError::Authentication);
    }
    let raw = std::str::from_utf8(bytes)
        .map_err(|_| ProviderError::Authentication)?
        .trim();
    let decoded;
    let bytes = if let Some(encoded) = raw.strip_prefix("go-keyring-base64:") {
        decoded = STANDARD
            .decode(encoded)
            .map_err(|_| ProviderError::Authentication)?;
        decoded.as_slice()
    } else {
        raw.as_bytes()
    };
    let mut object: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ProviderError::Authentication)?;
    let token = object
        .get_mut("token")
        .map(serde_json::Value::take)
        .unwrap_or(object);
    let mut credential: Credential =
        serde_json::from_value(token).map_err(|_| ProviderError::Authentication)?;
    for field in [&mut credential.access_token, &mut credential.refresh_token] {
        *field = field
            .take()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());
    }
    if credential.access_token.is_none() && credential.refresh_token.is_none() {
        return Err(ProviderError::Authentication);
    }
    if credential
        .expiry
        .as_ref()
        .is_some_and(|expiry| OffsetDateTime::parse(expiry, &Rfc3339).is_err())
    {
        return Err(ProviderError::Authentication);
    }
    Ok(credential)
}

#[cfg(target_os = "macos")]
fn options(service: &str, account: &str) -> security_framework::passwords::PasswordOptions {
    use core_foundation::{base::TCFType, string::CFString};
    use security_framework_sys::item::kSecUseAuthenticationUI;
    unsafe extern "C" {
        static kSecUseAuthenticationUIFail: core_foundation::string::CFStringRef;
    }
    let mut options =
        security_framework::passwords::PasswordOptions::new_generic_password(service, account);
    #[allow(deprecated)]
    unsafe {
        options.query.push((
            CFString::wrap_under_get_rule(kSecUseAuthenticationUI),
            CFString::wrap_under_get_rule(kSecUseAuthenticationUIFail).into_CFType(),
        ));
    }
    options
}
fn read_password(service: &str, account: &str) -> Result<Option<Vec<u8>>, ProviderError> {
    #[cfg(target_os = "macos")]
    {
        match security_framework::passwords::generic_password(options(service, account)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.code() == -25300 => Ok(None),
            Err(_) => Err(ProviderError::CredentialStorage),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (service, account);
        Err(ProviderError::Unavailable)
    }
}
impl Store for NativeStore {
    fn credential(&self) -> Result<Credential, ProviderError> {
        parse_credential(
            &read_password("gemini", "antigravity")
                .map_err(|error| {
                    if error == ProviderError::Unavailable {
                        ProviderError::Authentication
                    } else {
                        ProviderError::LocalCredentialStorage
                    }
                })?
                .ok_or(ProviderError::Authentication)?,
        )
    }
    fn cache(&self) -> Result<Option<CachedToken>, ProviderError> {
        Ok(read_password(CACHE_SERVICE, "access-token")?
            .filter(|b| b.len() <= MAX_CREDENTIAL_BYTES)
            .and_then(|b| serde_json::from_slice(&b).ok()))
    }
    fn save_cache(&self, cache: &CachedToken) -> Result<(), ProviderError> {
        #[cfg(target_os = "macos")]
        {
            let bytes = serde_json::to_vec(cache).map_err(|_| ProviderError::Internal)?;
            security_framework::passwords::set_generic_password_options(
                &bytes,
                options(CACHE_SERVICE, "access-token"),
            )
            .map_err(|_| ProviderError::CredentialStorage)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = cache;
            Err(ProviderError::Unavailable)
        }
    }
    fn clients(&self) -> Result<Vec<OAuthClient>, ProviderError> {
        let mut roots = vec![std::path::PathBuf::from("/Applications/Antigravity.app")];
        if let Some(dirs) = directories::BaseDirs::new() {
            roots.push(dirs.home_dir().join("Applications/Antigravity.app"));
        }
        for root in roots {
            for relative in [
                "Contents/Resources/app/out/main.js",
                "Contents/Resources/bin/language_server",
                "Contents/Resources/app/extensions/antigravity/bin/language_server_macos_arm",
                "Contents/Resources/app/extensions/antigravity/bin/language_server_macos_x64",
            ] {
                if let Some(client) = read_client(&root.join(relative)) {
                    return Ok(client);
                }
            }
        }
        Err(ProviderError::Unavailable)
    }
}
fn read_client(path: &Path) -> Option<Vec<OAuthClient>> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    const MAX: u64 = 256 * 1024 * 1024;
    if !metadata.is_file() || metadata.len() > MAX {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX {
        return None;
    }
    parse_client(&bytes)
}
fn parse_client(bytes: &[u8]) -> Option<Vec<OAuthClient>> {
    let suffix = b".apps.googleusercontent.com";
    let mut ids = Vec::new();
    for (offset, _) in bytes
        .windows(suffix.len())
        .enumerate()
        .filter(|(_, s)| s[0] == b'.' && *s == suffix)
    {
        let start = bytes[..offset]
            .iter()
            .rposition(|b| !b.is_ascii_alphanumeric() && *b != b'-' && *b != b'_')
            .map_or(0, |i| i + 1);
        let end = offset + suffix.len();
        let prefix = &bytes[start..offset];
        let Some(dash) = prefix
            .windows(2)
            .position(|s| s[0].is_ascii_digit() && s[1] == b'-')
            .map(|p| p + 1)
        else {
            continue;
        };
        let number_start = prefix[..dash]
            .iter()
            .rposition(|b| !b.is_ascii_digit())
            .map_or(0, |i| i + 1);
        let id = String::from_utf8(bytes[start + number_start..end].to_vec()).ok()?;
        if id.as_bytes().first().is_some_and(u8::is_ascii_digit)
            && id.contains('-')
            && !ids.iter().any(|(value, _)| value == &id)
        {
            ids.push((id, end));
        }
    }
    let mut secrets = Vec::new();
    for (offset, _) in bytes
        .windows(7)
        .enumerate()
        .filter(|(_, s)| s[0] == b'G' && *s == b"GOCSPX-")
    {
        let candidate = bytes.get(offset..offset + 35)?;
        if candidate[7..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        {
            let value = String::from_utf8(candidate.to_vec()).ok()?;
            if !secrets.iter().any(|(s, _)| s == &value) {
                secrets.push((value, offset + 35));
            }
        }
    }
    match (ids.as_slice(), secrets.as_slice()) {
        ([(id, _)], [(secret, _)]) => Some(vec![OAuthClient {
            id: id.clone(),
            secret: secret.clone(),
        }]),
        // Antigravity 2 native binaries identify the app client at the AuthProvider
        // marker and its secret immediately before the Cloud Code URL. Reject drift.
        ([(id, id_end), (legacy_id, _)], [(legacy_secret, _), (secret, secret_end)])
            if bytes[*id_end..].starts_with(b"[AuthProvider]")
                && bytes[*secret_end..].starts_with(b"https://cloudcode-pa.googleapis.com") =>
        {
            Some(vec![
                OAuthClient {
                    id: id.clone(),
                    secret: secret.clone(),
                },
                OAuthClient {
                    id: legacy_id.clone(),
                    secret: legacy_secret.clone(),
                },
            ])
        }
        _ => None,
    }
}

pub(crate) struct Session {
    pub token: Secret,
    credential: Credential,
    store: Arc<dyn Store>,
    refreshed: bool,
}
impl Session {
    pub async fn load(
        store: Arc<dyn Store>,
        context: &ProviderContext,
    ) -> Result<Self, ProviderError> {
        Self::load_with_refresh_url(store, context, REFRESH_URL).await
    }
    async fn load_with_refresh_url(
        store: Arc<dyn Store>,
        context: &ProviderContext,
        refresh_url: &str,
    ) -> Result<Self, ProviderError> {
        let source = store.clone();
        tracing::debug!("Reading Antigravity login from Keychain");
        let credential = keychain_task(move || source.credential()).await?;
        tracing::debug!("Antigravity login loaded; reading derived cache");
        let source = store.clone();
        let cached = cache_task(move || source.cache()).await.flatten();
        let now = context.clock.now();
        let cached = cached.filter(|c| {
            c.fingerprint == credential.fingerprint()
                && c.expires_at > now.unix_timestamp() + 60
                && !c.access_token.trim().is_empty()
        });
        let token = cached
            .map(|c| Secret(c.access_token))
            .or_else(|| credential.usable_token(now));
        let mut session = Self {
            token: token.unwrap_or_else(|| Secret(String::new())),
            credential,
            store,
            refreshed: false,
        };
        if session.token.0.is_empty() {
            session.refresh(context, refresh_url).await?;
        }
        Ok(session)
    }
    pub async fn verify(&self) -> Result<(), ProviderError> {
        let store = self.store.clone();
        let fingerprint = self.credential.fingerprint();
        keychain_task(move || {
            if store.credential()?.fingerprint() != fingerprint {
                return Err(ProviderError::Authentication);
            }
            Ok(())
        })
        .await
    }
    pub async fn refresh(
        &mut self,
        context: &ProviderContext,
        url: &str,
    ) -> Result<(), ProviderError> {
        if self.refreshed {
            return Err(ProviderError::Authentication);
        }
        self.refreshed = true;
        let refresh_token = self
            .credential
            .refresh_token
            .clone()
            .ok_or(ProviderError::Authentication)?;
        self.verify().await?;
        let store = self.store.clone();
        tracing::debug!("Discovering Antigravity OAuth client in installed app");
        let clients = tokio::task::spawn_blocking(move || store.clients())
            .await
            .map_err(|_| ProviderError::Internal)??;
        #[derive(Deserialize)]
        struct Response {
            access_token: String,
            expires_in: i64,
        }
        let mut refreshed = None;
        // Only the two recognized app clients are eligible. A credential rejection
        // or transient failure never retries another client; only client mismatch does.
        for client in clients.into_iter().take(2) {
            self.verify().await?;
            tracing::debug!("Refreshing Antigravity access token with Google OAuth");
            let response = context
                .http
                .post(url)
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &refresh_token),
                    ("client_id", &client.id),
                    ("client_secret", &client.secret),
                ])
                .send()
                .await
                .map_err(|error| {
                    if error.is_timeout() {
                        ProviderError::Timeout
                    } else {
                        ProviderError::Transient
                    }
                })?;
            tracing::debug!(
                status = response.status().as_u16(),
                "Antigravity OAuth response"
            );
            // Token endpoint errors contain only a whitelisted error code in diagnostics.
            if matches!(response.status().as_u16(), 400 | 401 | 403) {
                let mut response = response;
                let mut bytes = Vec::new();
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .map_err(|_| ProviderError::Transient)?
                {
                    if bytes.len() + chunk.len() > MAX_CREDENTIAL_BYTES {
                        return Err(ProviderError::Authentication);
                    }
                    bytes.extend_from_slice(&chunk);
                }
                let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
                let reason = match value.get("error").and_then(serde_json::Value::as_str) {
                    Some("invalid_client") => "invalid_client",
                    Some("invalid_grant") => "invalid_grant",
                    Some("unauthorized_client") => "unauthorized_client",
                    _ => "rejected",
                };
                tracing::debug!(reason, "Antigravity OAuth refresh rejected");
                if matches!(reason, "invalid_client" | "unauthorized_client") {
                    continue;
                }
                return Err(ProviderError::Authentication);
            }
            refreshed = Some(http::json_response::<Response>(response, context.clock.now()).await?);
            break;
        }
        let response = refreshed.ok_or(ProviderError::Authentication)?;
        if response.access_token.trim().is_empty()
            || response.expires_in <= 60
            || response.expires_in > 86400
        {
            return Err(ProviderError::InvalidData);
        }
        self.verify().await?;
        let cache = CachedToken {
            fingerprint: self.credential.fingerprint(),
            access_token: response.access_token.clone(),
            expires_at: context.clock.now().unix_timestamp() + response.expires_in,
        };
        let store = self.store.clone();
        // Late writes remain bound to the source fingerprint and cannot authorize a
        // different login. A blocked optional cache must not discard the fresh token.
        cache_task(move || store.save_cache(&cache)).await;
        self.token = Secret(response.access_token);
        Ok(())
    }
    pub async fn retry_auth(&mut self, context: &ProviderContext) -> Result<(), ProviderError> {
        self.refresh(context, REFRESH_URL).await
    }
}

pub(crate) async fn usage_cache_identity() -> Option<String> {
    keychain_task(|| {
        NativeStore
            .credential()
            .map(|credential| credential.fingerprint())
    })
    .await
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    struct MemoryStore {
        credential: Mutex<Option<Credential>>,
        cached: Mutex<Option<CachedToken>>,
        writes: Mutex<usize>,
    }
    impl MemoryStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                credential: Mutex::new(Some(Credential {
                    access_token: Some("original-access".into()),
                    refresh_token: Some("original-refresh".into()),
                    expiry: None,
                })),
                cached: Mutex::new(None),
                writes: Mutex::new(0),
            })
        }
    }
    impl Store for MemoryStore {
        fn credential(&self) -> Result<Credential, ProviderError> {
            self.credential
                .lock()
                .unwrap()
                .clone()
                .ok_or(ProviderError::Authentication)
        }
        fn cache(&self) -> Result<Option<CachedToken>, ProviderError> {
            Ok(self.cached.lock().unwrap().as_ref().map(|c| CachedToken {
                fingerprint: c.fingerprint.clone(),
                access_token: c.access_token.clone(),
                expires_at: c.expires_at,
            }))
        }
        fn save_cache(&self, cache: &CachedToken) -> Result<(), ProviderError> {
            *self.writes.lock().unwrap() += 1;
            *self.cached.lock().unwrap() = Some(CachedToken {
                fingerprint: cache.fingerprint.clone(),
                access_token: cache.access_token.clone(),
                expires_at: cache.expires_at,
            });
            Ok(())
        }
        fn clients(&self) -> Result<Vec<OAuthClient>, ProviderError> {
            Ok(vec![OAuthClient {
                id: "synthetic-client".into(),
                secret: "synthetic-client-secret".into(),
            }])
        }
    }
    #[test]
    fn structured_credentials_are_bounded_and_validated() {
        let raw = br#"{"token":{"access_token":" access ","refresh_token":"refresh","expiry":"2026-09-05T10:00:00Z"}}"#;
        let wrapped = format!("go-keyring-base64:{}", STANDARD.encode(raw));
        let credential = parse_credential(wrapped.as_bytes()).unwrap();
        assert_eq!(credential.access_token.as_deref(), Some("access"));
        let expiry = OffsetDateTime::parse(credential.expiry.as_ref().unwrap(), &Rfc3339).unwrap();
        assert!(
            credential
                .usable_token(expiry - time::Duration::seconds(60))
                .is_none()
        );
        assert!(
            credential
                .usable_token(expiry - time::Duration::seconds(61))
                .is_some()
        );
        for invalid in [
            b"raw-token".as_slice(),
            b"{}",
            b"{\"access_token\":\" \"}",
            b"{\"access_token\":\"x\",\"expiry\":\"bad\"}",
            b"go-keyring-base64:bad",
        ] {
            assert!(parse_credential(invalid).is_err());
        }
        assert!(parse_credential(&vec![b'a'; MAX_CREDENTIAL_BYTES + 1]).is_err());
    }
    #[test]
    fn app_client_discovery_rejects_ambiguous_binary_layouts() {
        let id = "123-synthetic.apps.googleusercontent.com";
        let secret = format!("GOCSPX-{}", "a".repeat(28));
        let text = format!("client='runtime{id}' secret='{secret}'");
        let parsed = parse_client(text.as_bytes()).unwrap().remove(0);
        assert_eq!(parsed.id, id);
        assert_eq!(parsed.secret, secret);
        assert!(
            parse_client(format!("{text} '456-other.apps.googleusercontent.com'").as_bytes())
                .is_none()
        );
        let second_secret = format!("GOCSPX-{}", "b".repeat(28));
        let binary = format!(
            "{secret}{second_secret}https://cloudcode-pa.googleapis.com\0{id}[AuthProvider]\0'456-other.apps.googleusercontent.com'"
        );
        let parsed = parse_client(binary.as_bytes()).unwrap().remove(0);
        assert_eq!(parsed.id, id);
        assert_eq!(parsed.secret, second_secret);
        assert!(parse_client(binary.replace("[AuthProvider]", "[Changed]").as_bytes()).is_none());
    }
    #[tokio::test]
    async fn cache_is_bound_to_current_readable_login_and_expiry() {
        let context = http::fixture::context();
        let store = MemoryStore::new();
        *store.cached.lock().unwrap() = Some(CachedToken {
            fingerprint: store.credential().unwrap().fingerprint(),
            access_token: "cached-access".into(),
            expires_at: context.clock.now().unix_timestamp() + 300,
        });
        let session = Session::load(store.clone(), &context).await.unwrap();
        assert_eq!(session.token.0, "cached-access");
        store
            .credential
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .refresh_token = Some("other-refresh".into());
        assert_eq!(session.verify().await, Err(ProviderError::Authentication));
        assert_eq!(
            Session::load(store.clone(), &context)
                .await
                .unwrap()
                .token
                .0,
            "original-access"
        );
        *store.credential.lock().unwrap() = None;
        assert!(matches!(
            Session::load(store.clone(), &context).await,
            Err(ProviderError::Authentication)
        ));
        assert_eq!(*store.writes.lock().unwrap(), 0);
    }
    #[tokio::test]
    async fn refresh_posts_once_and_only_writes_derived_cache() {
        let context = http::fixture::context();
        let store = MemoryStore::new();
        let mut session = Session::load(store.clone(), &context).await.unwrap();
        let (base, task) = http::fixture::server(vec![
            serde_json::json!({"access_token":"fresh-access", "expires_in":3600}),
        ])
        .await;
        session.refresh(&context, &base).await.unwrap();
        assert_eq!(session.token.0, "fresh-access");
        assert_eq!(
            store.credential().unwrap().access_token.as_deref(),
            Some("original-access")
        );
        assert_eq!(*store.writes.lock().unwrap(), 1);
        assert_eq!(
            Session::load(store.clone(), &context)
                .await
                .unwrap()
                .token
                .0,
            "fresh-access"
        );
        assert_eq!(
            session.refresh(&context, &base).await,
            Err(ProviderError::Authentication)
        );
        let requests = task.await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("grant_type=refresh_token"));
        assert!(requests[0].contains("refresh_token=original-refresh"));
        assert!(!requests[0].contains("original-access"));
    }
    #[tokio::test]
    async fn refresh_failure_does_not_write_cache() {
        for status in [400, 401, 429, 503] {
            let store = MemoryStore::new();
            let context = http::fixture::context();
            let mut session = Session::load(store.clone(), &context).await.unwrap();
            let (base, task) =
                http::fixture::server_status(vec![(status, serde_json::json!({}))]).await;
            let expected = match status {
                400 | 401 => ProviderError::Authentication,
                429 => ProviderError::RateLimited,
                _ => ProviderError::Transient,
            };
            assert_eq!(session.refresh(&context, &base).await, Err(expected));
            task.await.unwrap();
            assert_eq!(*store.writes.lock().unwrap(), 0);
        }
    }
    #[tokio::test]
    async fn expired_token_refreshes_before_use_and_stale_cache_is_ignored() {
        let store = MemoryStore::new();
        let context = http::fixture::context();
        store.credential.lock().unwrap().as_mut().unwrap().expiry =
            Some(context.clock.now().format(&Rfc3339).unwrap());
        *store.cached.lock().unwrap() = Some(CachedToken {
            fingerprint: store.credential().unwrap().fingerprint(),
            access_token: "stale-cache".into(),
            expires_at: context.clock.now().unix_timestamp() + 60,
        });
        let (base, task) = http::fixture::server(vec![
            serde_json::json!({"access_token":"fresh-access", "expires_in":3600}),
        ])
        .await;
        let session = Session::load_with_refresh_url(store.clone(), &context, &base)
            .await
            .unwrap();
        assert_eq!(session.token.0, "fresh-access");
        assert_eq!(*store.writes.lock().unwrap(), 1);
        assert_eq!(task.await.unwrap().len(), 1);
    }
    #[tokio::test]
    async fn account_change_during_refresh_prevents_cache_write() {
        struct SwitchingStore {
            inner: Arc<MemoryStore>,
            reads: std::sync::atomic::AtomicUsize,
        }
        impl Store for SwitchingStore {
            fn credential(&self) -> Result<Credential, ProviderError> {
                let mut credential = self.inner.credential()?;
                if self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 3 {
                    credential.refresh_token = Some("other-account".into());
                }
                Ok(credential)
            }
            fn cache(&self) -> Result<Option<CachedToken>, ProviderError> {
                self.inner.cache()
            }
            fn save_cache(&self, cache: &CachedToken) -> Result<(), ProviderError> {
                self.inner.save_cache(cache)
            }
            fn clients(&self) -> Result<Vec<OAuthClient>, ProviderError> {
                self.inner.clients()
            }
        }
        let inner = MemoryStore::new();
        let store = Arc::new(SwitchingStore {
            inner: inner.clone(),
            reads: std::sync::atomic::AtomicUsize::new(0),
        });
        let context = http::fixture::context();
        let mut session = Session::load(store, &context).await.unwrap();
        let (base, task) = http::fixture::server(vec![
            serde_json::json!({"access_token":"fresh-access", "expires_in":3600}),
        ])
        .await;
        assert_eq!(
            session.refresh(&context, &base).await,
            Err(ProviderError::Authentication)
        );
        assert_eq!(*inner.writes.lock().unwrap(), 0);
        task.await.unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn blocked_native_read_returns_actionable_error() {
        let (release, blocked) = std::sync::mpsc::channel();
        let (started, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(keychain_task(move || {
            let _ = started.send(());
            blocked.recv().unwrap();
            Ok(())
        }));
        ready.await.unwrap();
        tokio::time::advance(std::time::Duration::from_secs(6)).await;
        assert_eq!(
            task.await.unwrap(),
            Err(ProviderError::LocalCredentialStorage)
        );
        release.send(()).unwrap();
    }
    #[tokio::test]
    async fn only_client_mismatch_tries_the_second_recognized_client() {
        struct TwoClients(Arc<MemoryStore>);
        impl Store for TwoClients {
            fn credential(&self) -> Result<Credential, ProviderError> {
                self.0.credential()
            }
            fn cache(&self) -> Result<Option<CachedToken>, ProviderError> {
                self.0.cache()
            }
            fn save_cache(&self, cache: &CachedToken) -> Result<(), ProviderError> {
                self.0.save_cache(cache)
            }
            fn clients(&self) -> Result<Vec<OAuthClient>, ProviderError> {
                Ok(vec![
                    OAuthClient {
                        id: "native-client".into(),
                        secret: "native-secret".into(),
                    },
                    OAuthClient {
                        id: "legacy-client".into(),
                        secret: "legacy-secret".into(),
                    },
                ])
            }
        }
        for reason in ["unauthorized_client", "invalid_grant"] {
            let memory = MemoryStore::new();
            let store = Arc::new(TwoClients(memory.clone()));
            let context = http::fixture::context();
            let mut session = Session::load(store, &context).await.unwrap();
            let mut responses = vec![(400, serde_json::json!({"error":reason}))];
            if reason == "unauthorized_client" {
                responses.push((
                    200,
                    serde_json::json!({"access_token":"fresh", "expires_in":3600}),
                ));
            }
            let (base, task) = http::fixture::server_status(responses).await;
            let result = session.refresh(&context, &base).await;
            if reason == "unauthorized_client" {
                result.unwrap();
                let requests = task.await.unwrap();
                assert_eq!(requests.len(), 2);
                assert!(requests[0].contains("client_id=native-client"));
                assert!(requests[1].contains("client_id=legacy-client"));
                assert_eq!(*memory.writes.lock().unwrap(), 1);
            } else {
                assert_eq!(result, Err(ProviderError::Authentication));
                assert_eq!(task.await.unwrap().len(), 1);
                assert_eq!(*memory.writes.lock().unwrap(), 0);
            }
        }
    }
    #[tokio::test(start_paused = true)]
    async fn blocked_optional_cache_is_a_miss_after_one_second() {
        let (release, blocked) = std::sync::mpsc::channel();
        let (started, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(cache_task(move || {
            let _ = started.send(());
            blocked.recv().unwrap();
            Ok(())
        }));
        ready.await.unwrap();
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        assert_eq!(task.await.unwrap(), None);
        release.send(()).unwrap();
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn keychain_queries_never_request_interaction() {
        use core_foundation::{base::TCFType, string::CFString};
        #[allow(deprecated)]
        let query = options("synthetic-service", "synthetic-account").query;
        let key = CFString::new("u_AuthUI");
        let fail = CFString::new("u_AuthUIF").into_CFType();
        assert!(query.iter().any(|(k, v)| k == &key && v == &fail));
    }
}
