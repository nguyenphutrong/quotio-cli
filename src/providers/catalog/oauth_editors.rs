use super::{AuthKind, Definition, common};
use crate::{
    domain::{ProviderUsage, QuotaWindow},
    error::ProviderError,
    providers::{FetchFuture, ProviderContext, Secret, http, process},
};
use serde_json::Value;
use std::{
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(target_os = "macos")]
use std::process::Stdio;
use time::OffsetDateTime;
#[cfg(target_os = "macos")]
use tokio::{
    io::{AsyncReadExt, BufReader},
    process::Command,
};

const CURSOR_USAGE_URL: &str =
    "https://api2.cursor.sh/aiserver.v1.DashboardService/GetCurrentPeriodUsage";
const GROK_CREDITS_URL: &str = "https://cli-chat-proxy.grok.com/v1/billing?format=credits";
const KIMI_CODE_USAGE_URL: &str = "https://api.kimi.com/coding/v1/usages";
const CURSOR_KEYCHAIN_SERVICE: &str = "cursor-access-token";
const CURSOR_STATE_QUERY: &str =
    "SELECT value FROM ItemTable WHERE key = 'cursorAuth/accessToken' LIMIT 1;";
const MAX_NATIVE_FILE_BYTES: u64 = 1024 * 1024;
const MAX_CURSOR_DATABASE_BYTES: u64 = 64 * 1024 * 1024;
const NATIVE_READ_TIMEOUT: Duration = Duration::from_secs(1);
const CURSOR_SQLITE_TIMEOUT: Duration = Duration::from_secs(2);

pub const DEFINITIONS: &[Definition] = &[
    Definition {
        id: "cursor",
        name: "Cursor",
        key_env: "CURSOR_ACCESS_TOKEN",
        auth: AuthKind::OAuth,
        settings: &[],
        fetch: cursor,
    },
    Definition {
        id: "grok",
        name: "Grok",
        key_env: "GROK_OAUTH_TOKEN",
        auth: AuthKind::OAuth,
        settings: &[],
        fetch: grok,
    },
    Definition {
        id: "kimi",
        name: "Kimi Code",
        key_env: "KIMI_CODE_API_KEY",
        auth: AuthKind::ApiKey,
        settings: &[],
        fetch: kimi,
    },
];

fn cursor(context: &ProviderContext) -> FetchFuture<'_> {
    Box::pin(async move { fetch_cursor_at(context, CURSOR_USAGE_URL).await })
}

fn grok(context: &ProviderContext) -> FetchFuture<'_> {
    Box::pin(async move { fetch_grok_at(context, GROK_CREDITS_URL).await })
}

fn kimi(context: &ProviderContext) -> FetchFuture<'_> {
    Box::pin(async move { fetch_kimi_at(context, KIMI_CODE_USAGE_URL).await })
}

async fn fetch_cursor_at(
    context: &ProviderContext,
    endpoint: &str,
) -> Result<ProviderUsage, ProviderError> {
    let key = cursor_token(context).await?;
    let now = context.clock.now();
    let root: Value = common::json(
        context
            .http
            .post(endpoint)
            .header(
                "Authorization",
                http::sensitive(&format!("Bearer {}", key.0))?,
            )
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("Connect-Protocol-Version", "1")
            .body("{}"),
        now,
    )
    .await?;
    token_usage(
        "cursor",
        &key,
        "native-oauth",
        "Cursor OAuth token",
        cursor_windows(&root, now)?,
    )
}

async fn fetch_grok_at(
    context: &ProviderContext,
    endpoint: &str,
) -> Result<ProviderUsage, ProviderError> {
    let key = grok_token(context).await?;
    let now = context.clock.now();
    let root: Value = common::json(
        context
            .http
            .get(endpoint)
            .header(
                "Authorization",
                http::sensitive(&format!("Bearer {}", key.0))?,
            )
            .header("x-xai-token-auth", "xai-grok-cli")
            .header("Accept", "application/json"),
        now,
    )
    .await?;
    token_usage(
        "grok",
        &key,
        "cli-oauth",
        "Grok OAuth token",
        grok_windows(&root, now)?,
    )
}

async fn fetch_kimi_at(
    context: &ProviderContext,
    endpoint: &str,
) -> Result<ProviderUsage, ProviderError> {
    let key = kimi_code_key(context)?;
    let now = context.clock.now();
    let root: Value = common::json(
        context
            .http
            .get(endpoint)
            .header(
                "Authorization",
                http::sensitive(&format!("Bearer {}", key.0))?,
            )
            .header("Accept", "application/json"),
        now,
    )
    .await?;
    token_usage(
        "kimi",
        &key,
        "code-api-key",
        "Kimi Code API key",
        kimi_windows(&root, now)?,
    )
}

fn token_usage(
    id: &str,
    key: &Secret,
    scope: &str,
    label: &str,
    windows: Vec<QuotaWindow>,
) -> Result<ProviderUsage, ProviderError> {
    let mut usage = common::usage(id, key, scope, windows)?;
    usage.account.label = label.into();
    Ok(usage)
}

fn percentage(value: Option<&Value>) -> Result<Option<f64>, ProviderError> {
    let value = common::number(value)?;
    if value.is_some_and(|value| value > 100.0) {
        return Err(ProviderError::InvalidData);
    }
    Ok(value)
}

fn cursor_windows(root: &Value, now: OffsetDateTime) -> Result<Vec<QuotaWindow>, ProviderError> {
    if root.get("enabled").and_then(Value::as_bool) == Some(false) {
        return Err(ProviderError::InvalidData);
    }
    let plan = root
        .get("planUsage")
        .filter(|value| value.is_object())
        .ok_or(ProviderError::InvalidData)?;
    let reset = common::date(root.get("billingCycleEnd"))?;
    if reset.is_some_and(|reset| reset <= now) {
        return Err(ProviderError::InvalidData);
    }
    let mut windows = Vec::new();
    for (field, label) in [
        ("totalPercentUsed", "Current period"),
        ("autoPercentUsed", "Cursor Models"),
        ("apiPercentUsed", "Other Models"),
    ] {
        if let Some(used) = percentage(plan.get(field))? {
            windows.push(common::window(
                label,
                Some(used),
                Some(100.0),
                None,
                "percent",
                reset,
                "cursor_native_oauth",
                now,
            )?);
        }
    }
    if windows.is_empty() {
        return Err(ProviderError::InvalidData);
    }
    Ok(windows)
}

fn grok_windows(root: &Value, now: OffsetDateTime) -> Result<Vec<QuotaWindow>, ProviderError> {
    let config = root
        .get("config")
        .filter(|value| value.is_object())
        .ok_or(ProviderError::InvalidData)?;
    // Proto JSON may omit zero-valued fields. Without a provider contract that
    // distinguishes omitted zero from withheld quota, keep this unknown rather
    // than manufacturing a 0% subscription reading.
    let used = percentage(config.get("creditUsagePercent"))?.ok_or(ProviderError::InvalidData)?;
    let period = config
        .get("currentPeriod")
        .filter(|value| value.is_object());
    let label = match period
        .and_then(|period| period.get("type"))
        .and_then(Value::as_str)
        .map(str::trim)
    {
        Some("USAGE_PERIOD_TYPE_WEEKLY") => "Weekly",
        Some("USAGE_PERIOD_TYPE_MONTHLY") => "Monthly",
        _ => "Credits",
    };
    let reset = period
        .and_then(|period| period.get("end"))
        .or_else(|| config.get("billingPeriodEnd"));
    let reset = common::date(reset)?;
    if reset.is_some_and(|reset| reset <= now) {
        return Err(ProviderError::InvalidData);
    }
    Ok(vec![common::window(
        label,
        Some(used),
        Some(100.0),
        None,
        "percent",
        reset,
        "grok_cli_oauth",
        now,
    )?])
}

fn kimi_windows(root: &Value, now: OffsetDateTime) -> Result<Vec<QuotaWindow>, ProviderError> {
    let usage = root.get("usage").ok_or(ProviderError::InvalidData)?;
    let mut windows = vec![kimi_detail_window(
        usage,
        "Code 7-day",
        "kimi_code_api",
        now,
    )?];
    match root.get("limits") {
        None | Some(Value::Null) => (),
        Some(Value::Array(limits)) => {
            if limits.len() > 8 {
                return Err(ProviderError::InvalidData);
            }
            for limit in limits {
                let window = limit.get("window").ok_or(ProviderError::InvalidData)?;
                let detail = limit.get("detail").ok_or(ProviderError::InvalidData)?;
                windows.push(kimi_detail_window(
                    detail,
                    &kimi_rate_label(window)?,
                    "kimi_code_api",
                    now,
                )?);
            }
        }
        Some(_) => return Err(ProviderError::InvalidData),
    }
    Ok(windows)
}

fn kimi_detail_window(
    detail: &Value,
    label: &str,
    source: &str,
    now: OffsetDateTime,
) -> Result<QuotaWindow, ProviderError> {
    let detail = detail.as_object().ok_or(ProviderError::InvalidData)?;
    let limit = common::number(detail.get("limit"))?
        .filter(|limit| *limit > 0.0)
        .ok_or(ProviderError::InvalidData)?;
    let used = common::number(detail.get("used"))?;
    let remaining = common::number(detail.get("remaining"))?;
    // A supplied used count is authoritative. Some plans report an overage,
    // where an independently reported remaining value would be stale or wrong.
    let (used, remaining) = if used.is_some() {
        (used, None)
    } else {
        (None, remaining)
    };
    if used.is_none() && remaining.is_none() {
        return Err(ProviderError::InvalidData);
    }
    let reset = first(detail, &["resetTime", "resetAt", "reset_time", "reset_at"]);
    common::window(
        label,
        used,
        Some(limit),
        remaining,
        "requests",
        common::date(reset)?,
        source,
        now,
    )
}

fn kimi_rate_label(window: &Value) -> Result<String, ProviderError> {
    let window = window.as_object().ok_or(ProviderError::InvalidData)?;
    let duration = common::number(window.get("duration"))?.ok_or(ProviderError::InvalidData)?;
    if duration.fract() != 0.0 || !(1.0..=10_080.0).contains(&duration) {
        return Err(ProviderError::InvalidData);
    }
    let unit = match window.get("timeUnit").and_then(Value::as_str) {
        Some("TIME_UNIT_MINUTE") => "minute",
        Some("TIME_UNIT_HOUR") => "hour",
        Some("TIME_UNIT_DAY") => "day",
        _ => return Err(ProviderError::InvalidData),
    };
    let duration = duration as u64;
    let suffix = if duration == 1 { "" } else { "s" };
    Ok(format!("Rate limit ({duration} {unit}{suffix})"))
}

fn first<'a>(object: &'a serde_json::Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

fn kimi_code_key(context: &ProviderContext) -> Result<Secret, ProviderError> {
    validate_kimi_code_key(common::key(context, "KIMI_CODE_API_KEY")?)
}

fn validate_kimi_code_key(key: Secret) -> Result<Secret, ProviderError> {
    let value = key.0.trim();
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("bearer ")
        || lower.starts_with("cookie:")
        || lower.starts_with("kimi-auth=")
        || looks_like_jwt(value)
    {
        return Err(ProviderError::Authentication);
    }
    Ok(key)
}

fn looks_like_jwt(value: &str) -> bool {
    let mut parts = value.split('.');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(first), Some(second), Some(third), None)
            if !first.is_empty() && !second.is_empty() && !third.is_empty()
    )
}

async fn cursor_token(context: &ProviderContext) -> Result<Secret, ProviderError> {
    if context.credentials.get("CURSOR_ACCESS_TOKEN").is_some() {
        return common::key(context, "CURSOR_ACCESS_TOKEN");
    }
    match cursor_state_token().await {
        Ok(Some(token)) => return Ok(token),
        Ok(None)
        | Err(
            ProviderError::Authentication
            | ProviderError::CredentialStorage
            | ProviderError::InvalidData
            | ProviderError::Unavailable,
        ) => (),
        Err(error) => return Err(error),
    }
    let bytes = blocking(|| common::read_keychain(CURSOR_KEYCHAIN_SERVICE, None)).await?;
    let bytes = bytes.ok_or(ProviderError::Authentication)?;
    secret_from_bytes(&bytes)
}

#[cfg(target_os = "macos")]
struct CursorDatabase {
    query_file: std::fs::File,
    inspection_file: std::fs::File,
}

#[cfg(target_os = "macos")]
async fn cursor_state_token() -> Result<Option<Secret>, ProviderError> {
    let path = cursor_state_database_path().ok_or(ProviderError::Authentication)?;
    let path_for_open = path.clone();
    let Some(CursorDatabase {
        query_file,
        inspection_file,
    }) = blocking(move || open_cursor_database(&path_for_open)).await?
    else {
        return Ok(None);
    };
    let bytes =
        match tokio::time::timeout(CURSOR_SQLITE_TIMEOUT, cursor_sqlite_output(query_file)).await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(_)) | Err(_) => return Ok(None),
        };
    let path_for_verify = path;
    if !blocking(move || cursor_database_remains_safe(&inspection_file, &path_for_verify)).await? {
        return Ok(None);
    }
    cursor_token_from_sqlite_output(&bytes)
}

#[cfg(target_os = "macos")]
async fn cursor_sqlite_output(database: std::fs::File) -> Result<Vec<u8>, ProviderError> {
    let mut child = Command::new("/usr/bin/sqlite3")
        .args([
            "-batch",
            "-noheader",
            "-readonly",
            "file:/dev/fd/0?mode=ro&immutable=1",
            CURSOR_STATE_QUERY,
        ])
        .stdin(Stdio::from(database))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| ProviderError::Unavailable)?;
    let stdout = child.stdout.take().ok_or(ProviderError::Internal)?;
    let mut bytes = Vec::new();
    BufReader::new(stdout)
        .take((process::MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| ProviderError::InvalidData)?;
    if bytes.len() > process::MAX_BYTES {
        return Err(ProviderError::InvalidData);
    }
    if !child
        .wait()
        .await
        .map_err(|_| ProviderError::Unavailable)?
        .success()
    {
        return Err(ProviderError::Unavailable);
    }
    Ok(bytes)
}

#[cfg(not(target_os = "macos"))]
async fn cursor_state_token() -> Result<Option<Secret>, ProviderError> {
    Ok(None)
}

#[cfg(target_os = "macos")]
fn cursor_state_database_path() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|dirs| {
        dirs.home_dir()
            .join("Library/Application Support/Cursor/User/globalStorage/state.vscdb")
    })
}

#[cfg(target_os = "macos")]
fn open_cursor_database(path: &Path) -> Result<Option<CursorDatabase>, ProviderError> {
    let before = match regular_file(path, MAX_CURSOR_DATABASE_BYTES)? {
        Some(metadata) => metadata,
        None => return Ok(None),
    };
    if cursor_has_wal_sidecars(path)? {
        return Ok(None);
    }
    let query_file = open_readonly_file(path)?;
    let opened = query_file
        .metadata()
        .map_err(|_| ProviderError::CredentialStorage)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(ProviderError::CredentialStorage);
        }
    }
    if !opened.is_file() || opened.len() > MAX_CURSOR_DATABASE_BYTES {
        return Err(ProviderError::CredentialStorage);
    }
    if !cursor_database_is_rollback(&query_file)? || cursor_has_wal_sidecars(path)? {
        return Ok(None);
    }
    let inspection_file = query_file
        .try_clone()
        .map_err(|_| ProviderError::CredentialStorage)?;
    Ok(Some(CursorDatabase {
        query_file,
        inspection_file,
    }))
}

#[cfg(target_os = "macos")]
fn cursor_database_remains_safe(
    inspection_file: &std::fs::File,
    path: &Path,
) -> Result<bool, ProviderError> {
    Ok(!cursor_has_wal_sidecars(path)? && cursor_database_is_rollback(inspection_file)?)
}

#[cfg(target_os = "macos")]
fn cursor_has_wal_sidecars(path: &Path) -> Result<bool, ProviderError> {
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        if regular_file(Path::new(&sidecar), MAX_CURSOR_DATABASE_BYTES)?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(target_os = "macos")]
fn cursor_database_is_rollback(file: &std::fs::File) -> Result<bool, ProviderError> {
    use std::os::unix::fs::FileExt;

    let mut header = [0u8; 100];
    let read = file
        .read_at(&mut header, 0)
        .map_err(|_| ProviderError::CredentialStorage)?;
    if read != header.len() || &header[..16] != b"SQLite format 3\0" {
        return Ok(false);
    }
    Ok(header[18] == 1 && header[19] == 1)
}

fn cursor_token_from_sqlite_output(bytes: &[u8]) -> Result<Option<Secret>, ProviderError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let output = std::str::from_utf8(bytes).map_err(|_| ProviderError::InvalidData)?;
    let mut lines = output.lines();
    let token = lines.next().ok_or(ProviderError::InvalidData)?;
    if lines.next().is_some() {
        return Err(ProviderError::InvalidData);
    }
    secret_from_text(token).map(Some)
}

async fn grok_token(context: &ProviderContext) -> Result<Secret, ProviderError> {
    if context.credentials.get("GROK_OAUTH_TOKEN").is_some() {
        return grok_oauth_token(common::key(context, "GROK_OAUTH_TOKEN")?);
    }
    let path = grok_auth_path().ok_or(ProviderError::Authentication)?;
    let now = context.clock.now();
    blocking(move || grok_native_token(&path, now)).await
}

fn grok_auth_path() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|dirs| dirs.home_dir().join(".grok/auth.json"))
}

fn grok_native_token(path: &Path, now: OffsetDateTime) -> Result<Secret, ProviderError> {
    let bytes = read_regular_file(path, MAX_NATIVE_FILE_BYTES)?;
    grok_native_token_from_bytes(&bytes, now)
}

fn grok_native_token_from_bytes(
    bytes: &[u8],
    now: OffsetDateTime,
) -> Result<Secret, ProviderError> {
    let root: Value = serde_json::from_slice(bytes).map_err(|_| ProviderError::Authentication)?;
    let entries = root.as_object().ok_or(ProviderError::Authentication)?;
    let modern: Vec<_> = entries
        .iter()
        .filter(|(scope, _)| scope.starts_with("https://auth.x.ai::"))
        .map(|(_, entry)| entry)
        .collect();
    let legacy: Vec<_> = entries
        .iter()
        .filter(|(scope, _)| scope.as_str() == "https://accounts.x.ai/sign-in")
        .map(|(_, entry)| entry)
        .collect();
    let candidates = if modern.is_empty() { legacy } else { modern };
    let [entry] = candidates.as_slice() else {
        return Err(ProviderError::Authentication);
    };
    let entry = entry.as_object().ok_or(ProviderError::Authentication)?;
    let expiration = first(entry, &["expires_at", "expires"]);
    let expires_at = common::date(expiration)?.ok_or(ProviderError::Authentication)?;
    if expires_at <= now {
        return Err(ProviderError::Authentication);
    }
    let token = entry
        .get("key")
        .and_then(Value::as_str)
        .ok_or(ProviderError::Authentication)?;
    grok_oauth_token(secret_from_text(token)?)
}

fn grok_oauth_token(key: Secret) -> Result<Secret, ProviderError> {
    let raw = key.0.trim();
    let token = raw
        .get(..7)
        .filter(|prefix| prefix.eq_ignore_ascii_case("bearer "))
        .map_or(raw, |prefix| &raw[prefix.len()..])
        .trim();
    let lower = token.to_ascii_lowercase();
    if lower.starts_with("cookie:") || lower.starts_with("xai-") || token.contains('=') {
        return Err(ProviderError::Authentication);
    }
    secret_from_text(token)
}

async fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, ProviderError> + Send + 'static,
) -> Result<T, ProviderError> {
    match tokio::time::timeout(NATIVE_READ_TIMEOUT, tokio::task::spawn_blocking(operation)).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) | Err(_) => Err(ProviderError::CredentialStorage),
    }
}

fn open_readonly_file(path: &Path) -> Result<std::fs::File, ProviderError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    options
        .open(path)
        .map_err(|_| ProviderError::CredentialStorage)
}
fn regular_file(
    path: &Path,
    maximum_bytes: u64,
) -> Result<Option<std::fs::Metadata>, ProviderError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ProviderError::CredentialStorage),
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > maximum_bytes
    {
        return Err(ProviderError::CredentialStorage);
    }
    Ok(Some(metadata))
}

fn read_regular_file(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>, ProviderError> {
    let before = regular_file(path, maximum_bytes)?.ok_or(ProviderError::Authentication)?;
    let file = open_readonly_file(path)?;
    let opened = file
        .metadata()
        .map_err(|_| ProviderError::CredentialStorage)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(ProviderError::CredentialStorage);
        }
    }
    if !opened.is_file() || opened.len() > maximum_bytes {
        return Err(ProviderError::CredentialStorage);
    }
    let mut bytes = Vec::new();
    file.take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProviderError::CredentialStorage)?;
    if bytes.len() > maximum_bytes as usize {
        return Err(ProviderError::CredentialStorage);
    }
    Ok(bytes)
}

fn secret_from_bytes(bytes: &[u8]) -> Result<Secret, ProviderError> {
    let value = std::str::from_utf8(bytes).map_err(|_| ProviderError::Authentication)?;
    secret_from_text(value)
}

fn secret_from_text(value: &str) -> Result<Secret, ProviderError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 16_384 || value.chars().any(char::is_control) {
        return Err(ProviderError::Authentication);
    }
    Ok(Secret(value.into()))
}

pub(super) async fn cache_token(id: &str, context: &ProviderContext) -> Option<Secret> {
    match id {
        "cursor" => cursor_token(context).await.ok(),
        "grok" => grok_token(context).await.ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{Clock, CredentialStore, http::fixture};
    use serde_json::json;
    use std::sync::Arc;

    #[cfg(target_os = "macos")]
    use std::{
        path::{Path, PathBuf},
        process::Command as StdCommand,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(target_os = "macos")]
    static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[cfg(target_os = "macos")]
    struct TemporaryDirectory(PathBuf);

    #[cfg(target_os = "macos")]
    impl TemporaryDirectory {
        fn new() -> Self {
            for attempt in 0..128 {
                let ordinal = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "quotio-oauth-editors-{}-{ordinal}-{attempt}",
                    std::process::id()
                ));
                if std::fs::create_dir(&path).is_ok() {
                    return Self(path);
                }
            }
            panic!("could not create synthetic Cursor database directory");
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(target_os = "macos")]
    fn create_cursor_database(path: &Path, token: &str) {
        let statement = format!(
            "CREATE TABLE ItemTable (key TEXT, value TEXT); INSERT INTO ItemTable VALUES ('cursorAuth/accessToken', '{token}');"
        );
        let status = StdCommand::new("/usr/bin/sqlite3")
            .arg(path)
            .arg(statement)
            .status()
            .unwrap();
        assert!(status.success());
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH
        }
    }

    struct Credentials;
    impl CredentialStore for Credentials {
        fn get(&self, name: &str) -> Option<Secret> {
            match name {
                "CURSOR_ACCESS_TOKEN" => Some(Secret("cursor-native-token".into())),
                "GROK_OAUTH_TOKEN" => Some(Secret("Bearer grok-native-token".into())),
                "KIMI_CODE_API_KEY" => Some(Secret("kimi-code-key".into())),
                _ => None,
            }
        }
    }

    fn context() -> ProviderContext {
        ProviderContext {
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            clock: Arc::new(FixedClock),
            credentials: Arc::new(Credentials),
        }
    }

    #[tokio::test]
    async fn cursor_uses_native_bearer_rpc_without_cookie() {
        let (base, server) = fixture::server(vec![json!({
            "enabled": true,
            "billingCycleEnd": "2026-09-12T00:00:00Z",
            "planUsage": {
                "totalPercentUsed": 25,
                "autoPercentUsed": 10,
                "apiPercentUsed": 15
            }
        })])
        .await;
        let usage = fetch_cursor_at(&context(), &format!("{base}/cursor"))
            .await
            .unwrap();
        assert_eq!(usage.windows.len(), 3);
        assert_eq!(usage.windows[0].label, "Current period");
        let request = server.await.unwrap().pop().unwrap();
        let lower = request.to_ascii_lowercase();
        assert!(request.starts_with("POST /cursor HTTP/1.1"));
        assert!(lower.contains("authorization: bearer cursor-native-token"));
        assert!(lower.contains("connect-protocol-version: 1"));
        assert!(!lower.contains("\r\ncookie:"));
        assert!(request.ends_with("{}"));
    }

    #[test]
    fn cursor_rejects_out_of_range_usage() {
        assert_eq!(
            cursor_windows(
                &json!({"planUsage": {"totalPercentUsed": 101}}),
                OffsetDateTime::UNIX_EPOCH
            )
            .err(),
            Some(ProviderError::InvalidData)
        );
    }

    #[test]
    fn cursor_sqlite_output_accepts_exactly_one_token() {
        assert_eq!(
            cursor_token_from_sqlite_output(b"cursor-native-token\n")
                .unwrap()
                .unwrap()
                .0,
            "cursor-native-token"
        );
        assert_eq!(
            cursor_token_from_sqlite_output(b"first\nsecond\n").err(),
            Some(ProviderError::InvalidData)
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn cursor_sqlite_uses_opened_descriptor_after_path_replacement() {
        let directory = TemporaryDirectory::new();
        let database = directory.path().join("state.vscdb");
        create_cursor_database(&database, "opened-token");
        let CursorDatabase {
            query_file,
            inspection_file,
        } = open_cursor_database(&database).unwrap().unwrap();

        let replacement = directory.path().join("replacement.vscdb");
        create_cursor_database(&replacement, "replacement-token");
        std::fs::rename(&replacement, &database).unwrap();

        let output = cursor_sqlite_output(query_file).await.unwrap();
        assert!(cursor_database_remains_safe(&inspection_file, &database).unwrap());
        assert_eq!(
            cursor_token_from_sqlite_output(&output).unwrap().unwrap().0,
            "opened-token"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_reader_rejects_symlink_at_open() {
        let directory = TemporaryDirectory::new();
        let target = directory.path().join("target");
        std::fs::write(&target, b"fixture").unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            open_readonly_file(&link).err(),
            Some(ProviderError::CredentialStorage)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cursor_skips_wal_sidecars_for_descriptor_reads() {
        let directory = TemporaryDirectory::new();
        let database = directory.path().join("state.vscdb");
        create_cursor_database(&database, "fixture-token");
        std::fs::write(format!("{}-wal", database.display()), b"synthetic-wal").unwrap();
        assert!(open_cursor_database(&database).unwrap().is_none());
    }

    #[tokio::test]
    async fn grok_uses_cli_oauth_proxy_without_cookie() {
        let (base, server) = fixture::server(vec![json!({
            "config": {
                "creditUsagePercent": 30,
                "currentPeriod": {
                    "type": "USAGE_PERIOD_TYPE_WEEKLY",
                    "end": "2026-09-12T00:00:00Z"
                }
            }
        })])
        .await;
        let usage = fetch_grok_at(&context(), &format!("{base}/billing?format=credits"))
            .await
            .unwrap();
        assert_eq!(usage.windows[0].label, "Weekly");
        let request = server.await.unwrap().pop().unwrap();
        let lower = request.to_ascii_lowercase();
        assert!(request.starts_with("GET /billing?format=credits HTTP/1.1"));
        assert!(lower.contains("authorization: bearer grok-native-token"));
        assert!(lower.contains("x-xai-token-auth: xai-grok-cli"));
        assert!(!lower.contains("\r\ncookie:"));
    }

    #[test]
    fn grok_native_auth_requires_one_fresh_oidc_entry() {
        let token = json!({
            "https://auth.x.ai::fixture-client": {
                "key": "grok-native-token",
                "expires_at": "2026-09-12T00:00:00Z"
            }
        })
        .to_string();
        assert_eq!(
            grok_native_token_from_bytes(token.as_bytes(), OffsetDateTime::UNIX_EPOCH)
                .unwrap()
                .0,
            "grok-native-token"
        );
        let multiple = json!({
            "https://auth.x.ai::one": {"key": "one", "expires_at": "2026-09-12T00:00:00Z"},
            "https://auth.x.ai::two": {"key": "two", "expires_at": "2026-09-12T00:00:00Z"}
        })
        .to_string();
        assert_eq!(
            grok_native_token_from_bytes(multiple.as_bytes(), OffsetDateTime::UNIX_EPOCH).err(),
            Some(ProviderError::Authentication)
        );
        let expired = json!({
            "https://auth.x.ai::fixture-client": {
                "key": "expired-token",
                "expires_at": "1970-01-01T00:00:00Z"
            }
        })
        .to_string();
        assert_eq!(
            grok_native_token_from_bytes(expired.as_bytes(), OffsetDateTime::UNIX_EPOCH).err(),
            Some(ProviderError::Authentication)
        );
    }

    #[test]
    fn grok_does_not_make_missing_percent_zero() {
        assert_eq!(
            grok_windows(
                &json!({"config": {"currentPeriod": {"type": "USAGE_PERIOD_TYPE_WEEKLY"}}}),
                OffsetDateTime::UNIX_EPOCH
            )
            .err(),
            Some(ProviderError::InvalidData)
        );
    }

    #[tokio::test]
    async fn kimi_uses_code_key_without_web_session() {
        let (base, server) = fixture::server(vec![json!({
            "usage": {
                "limit": "100",
                "used": "25",
                "reset_time": "2026-09-12T00:00:00Z"
            },
            "limits": [{
                "window": {"duration": 5, "timeUnit": "TIME_UNIT_HOUR"},
                "detail": {"limit": 20, "remaining": 15, "resetAt": "2026-09-06T05:00:00Z"}
            }]
        })])
        .await;
        let usage = fetch_kimi_at(&context(), &format!("{base}/coding/v1/usages"))
            .await
            .unwrap();
        assert_eq!(usage.windows.len(), 2);
        assert_eq!(usage.windows[0].label, "Code 7-day");
        assert_eq!(usage.windows[1].label, "Rate limit (5 hours)");
        let request = server.await.unwrap().pop().unwrap();
        let lower = request.to_ascii_lowercase();
        assert!(request.starts_with("GET /coding/v1/usages HTTP/1.1"));
        assert!(lower.contains("authorization: bearer kimi-code-key"));
        assert!(!lower.contains("\r\ncookie:"));
    }

    #[test]
    fn kimi_rejects_web_tokens_and_missing_counts() {
        assert_eq!(
            validate_kimi_code_key(Secret("header.payload.signature".into())).err(),
            Some(ProviderError::Authentication)
        );
        assert_eq!(
            kimi_windows(
                &json!({"usage": {"limit": 100}}),
                OffsetDateTime::UNIX_EPOCH
            )
            .err(),
            Some(ProviderError::InvalidData)
        );
    }
}
