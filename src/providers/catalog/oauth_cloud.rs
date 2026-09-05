use super::{AuthKind, Definition, Setting, common};
use crate::{
    domain::{ProviderUsage, QuotaWindow},
    error::ProviderError,
    providers::{FetchFuture, ProviderContext, Secret},
};
use directories::BaseDirs;
use reqwest::{RequestBuilder, StatusCode};
use ring::{
    digest::{SHA256, digest},
    rand::{SecureRandom, SystemRandom},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration as StdDuration,
};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const MAX_NATIVE_FILE_BYTES: usize = 1024 * 1024;
const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const MONITORING_ENDPOINT: &str = "https://monitoring.googleapis.com";
const MONITORING_USAGE_METRIC: &str = "serviceruntime.googleapis.com/quota/allocation/usage";
const MONITORING_LIMIT_METRIC: &str = "serviceruntime.googleapis.com/quota/limit";
const MONITORING_SERVICE: &str = "aiplatform.googleapis.com";
const MAX_MONITORING_PAGES: usize = 20;

const KIRO_SETTINGS: &[Setting] = &[
    Setting {
        name: "region",
        env: "KIRO_REGION",
        required: false,
    },
    Setting {
        name: "profile_arn",
        env: "KIRO_PROFILE_ARN",
        required: false,
    },
];

const VERTEXAI_SETTINGS: &[Setting] = &[Setting {
    name: "project_id",
    env: "VERTEXAI_PROJECT_ID",
    required: false,
}];

pub const DEFINITIONS: &[Definition] = &[
    Definition {
        id: "kiro",
        name: "Kiro",
        key_env: "KIRO_ACCESS_TOKEN",
        auth: AuthKind::OAuth,
        settings: KIRO_SETTINGS,
        fetch: fetch_kiro,
    },
    Definition {
        id: "vertexai",
        name: "Vertex AI",
        key_env: "VERTEXAI_ACCESS_TOKEN",
        auth: AuthKind::OAuth,
        settings: VERTEXAI_SETTINGS,
        fetch: fetch_vertexai,
    },
];

struct KiroSession {
    token: Secret,
    region: String,
    profile_arn: Option<String>,
}

struct KiroNativeCredential {
    access_token: String,
    refresh_token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    auth_method: String,
    profile_arn: Option<String>,
    region: Option<String>,
    expires_at: Option<OffsetDateTime>,
}

struct VertexSession {
    token: Secret,
    project: String,
}

struct VertexAdcCredential {
    access_token: Option<String>,
    expires_at: Option<OffsetDateTime>,
    refresh_token: String,
    client_id: String,
    client_secret: String,
}

fn fetch_kiro<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(async move {
        let session = kiro_session(context).await?;
        let endpoint = format!("https://q.{}.amazonaws.com/getUsageLimits", session.region);
        fetch_kiro_at(
            context,
            &endpoint,
            &session.token,
            &session.region,
            session.profile_arn.as_deref(),
        )
        .await
    })
}

fn fetch_vertexai<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(async move {
        let session = vertex_session(context).await?;
        fetch_vertex_at(
            context,
            MONITORING_ENDPOINT,
            &session.token,
            &session.project,
        )
        .await
    })
}

fn checked_text(value: &str, maximum_length: usize) -> Result<String, ProviderError> {
    let value = value.trim();
    if value.is_empty() || value.len() > maximum_length || value.chars().any(char::is_control) {
        return Err(ProviderError::InvalidData);
    }
    Ok(value.to_owned())
}

fn checked_secret(value: &str) -> Result<String, ProviderError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 16_384 || value.chars().any(char::is_control) {
        return Err(ProviderError::Authentication);
    }
    Ok(value.to_owned())
}

fn nonsecret_setting(
    context: &ProviderContext,
    env: &str,
    maximum_length: usize,
) -> Result<Option<String>, ProviderError> {
    context
        .credentials
        .get(env)
        .map(|value| checked_text(&value.0, maximum_length))
        .transpose()
}

fn first_text(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
    maximum_length: usize,
) -> Result<Option<String>, ProviderError> {
    for key in keys {
        if let Some(value) = object.get(*key).filter(|value| !value.is_null()) {
            return checked_text(
                value.as_str().ok_or(ProviderError::InvalidData)?,
                maximum_length,
            )
            .map(Some);
        }
    }
    Ok(None)
}

fn first_secret(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Result<Option<String>, ProviderError> {
    for key in keys {
        if let Some(value) = object.get(*key).filter(|value| !value.is_null()) {
            return checked_secret(value.as_str().ok_or(ProviderError::Authentication)?).map(Some);
        }
    }
    Ok(None)
}

fn first_number(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Result<Option<f64>, ProviderError> {
    for key in keys {
        if let Some(value) = object.get(*key).filter(|value| !value.is_null()) {
            return common::number(Some(value));
        }
    }
    Ok(None)
}

fn first_date(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Result<Option<OffsetDateTime>, ProviderError> {
    for key in keys {
        if let Some(value) = object.get(*key).filter(|value| !value.is_null()) {
            return common::date(Some(value));
        }
    }
    Ok(None)
}

fn native_file(path: &Path) -> Result<Option<Vec<u8>>, ProviderError> {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ProviderError::CredentialStorage),
    };
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.len() > MAX_NATIVE_FILE_BYTES as u64
    {
        return Err(ProviderError::CredentialStorage);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.uid() != unsafe { libc::geteuid() } || before.mode() & 0o077 != 0 {
            return Err(ProviderError::CredentialStorage);
        }
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .map_err(|_| ProviderError::CredentialStorage)?;
    let opened = file
        .metadata()
        .map_err(|_| ProviderError::CredentialStorage)?;
    if !opened.is_file() || opened.len() > MAX_NATIVE_FILE_BYTES as u64 {
        return Err(ProviderError::CredentialStorage);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev()
            || before.ino() != opened.ino()
            || opened.uid() != unsafe { libc::geteuid() }
            || opened.mode() & 0o077 != 0
        {
            return Err(ProviderError::CredentialStorage);
        }
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(MAX_NATIVE_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProviderError::CredentialStorage)?;
    if bytes.len() > MAX_NATIVE_FILE_BYTES {
        return Err(ProviderError::CredentialStorage);
    }
    Ok(Some(bytes))
}

async fn read_native_file(path: PathBuf) -> Result<Option<Vec<u8>>, ProviderError> {
    // This timeout ends the caller's wait; Tokio cannot cancel a kernel read that
    // has already entered spawn_blocking. The closure performs only a bounded
    // metadata/read operation, never parsing, writing credentials, or networking.
    let task = tokio::task::spawn_blocking(move || native_file(&path));
    match tokio::time::timeout(StdDuration::from_secs(2), task).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) | Err(_) => Err(ProviderError::CredentialStorage),
    }
}

async fn read_native_json(path: PathBuf) -> Result<Option<Value>, ProviderError> {
    let Some(bytes) = read_native_file(path).await? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| ProviderError::CredentialStorage)
}

fn home_dir() -> Result<PathBuf, ProviderError> {
    BaseDirs::new()
        .map(|dirs| dirs.home_dir().to_path_buf())
        .ok_or(ProviderError::CredentialStorage)
}

fn kiro_auth_path() -> Result<PathBuf, ProviderError> {
    Ok(home_dir()?
        .join(".aws")
        .join("sso")
        .join("cache")
        .join("kiro-auth-token.json"))
}

fn valid_kiro_region(value: &str) -> bool {
    let parts: Vec<_> = value.split('-').collect();
    parts.len() >= 3
        && parts[0].len() == 2
        && parts[0].bytes().all(|byte| byte.is_ascii_lowercase())
        && parts[1..parts.len() - 1].iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
        && parts
            .last()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn profile_region(profile: &str) -> Result<Option<String>, ProviderError> {
    let parts: Vec<_> = profile.split(':').collect();
    if parts.len() >= 4 && parts[0] == "arn" && parts[2] == "codewhisperer" {
        if !valid_kiro_region(parts[3]) {
            return Err(ProviderError::InvalidData);
        }
        return Ok(Some(parts[3].to_owned()));
    }
    Ok(None)
}

fn kiro_metadata(
    context: &ProviderContext,
    native_region: Option<&str>,
    native_profile: Option<&str>,
) -> Result<(String, Option<String>), ProviderError> {
    let configured_region = nonsecret_setting(context, "KIRO_REGION", 64)?;
    let configured_profile = nonsecret_setting(context, "KIRO_PROFILE_ARN", 2048)?;
    let native_region = native_region
        .map(|value| checked_text(value, 64))
        .transpose()?;
    let native_profile = native_profile
        .map(|value| checked_text(value, 2048))
        .transpose()?;
    if configured_profile
        .as_ref()
        .zip(native_profile.as_ref())
        .is_some_and(|(configured, native)| configured != native)
    {
        return Err(ProviderError::InvalidData);
    }
    let profile = configured_profile.or(native_profile);
    let profile_region = profile
        .as_deref()
        .map(profile_region)
        .transpose()?
        .flatten();
    let regions = [configured_region, native_region, profile_region];
    let region = regions
        .iter()
        .flatten()
        .next()
        .cloned()
        .unwrap_or_else(|| "us-east-1".into());
    if !valid_kiro_region(&region)
        || regions
            .iter()
            .flatten()
            .any(|candidate| candidate != &region)
    {
        return Err(ProviderError::InvalidData);
    }
    Ok((region, profile))
}

fn parse_kiro_native(value: &Value) -> Result<KiroNativeCredential, ProviderError> {
    let object = value.as_object().ok_or(ProviderError::CredentialStorage)?;
    Ok(KiroNativeCredential {
        access_token: first_secret(object, &["accessToken", "access_token"])?
            .ok_or(ProviderError::Authentication)?,
        refresh_token: first_secret(object, &["refreshToken", "refresh_token"])?,
        client_id: first_secret(object, &["clientId", "client_id"])?,
        client_secret: first_secret(object, &["clientSecret", "client_secret"])?,
        auth_method: first_text(object, &["authMethod", "auth_method"], 64)?
            .unwrap_or_else(|| "IdC".into()),
        profile_arn: first_text(object, &["profileArn", "profile_arn"], 2048)?,
        region: first_text(object, &["region"], 64)?,
        expires_at: first_date(object, &["expiresAt", "expires_at", "expiry", "expired"])?,
    })
}

async fn oauth_response(
    request: RequestBuilder,
    now: OffsetDateTime,
) -> Result<Value, ProviderError> {
    let response = request.send().await.map_err(|error| {
        if error.is_timeout() {
            ProviderError::Timeout
        } else {
            ProviderError::Transient
        }
    })?;
    if matches!(
        response.status(),
        StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        return Err(ProviderError::Authentication);
    }
    crate::providers::http::json_response(response, now).await
}

fn refreshed_expiry(now: OffsetDateTime, seconds: f64) -> Result<OffsetDateTime, ProviderError> {
    if seconds <= 0.0 || seconds > 31_536_000.0 || seconds.fract() != 0.0 {
        return Err(ProviderError::InvalidData);
    }
    now.checked_add(Duration::seconds(seconds as i64))
        .ok_or(ProviderError::InvalidData)
}

async fn refresh_kiro_at(
    context: &ProviderContext,
    mut credential: KiroNativeCredential,
    endpoint: &str,
) -> Result<KiroNativeCredential, ProviderError> {
    let refresh_token = credential
        .refresh_token
        .as_deref()
        .ok_or(ProviderError::Authentication)?;
    let body = if credential.auth_method.eq_ignore_ascii_case("social") {
        json!({"refreshToken": refresh_token})
    } else {
        json!({
            "refreshToken": refresh_token,
            "clientId": credential.client_id.as_deref().ok_or(ProviderError::Authentication)?,
            "clientSecret": credential.client_secret.as_deref().ok_or(ProviderError::Authentication)?,
            "grantType": "refresh_token",
        })
    };
    let now = context.clock.now();
    let root = oauth_response(
        context
            .http
            .post(endpoint)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&body),
        now,
    )
    .await?;
    let object = root.as_object().ok_or(ProviderError::InvalidData)?;
    credential.access_token = first_secret(object, &["accessToken", "access_token"])?
        .ok_or(ProviderError::InvalidData)?;
    credential.refresh_token =
        first_secret(object, &["refreshToken", "refresh_token"])?.or(credential.refresh_token);
    credential.expires_at = Some(refreshed_expiry(
        now,
        first_number(object, &["expiresIn", "expires_in"])?.ok_or(ProviderError::InvalidData)?,
    )?);
    Ok(credential)
}

async fn refresh_kiro(
    context: &ProviderContext,
    credential: KiroNativeCredential,
    region: &str,
) -> Result<KiroNativeCredential, ProviderError> {
    let endpoint = if credential.auth_method.eq_ignore_ascii_case("social") {
        format!("https://prod.{region}.auth.desktop.kiro.dev/refreshToken")
    } else {
        format!("https://oidc.{region}.amazonaws.com/token")
    };
    refresh_kiro_at(context, credential, &endpoint).await
}

async fn kiro_session(context: &ProviderContext) -> Result<KiroSession, ProviderError> {
    if context.credentials.get("KIRO_ACCESS_TOKEN").is_some() {
        let (region, profile_arn) = kiro_metadata(context, None, None)?;
        return Ok(KiroSession {
            token: common::key(context, "KIRO_ACCESS_TOKEN")?,
            region,
            profile_arn,
        });
    }

    let source = read_native_json(kiro_auth_path()?)
        .await?
        .ok_or(ProviderError::Authentication)?;
    let mut credential = parse_kiro_native(&source)?;
    let (region, profile_arn) = kiro_metadata(
        context,
        credential.region.as_deref(),
        credential.profile_arn.as_deref(),
    )?;
    if credential
        .expires_at
        .is_none_or(|expires_at| expires_at <= context.clock.now() + Duration::minutes(5))
    {
        credential = refresh_kiro(context, credential, &region).await?;
    }
    Ok(KiroSession {
        token: Secret(credential.access_token),
        region,
        profile_arn,
    })
}

fn kiro_machine_identifier(token: &Secret) -> String {
    digest(&SHA256, format!("quotio:kiro:{}", token.0).as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn invocation_id() -> Result<String, ProviderError> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| ProviderError::Internal)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    ))
}

fn kiro_windows(
    root: &Value,
    now: OffsetDateTime,
) -> Result<(Vec<QuotaWindow>, Option<String>), ProviderError> {
    let object = root.as_object().ok_or(ProviderError::InvalidData)?;
    let common_reset = first_date(object, &["nextDateReset", "next_date_reset"])?;
    let plan = match object
        .get("subscriptionInfo")
        .filter(|value| !value.is_null())
    {
        None => None,
        Some(value) => first_text(
            value.as_object().ok_or(ProviderError::InvalidData)?,
            &["subscriptionTitle", "subscription_title"],
            128,
        )?,
    };
    let breakdowns = object
        .get("usageBreakdownList")
        .or_else(|| object.get("usage_breakdown_list"))
        .and_then(Value::as_array)
        .ok_or(ProviderError::InvalidData)?;
    let mut windows = Vec::new();
    for breakdown in breakdowns {
        let breakdown = breakdown.as_object().ok_or(ProviderError::InvalidData)?;
        let name = first_text(
            breakdown,
            &[
                "resourceType",
                "resource_type",
                "displayName",
                "display_name",
            ],
            128,
        )?
        .unwrap_or_else(|| "requests".into());
        let used = first_number(
            breakdown,
            &[
                "currentUsageWithPrecision",
                "current_usage_with_precision",
                "currentUsage",
                "current_usage",
            ],
        )?;
        let limit = first_number(
            breakdown,
            &[
                "usageLimitWithPrecision",
                "usage_limit_with_precision",
                "usageLimit",
                "usage_limit",
            ],
        )?;
        let reset = first_date(breakdown, &["nextDateReset", "next_date_reset"])?.or(common_reset);
        if used.is_some() || limit.is_some() {
            windows.push(common::window(
                &format!("Kiro {name}"),
                used,
                limit,
                None,
                "requests",
                reset,
                "kiro_usage_limits",
                now,
            )?);
        }

        let Some(trial) = breakdown
            .get("freeTrialInfo")
            .filter(|value| !value.is_null())
        else {
            continue;
        };
        let trial = trial.as_object().ok_or(ProviderError::InvalidData)?;
        let active = first_text(trial, &["freeTrialStatus", "free_trial_status"], 32)?
            .is_some_and(|value| value.eq_ignore_ascii_case("ACTIVE"));
        if !active {
            continue;
        }
        let used = first_number(
            trial,
            &[
                "currentUsageWithPrecision",
                "current_usage_with_precision",
                "currentUsage",
                "current_usage",
            ],
        )?;
        let limit = first_number(
            trial,
            &[
                "usageLimitWithPrecision",
                "usage_limit_with_precision",
                "usageLimit",
                "usage_limit",
            ],
        )?;
        if used.is_some() || limit.is_some() {
            windows.push(common::window(
                &format!("Kiro bonus {name}"),
                used,
                limit,
                None,
                "requests",
                first_date(trial, &["freeTrialExpiry", "free_trial_expiry"])?.or(common_reset),
                "kiro_usage_limits",
                now,
            )?);
        }
    }
    if windows.is_empty() {
        return Err(ProviderError::QuotaUnavailable);
    }
    Ok((windows, plan))
}

async fn fetch_kiro_at(
    context: &ProviderContext,
    endpoint: &str,
    token: &Secret,
    region: &str,
    profile_arn: Option<&str>,
) -> Result<ProviderUsage, ProviderError> {
    let machine = kiro_machine_identifier(token);
    let user_agent = format!(
        "aws-sdk-js/1.0.0 ua/2.1 os/other lang/rust api/codewhispererruntime#1.0.0 KiroIDE-quotio-{machine}"
    );
    let mut query = vec![
        ("origin".to_owned(), "AI_EDITOR".to_owned()),
        ("resourceType".to_owned(), "AGENTIC_REQUEST".to_owned()),
    ];
    if let Some(profile_arn) = profile_arn {
        query.push(("profileArn".into(), profile_arn.into()));
    }
    let root: Value = common::json(
        context
            .http
            .get(endpoint)
            .query(&query)
            .header(
                "Authorization",
                crate::providers::http::sensitive(&format!("Bearer {}", token.0))?,
            )
            .header(
                "User-Agent",
                crate::providers::http::sensitive(&user_agent)?,
            )
            .header(
                "x-amz-user-agent",
                crate::providers::http::sensitive(&format!(
                    "aws-sdk-js/1.0.0 KiroIDE-quotio-{machine}"
                ))?,
            )
            .header("amz-sdk-invocation-id", invocation_id()?)
            .header("amz-sdk-request", "attempt=1; max=1")
            .header("Accept", "application/json"),
        context.clock.now(),
    )
    .await?;
    let (windows, plan) = kiro_windows(&root, context.clock.now())?;
    let scope = format!("{region}\0{}", profile_arn.unwrap_or_default());
    let mut usage = common::usage("kiro", token, &scope, windows)?;
    usage.account.label = "Kiro OAuth token".into();
    usage.account.plan = plan;
    Ok(usage)
}

fn configured_path(context: &ProviderContext, env: &str) -> Result<Option<PathBuf>, ProviderError> {
    let Some(value) = context.credentials.get(env) else {
        return Ok(None);
    };
    let path = PathBuf::from(checked_text(&value.0, 4096)?);
    if !path.is_absolute() {
        return Err(ProviderError::InvalidData);
    }
    Ok(Some(path))
}

fn vertex_config_dir(context: &ProviderContext) -> Result<PathBuf, ProviderError> {
    configured_path(context, "CLOUDSDK_CONFIG")?
        .map(Ok)
        .unwrap_or_else(|| Ok(home_dir()?.join(".config").join("gcloud")))
}

fn vertex_adc_path(context: &ProviderContext) -> Result<PathBuf, ProviderError> {
    configured_path(context, "GOOGLE_APPLICATION_CREDENTIALS")?
        .map(Ok)
        .unwrap_or_else(|| {
            Ok(vertex_config_dir(context)?.join("application_default_credentials.json"))
        })
}

fn valid_google_project(value: &str) -> bool {
    let bytes = value.as_bytes();
    (6..=30).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn project_from_config(bytes: &[u8]) -> Result<Option<String>, ProviderError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ProviderError::InvalidData)?;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name.trim() == "project" {
            return checked_text(value, 64).map(Some);
        }
    }
    Ok(None)
}

async fn vertex_project(context: &ProviderContext) -> Result<String, ProviderError> {
    if let Some(project) = nonsecret_setting(context, "VERTEXAI_PROJECT_ID", 64)? {
        return valid_google_project(&project)
            .then_some(project)
            .ok_or(ProviderError::InvalidData);
    }
    let config = vertex_config_dir(context)?.join("configurations/config_default");
    if let Some(bytes) = read_native_file(config).await?
        && let Some(project) = project_from_config(&bytes)?
    {
        return valid_google_project(&project)
            .then_some(project)
            .ok_or(ProviderError::InvalidData);
    }
    for env in [
        "GOOGLE_CLOUD_PROJECT",
        "GCLOUD_PROJECT",
        "CLOUDSDK_CORE_PROJECT",
    ] {
        if let Some(project) = nonsecret_setting(context, env, 64)? {
            return valid_google_project(&project)
                .then_some(project)
                .ok_or(ProviderError::InvalidData);
        }
    }
    Err(ProviderError::InvalidData)
}

fn parse_vertex_adc(value: &Value) -> Result<VertexAdcCredential, ProviderError> {
    let object = value.as_object().ok_or(ProviderError::CredentialStorage)?;
    if object.get("type").and_then(Value::as_str) != Some("authorized_user") {
        return Err(ProviderError::Authentication);
    }
    Ok(VertexAdcCredential {
        access_token: first_secret(object, &["access_token"])?,
        expires_at: first_date(object, &["token_expiry", "expires_at"])?,
        refresh_token: first_secret(object, &["refresh_token"])?
            .ok_or(ProviderError::Authentication)?,
        client_id: first_secret(object, &["client_id"])?.ok_or(ProviderError::Authentication)?,
        client_secret: first_secret(object, &["client_secret"])?
            .ok_or(ProviderError::Authentication)?,
    })
}

async fn refresh_vertex_at(
    context: &ProviderContext,
    credential: &VertexAdcCredential,
    endpoint: &str,
) -> Result<Secret, ProviderError> {
    let now = context.clock.now();
    let root = oauth_response(
        context.http.post(endpoint).form(&[
            ("client_id", credential.client_id.as_str()),
            ("client_secret", credential.client_secret.as_str()),
            ("refresh_token", credential.refresh_token.as_str()),
            ("grant_type", "refresh_token"),
        ]),
        now,
    )
    .await?;
    let object = root.as_object().ok_or(ProviderError::InvalidData)?;
    let token = first_secret(object, &["access_token"])?.ok_or(ProviderError::InvalidData)?;
    if let Some(expires_in) = first_number(object, &["expires_in"])? {
        let _ = refreshed_expiry(now, expires_in)?;
    }
    Ok(Secret(token))
}

async fn vertex_session(context: &ProviderContext) -> Result<VertexSession, ProviderError> {
    let project = vertex_project(context).await?;
    if context.credentials.get("VERTEXAI_ACCESS_TOKEN").is_some() {
        return Ok(VertexSession {
            token: common::key(context, "VERTEXAI_ACCESS_TOKEN")?,
            project,
        });
    }
    let source = read_native_json(vertex_adc_path(context)?)
        .await?
        .ok_or(ProviderError::Authentication)?;
    let credential = parse_vertex_adc(&source)?;
    let token = match (&credential.access_token, credential.expires_at) {
        (Some(token), Some(expires_at))
            if expires_at > context.clock.now() + Duration::minutes(5) =>
        {
            Secret(token.clone())
        }
        _ => refresh_vertex_at(context, &credential, GOOGLE_TOKEN_ENDPOINT).await?,
    };
    Ok(VertexSession { token, project })
}

async fn monitoring_response(
    request: RequestBuilder,
    now: OffsetDateTime,
) -> Result<Value, ProviderError> {
    let response = request.send().await.map_err(|error| {
        if error.is_timeout() {
            ProviderError::Timeout
        } else {
            ProviderError::Transient
        }
    })?;
    match response.status() {
        StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => Err(ProviderError::QuotaUnavailable),
        StatusCode::BAD_REQUEST => Err(ProviderError::InvalidData),
        _ => crate::providers::http::json_response(response, now).await,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MonitoringPage {
    #[serde(default)]
    time_series: Vec<MonitoringTimeSeries>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct MonitoringTimeSeries {
    metric: MonitoringMetric,
    resource: MonitoringResource,
    #[serde(default)]
    points: Vec<MonitoringPoint>,
}

#[derive(Deserialize)]
struct MonitoringMetric {
    #[serde(rename = "type")]
    metric_type: String,
    #[serde(default)]
    labels: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct MonitoringResource {
    #[serde(rename = "type")]
    resource_type: String,
    #[serde(default)]
    labels: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct MonitoringPoint {
    value: MonitoringValue,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MonitoringValue {
    #[serde(default)]
    double_value: Option<f64>,
    #[serde(default)]
    int64_value: Option<String>,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct QuotaKey {
    metric: String,
    limit_name: String,
    location: String,
}

fn page_token(value: Option<String>) -> Result<Option<String>, ProviderError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 4096 || value.chars().any(char::is_control) || value.trim() != value {
        return Err(ProviderError::InvalidData);
    }
    Ok(Some(value))
}

async fn monitoring_series(
    context: &ProviderContext,
    base: &str,
    token: &Secret,
    project: &str,
    metric_type: &str,
) -> Result<Vec<MonitoringTimeSeries>, ProviderError> {
    let now = context.clock.now();
    let start = (now - Duration::hours(24))
        .format(&Rfc3339)
        .map_err(|_| ProviderError::InvalidData)?;
    let end = now
        .format(&Rfc3339)
        .map_err(|_| ProviderError::InvalidData)?;
    let filter = format!(
        "metric.type=\"{metric_type}\" AND resource.type=\"consumer_quota\" AND resource.label.service=\"{MONITORING_SERVICE}\""
    );
    let endpoint = format!(
        "{}/v3/projects/{project}/timeSeries",
        base.trim_end_matches('/')
    );
    let authorization = crate::providers::http::sensitive(&format!("Bearer {}", token.0))?;
    let mut all_series = Vec::new();
    let mut seen_tokens = BTreeSet::new();
    let mut next: Option<String> = None;
    for page in 0..MAX_MONITORING_PAGES {
        let mut query = vec![
            ("filter".to_owned(), filter.clone()),
            ("interval.startTime".to_owned(), start.clone()),
            ("interval.endTime".to_owned(), end.clone()),
            ("aggregation.alignmentPeriod".to_owned(), "3600s".into()),
            (
                "aggregation.perSeriesAligner".to_owned(),
                "ALIGN_MAX".into(),
            ),
            ("view".to_owned(), "FULL".into()),
            ("pageSize".to_owned(), "1000".into()),
        ];
        if let Some(token) = &next {
            query.push(("pageToken".into(), token.clone()));
        }
        let root = monitoring_response(
            context
                .http
                .get(&endpoint)
                .query(&query)
                .header("Authorization", authorization.clone())
                .header("Accept", "application/json"),
            now,
        )
        .await?;
        let response: MonitoringPage =
            serde_json::from_value(root).map_err(|_| ProviderError::InvalidData)?;
        all_series.extend(response.time_series);
        let token = page_token(response.next_page_token)?;
        let Some(token) = token else {
            return Ok(all_series);
        };
        if !seen_tokens.insert(token.clone()) || page + 1 == MAX_MONITORING_PAGES {
            return Err(ProviderError::QuotaUnavailable);
        }
        next = Some(token);
    }
    Err(ProviderError::QuotaUnavailable)
}

fn monitoring_text(value: &str) -> Result<String, ProviderError> {
    checked_text(value, 192)
}

fn monitoring_key(
    series: &MonitoringTimeSeries,
    expected_metric: &str,
) -> Result<Option<QuotaKey>, ProviderError> {
    if series.metric.metric_type != expected_metric
        || series.resource.resource_type != "consumer_quota"
        || series.resource.labels.get("service").map(String::as_str) != Some(MONITORING_SERVICE)
    {
        return Ok(None);
    }
    let Some(metric) = series
        .metric
        .labels
        .get("quota_metric")
        .or_else(|| series.resource.labels.get("quota_id"))
    else {
        return Ok(None);
    };
    let limit_name = series
        .metric
        .labels
        .get("limit_name")
        .map(|value| monitoring_text(value))
        .transpose()?
        .unwrap_or_default();
    let location = series
        .resource
        .labels
        .get("location")
        .map(|value| monitoring_text(value))
        .transpose()?
        .unwrap_or_else(|| "global".into());
    Ok(Some(QuotaKey {
        metric: monitoring_text(metric)?,
        limit_name,
        location,
    }))
}

fn point_value(point: &MonitoringPoint) -> Result<Option<f64>, ProviderError> {
    let value = if let Some(value) = point.value.double_value {
        value
    } else if let Some(value) = &point.value.int64_value {
        value
            .parse::<u64>()
            .map_err(|_| ProviderError::InvalidData)? as f64
    } else {
        return Ok(None);
    };
    if !value.is_finite() || value < 0.0 {
        return Err(ProviderError::InvalidData);
    }
    Ok(Some(value))
}

fn aggregate_monitoring(
    series: &[MonitoringTimeSeries],
    expected_metric: &str,
) -> Result<BTreeMap<QuotaKey, f64>, ProviderError> {
    let mut values = BTreeMap::<QuotaKey, f64>::new();
    for entry in series {
        let Some(key) = monitoring_key(entry, expected_metric)? else {
            continue;
        };
        let mut maximum: Option<f64> = None;
        for point in &entry.points {
            if let Some(value) = point_value(point)? {
                maximum = Some(maximum.map_or(value, |previous| previous.max(value)));
            }
        }
        if let Some(value) = maximum {
            values
                .entry(key)
                .and_modify(|previous| *previous = previous.max(value))
                .or_insert(value);
        }
    }
    Ok(values)
}

fn matching_limit<'a>(
    key: &QuotaKey,
    limits: &'a BTreeMap<QuotaKey, f64>,
) -> Option<(&'a QuotaKey, f64)> {
    if let Some((key, value)) = limits.get_key_value(key) {
        return Some((key, *value));
    }
    if !key.limit_name.is_empty() {
        return None;
    }
    let mut candidates = limits.iter().filter(|(candidate, _)| {
        candidate.metric == key.metric && candidate.location == key.location
    });
    let (candidate, limit) = candidates.next()?;
    candidates.next().is_none().then_some((candidate, *limit))
}

fn vertex_windows(
    usage_series: &[MonitoringTimeSeries],
    limit_series: &[MonitoringTimeSeries],
    now: OffsetDateTime,
) -> Result<Vec<QuotaWindow>, ProviderError> {
    let usage = aggregate_monitoring(usage_series, MONITORING_USAGE_METRIC)?;
    let limits = aggregate_monitoring(limit_series, MONITORING_LIMIT_METRIC)?;
    let mut windows = Vec::new();
    for (key, used) in usage {
        let Some((limit_key, limit)) = matching_limit(&key, &limits) else {
            continue;
        };
        let limit_name = if key.limit_name.is_empty() {
            limit_key.limit_name.as_str()
        } else {
            key.limit_name.as_str()
        };
        windows.push(common::window(
            &format!(
                "Vertex AI quota {} ({}, {})",
                key.metric,
                if limit_name.is_empty() {
                    "unnamed limit"
                } else {
                    limit_name
                },
                key.location
            ),
            Some(used),
            Some(limit),
            None,
            "quota units",
            None,
            "gcp_monitoring_quota_24h_max",
            now,
        )?);
    }
    if windows.is_empty() {
        return Err(ProviderError::QuotaUnavailable);
    }
    Ok(windows)
}

async fn fetch_vertex_at(
    context: &ProviderContext,
    base: &str,
    token: &Secret,
    project: &str,
) -> Result<ProviderUsage, ProviderError> {
    if !valid_google_project(project) {
        return Err(ProviderError::InvalidData);
    }
    let usage = monitoring_series(context, base, token, project, MONITORING_USAGE_METRIC).await?;
    let limits = monitoring_series(context, base, token, project, MONITORING_LIMIT_METRIC).await?;
    let mut result = common::usage(
        "vertexai",
        token,
        project,
        vertex_windows(&usage, &limits, context.clock.now())?,
    )?;
    result.account.label = "Vertex AI OAuth token".into();
    Ok(result)
}

// Hash native credential material in memory; do not refresh OAuth during a cache lookup.
pub(super) async fn cache_identity(id: &str, context: &ProviderContext) -> Option<String> {
    let parts = match id {
        "kiro" => {
            if let Some(token) = context.credentials.get("KIRO_ACCESS_TOKEN") {
                let (region, profile) = kiro_metadata(context, None, None).ok()?;
                vec![token.0, region, profile.unwrap_or_default()]
            } else {
                let source = read_native_json(kiro_auth_path().ok()?).await.ok()??;
                let credential = parse_kiro_native(&source).ok()?;
                let (region, profile) = kiro_metadata(
                    context,
                    credential.region.as_deref(),
                    credential.profile_arn.as_deref(),
                )
                .ok()?;
                vec![
                    serde_json::to_string(&source).ok()?,
                    region,
                    profile.unwrap_or_default(),
                ]
            }
        }
        "vertexai" => {
            let project = vertex_project(context).await.ok()?;
            if let Some(token) = context.credentials.get("VERTEXAI_ACCESS_TOKEN") {
                vec![token.0, project]
            } else {
                let source = read_native_json(vertex_adc_path(context).ok()?)
                    .await
                    .ok()??;
                parse_vertex_adc(&source).ok()?;
                vec![serde_json::to_string(&source).ok()?, project]
            }
        }
        _ => return None,
    };
    Some(crate::cache::fingerprint(
        &parts.iter().map(String::as_str).collect::<Vec<_>>(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::http::fixture;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    fn token() -> Secret {
        Secret("synthetic-token".into())
    }

    fn temp_file(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "quotio-oauth-cloud-{name}-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[tokio::test]
    async fn native_cache_identity_tracks_credentials_and_project_without_refreshing() {
        struct Keys(std::collections::HashMap<String, String>);
        impl crate::providers::CredentialStore for Keys {
            fn get(&self, name: &str) -> Option<Secret> {
                self.0.get(name).cloned().map(Secret)
            }
        }
        let path = temp_file("cache-identity");
        let write = |token: &str| {
            fs::write(&path, serde_json::to_vec(&json!({
            "type": "authorized_user", "client_id": "fixture-client", "client_secret": "fixture-secret", "refresh_token": token
        })).unwrap()).unwrap()
        };
        let context = |project: &str| {
            let mut context = fixture::context();
            context.credentials = std::sync::Arc::new(Keys(
                [
                    (
                        "GOOGLE_APPLICATION_CREDENTIALS".into(),
                        path.to_string_lossy().into_owned(),
                    ),
                    ("VERTEXAI_PROJECT_ID".into(), project.into()),
                ]
                .into_iter()
                .collect(),
            ));
            context
        };
        write("fixture-refresh-a");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let first = cache_identity("vertexai", &context("project-one"))
            .await
            .unwrap();
        assert_eq!(
            first,
            cache_identity("vertexai", &context("project-one"))
                .await
                .unwrap()
        );
        assert_ne!(
            first,
            cache_identity("vertexai", &context("project-two"))
                .await
                .unwrap()
        );
        write("fixture-refresh-b");
        assert_ne!(
            first,
            cache_identity("vertexai", &context("project-one"))
                .await
                .unwrap()
        );
        assert!(!first.contains("fixture"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn native_credential_parsers_accept_only_supported_shapes() {
        let kiro = parse_kiro_native(&json!({
            "accessToken": "access",
            "refreshToken": "refresh",
            "clientId": "client",
            "clientSecret": "secret",
            "profileArn": "arn:aws:codewhisperer:ap-northeast-2:123:profile/test",
            "expiresAt": "2030-01-01T00:00:00Z"
        }))
        .unwrap();
        assert_eq!(kiro.region, None);
        assert_eq!(
            profile_region(kiro.profile_arn.as_deref().unwrap())
                .unwrap()
                .as_deref(),
            Some("ap-northeast-2")
        );

        let adc = parse_vertex_adc(&json!({
            "type": "authorized_user",
            "client_id": "client",
            "client_secret": "secret",
            "refresh_token": "refresh"
        }))
        .unwrap();
        assert_eq!(adc.client_id, "client");
        assert!(
            parse_vertex_adc(&json!({
                "type": "service_account",
                "private_key": "synthetic"
            }))
            .is_err()
        );
    }

    #[test]
    fn vertex_adc_requires_explicit_authorized_user_type() {
        for fixture in [
            json!({
                "client_id": "client",
                "client_secret": "secret",
                "refresh_token": "refresh"
            }),
            json!({
                "type": " authorized_user ",
                "client_id": "client",
                "client_secret": "secret",
                "refresh_token": "refresh"
            }),
        ] {
            assert!(parse_vertex_adc(&fixture).is_err());
        }
    }

    #[tokio::test]
    async fn native_file_reader_is_read_only() {
        let path = temp_file("native.json");
        let original = br#"{"accessToken":"synthetic"}"#;
        fs::write(&path, original).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let read = read_native_file(path.clone()).await.unwrap().unwrap();
        assert_eq!(read, original);
        assert_eq!(fs::read(&path).unwrap(), original);
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn native_file_reader_rejects_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let target = temp_file("native-target.json");
        let link = temp_file("native-link.json");
        fs::write(&target, br#"{"accessToken":"synthetic"}"#).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &link).unwrap();
        assert!(matches!(
            read_native_file(link.clone()).await,
            Err(ProviderError::CredentialStorage)
        ));
        fs::remove_file(link).unwrap();
        fs::remove_file(target).unwrap();
    }

    #[tokio::test]
    async fn kiro_refresh_and_usage_keep_requests_cookie_free() {
        let native = parse_kiro_native(&json!({
            "accessToken": "old-access",
            "refreshToken": "refresh",
            "authMethod": "Social"
        }))
        .unwrap();
        let (refresh_url, refresh_task) = fixture::server(vec![json!({
            "accessToken": "new-access",
            "expiresIn": 3600
        })])
        .await;
        let refreshed = refresh_kiro_at(&fixture::context(), native, &refresh_url)
            .await
            .unwrap();
        assert_eq!(refreshed.access_token, "new-access");
        let refresh_requests = refresh_task.await.unwrap();
        assert!(refresh_requests[0].starts_with("POST / HTTP/1.1"));
        assert!(refresh_requests[0].contains("refreshToken"));

        let (base, task) = fixture::server(vec![json!({
            "nextDateReset": 1_900_000_000i64,
            "subscriptionInfo": {"subscriptionTitle": "Kiro Pro"},
            "usageBreakdownList": [{
                "resourceType": "AGENTIC_REQUEST",
                "currentUsageWithPrecision": 20,
                "usageLimitWithPrecision": 100,
                "freeTrialInfo": {
                    "freeTrialStatus": "ACTIVE",
                    "currentUsage": 5,
                    "usageLimit": 10,
                    "freeTrialExpiry": 1_800_000_000i64
                }
            }]
        })])
        .await;
        let usage = fetch_kiro_at(
            &fixture::context(),
            &format!("{base}/getUsageLimits"),
            &token(),
            "ap-northeast-2",
            Some("arn:aws:codewhisperer:ap-northeast-2:123:profile/test"),
        )
        .await
        .unwrap();
        assert_eq!(usage.account.plan.as_deref(), Some("Kiro Pro"));
        assert_eq!(usage.windows.len(), 2);
        assert_eq!(usage.windows[0].consumption.as_ref().unwrap().used, 20.0);
        let requests = task.await.unwrap();
        assert!(requests[0].starts_with(
            "GET /getUsageLimits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST&profileArn="
        ));
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains("authorization: bearer synthetic-token")
        );
        assert!(requests[0].contains("amz-sdk-request: attempt=1; max=1"));
        assert!(requests[0].contains("KiroIDE-quotio-"));
        assert!(!requests[0].to_ascii_lowercase().contains("cookie:"));
    }

    #[test]
    fn kiro_does_not_invent_quota_from_an_empty_breakdown() {
        let result = kiro_windows(
            &json!({"usageBreakdownList": [{"resourceType": "AGENTIC_REQUEST"}]}),
            OffsetDateTime::UNIX_EPOCH,
        );
        assert!(matches!(result, Err(ProviderError::QuotaUnavailable)));
        assert!(!valid_kiro_region("us east 1"));
    }

    #[tokio::test]
    async fn vertex_refresh_and_monitoring_match_quota_series() {
        let adc = parse_vertex_adc(&json!({
            "type": "authorized_user",
            "client_id": "client",
            "client_secret": "secret",
            "refresh_token": "refresh"
        }))
        .unwrap();
        let (refresh_url, refresh_task) = fixture::server(vec![json!({
            "access_token": "new-access",
            "expires_in": 3600
        })])
        .await;
        let refreshed = refresh_vertex_at(&fixture::context(), &adc, &refresh_url)
            .await
            .unwrap();
        assert_eq!(refreshed.0, "new-access");
        let refresh_requests = refresh_task.await.unwrap();
        assert!(refresh_requests[0].starts_with("POST / HTTP/1.1"));
        assert!(refresh_requests[0].contains("grant_type=refresh_token"));

        let quota_metric = "aiplatform.googleapis.com/generate_content";
        let limit_name = "GenerateContentRequestsPerMinutePerProject";
        let series = |metric_type: &str, value: &str| {
            json!({"timeSeries": [{
                "metric": {"type": metric_type, "labels": {
                    "quota_metric": quota_metric,
                    "limit_name": limit_name
                }},
                "resource": {"type": "consumer_quota", "labels": {
                    "service": "aiplatform.googleapis.com",
                    "location": "us-central1"
                }},
                "points": [{"value": {"int64Value": value}}]
            }]})
        };
        let (base, task) = fixture::server(vec![
            series(MONITORING_USAGE_METRIC, "25"),
            series(MONITORING_LIMIT_METRIC, "100"),
        ])
        .await;
        let usage = fetch_vertex_at(&fixture::context(), &base, &token(), "demo-project")
            .await
            .unwrap();
        assert_eq!(usage.windows.len(), 1);
        assert_eq!(usage.windows[0].consumption.as_ref().unwrap().used, 25.0);
        assert_eq!(usage.windows[0].amounts.as_ref().unwrap().remaining, 75.0);
        let requests = task.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|request| request.starts_with("GET /v3/projects/demo-project/timeSeries?"))
        );
        assert!(requests.iter().all(|request| {
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer synthetic-token")
        }));
        assert!(
            requests
                .iter()
                .all(|request| !request.to_ascii_lowercase().contains("cookie:"))
        );
    }

    #[test]
    fn vertex_only_matches_an_unnamed_usage_series_when_unambiguous() {
        let quota_metric = "aiplatform.googleapis.com/generate_content";
        let usage = serde_json::from_value::<MonitoringPage>(json!({"timeSeries": [{
            "metric": {"type": MONITORING_USAGE_METRIC, "labels": {"quota_metric": quota_metric}},
            "resource": {"type": "consumer_quota", "labels": {"service": MONITORING_SERVICE, "location": "global"}},
            "points": [{"value": {"int64Value": "5"}}]
        }]}))
        .unwrap();
        let limits = serde_json::from_value::<MonitoringPage>(json!({"timeSeries": [
            {
                "metric": {"type": MONITORING_LIMIT_METRIC, "labels": {"quota_metric": quota_metric, "limit_name": "one"}},
                "resource": {"type": "consumer_quota", "labels": {"service": MONITORING_SERVICE, "location": "global"}},
                "points": [{"value": {"int64Value": "10"}}]
            },
            {
                "metric": {"type": MONITORING_LIMIT_METRIC, "labels": {"quota_metric": quota_metric, "limit_name": "two"}},
                "resource": {"type": "consumer_quota", "labels": {"service": MONITORING_SERVICE, "location": "global"}},
                "points": [{"value": {"int64Value": "20"}}]
            }
        ]}))
        .unwrap();
        assert!(matches!(
            vertex_windows(
                &usage.time_series,
                &limits.time_series,
                OffsetDateTime::UNIX_EPOCH
            ),
            Err(ProviderError::QuotaUnavailable)
        ));
    }

    #[tokio::test]
    async fn vertex_iam_denial_is_quota_unavailable() {
        let (base, task) = fixture::server_status(vec![(403, json!({}))]).await;
        let result = fetch_vertex_at(&fixture::context(), &base, &token(), "demo-project").await;
        assert!(matches!(result, Err(ProviderError::QuotaUnavailable)));
        task.await.unwrap();
    }

    #[test]
    fn definitions_describe_oauth_sources() {
        assert_eq!(DEFINITIONS.len(), 2);
        assert!(
            DEFINITIONS
                .iter()
                .all(|definition| definition.auth == AuthKind::OAuth)
        );
        assert!(valid_google_project("demo-project"));
        assert_eq!(
            project_from_config(b"[core]\nproject = demo-project\n")
                .unwrap()
                .as_deref(),
            Some("demo-project")
        );
    }
}
