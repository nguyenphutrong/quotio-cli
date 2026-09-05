use super::{FetchFuture, ProviderAdapter, ProviderContext, Secret, http};
use crate::{domain::*, error::ProviderError};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const BASE: &str = "https://cloudcode-pa.googleapis.com/v1internal:";
pub struct AntigravityProvider {
    pub auth_directory: Option<PathBuf>,
}
impl Default for AntigravityProvider {
    fn default() -> Self {
        Self {
            auth_directory: directories::BaseDirs::new()
                .map(|dirs| dirs.home_dir().join(".cli-proxy-api")),
        }
    }
}
#[derive(Deserialize)]
struct AuthFile {
    access_token: String,
}
fn read_auth(path: &Path) -> Result<Secret, ProviderError> {
    let before = std::fs::symlink_metadata(path).map_err(|_| ProviderError::Authentication)?;
    if !before.is_file() || before.is_symlink() || before.len() > 1024 * 1024 {
        return Err(ProviderError::Authentication);
    }
    let file = std::fs::File::open(path).map_err(|_| ProviderError::Authentication)?;
    let opened = file.metadata().map_err(|_| ProviderError::Authentication)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(ProviderError::Authentication);
        }
    }
    if !opened.is_file() {
        return Err(ProviderError::Authentication);
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProviderError::Authentication)?;
    if bytes.len() > 1024 * 1024 {
        return Err(ProviderError::Authentication);
    }
    let auth: AuthFile =
        serde_json::from_slice(&bytes).map_err(|_| ProviderError::Authentication)?;
    if auth.access_token.trim().is_empty() {
        return Err(ProviderError::Authentication);
    }
    Ok(Secret(auth.access_token))
}
impl AntigravityProvider {
    fn token(&self, context: &ProviderContext) -> Result<Secret, ProviderError> {
        if let Some(token) = context.credentials.get("ANTIGRAVITY_ACCESS_TOKEN") {
            return if token.0.trim().is_empty() {
                Err(ProviderError::Authentication)
            } else {
                Ok(token)
            };
        }
        if let Some(path) = context.credentials.get("ANTIGRAVITY_AUTH_FILE") {
            return read_auth(Path::new(&path.0));
        }
        let directory = self
            .auth_directory
            .as_ref()
            .ok_or(ProviderError::Authentication)?;
        let entries = std::fs::read_dir(directory).map_err(|_| ProviderError::Authentication)?;
        let mut paths = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| ProviderError::Authentication)?;
            let name = entry.file_name();
            if name
                .to_str()
                .is_some_and(|name| name.starts_with("antigravity-") && name.ends_with(".json"))
            {
                paths.push(entry.path());
            }
        }
        if paths.len() != 1 {
            return Err(ProviderError::Authentication);
        }
        read_auth(&paths[0])
    }
}
#[derive(Deserialize, PartialEq)]
struct Identity {
    id: String,
    email: String,
}
fn identity_valid(identity: &Identity) -> bool {
    !identity.id.trim().is_empty() && !identity.email.trim().is_empty()
}
fn field<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| value.get(key))
}
fn string(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str).filter(|s| !s.is_empty())
}
fn fraction(value: Option<&Value>) -> Result<Option<f64>, ProviderError> {
    let Some(value) = value.filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let n = value
        .as_f64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
        .ok_or(ProviderError::InvalidData)?;
    if !n.is_finite() || !(0.0..=1.0).contains(&n) {
        return Err(ProviderError::InvalidData);
    }
    Ok(Some(n))
}
fn window(
    label: String,
    remaining: Option<f64>,
    reset: Option<&Value>,
    source: &str,
    now: OffsetDateTime,
) -> Result<QuotaWindow, ProviderError> {
    let reset = match reset {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::String(s)) => {
            Some(OffsetDateTime::parse(s, &Rfc3339).map_err(|_| ProviderError::InvalidData)?)
        }
        _ => return Err(ProviderError::InvalidData),
    };
    Ok(QuotaWindow {
        label,
        quota: Quota::from_remaining(remaining.map(|v| v * 100.0)),
        amounts: None,
        resets_at: reset,
        fetched_at: now,
        provenance: Provenance {
            source: source.into(),
            confidence: if remaining.is_some() {
                Confidence::Exact
            } else {
                Confidence::Unknown
            },
        },
    })
}
fn summary(value: &Value, now: OffsetDateTime) -> Result<Vec<QuotaWindow>, ProviderError> {
    let groups = value
        .get("groups")
        .or_else(|| value.pointer("/response/groups"))
        .or_else(|| value.pointer("/summary/groups"))
        .and_then(Value::as_array)
        .ok_or(ProviderError::InvalidData)?;
    let mut windows = Vec::new();
    for group in groups {
        let name =
            string(field(group, &["displayName", "name"])).ok_or(ProviderError::InvalidData)?;
        for bucket in group
            .get("buckets")
            .and_then(Value::as_array)
            .ok_or(ProviderError::InvalidData)?
        {
            if bucket.get("disabled").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let label = string(field(
                bucket,
                &["bucketId", "id", "displayName", "name", "window"],
            ))
            .ok_or(ProviderError::InvalidData)?;
            let remaining =
                field(bucket, &["remainingFraction", "remaining_fraction"]).or_else(|| {
                    bucket.get("remaining").and_then(|r| {
                        field(r, &["remainingFraction", "remaining_fraction"]).or_else(|| {
                            if string(r.get("case")) == Some("remainingFraction") {
                                r.get("value")
                            } else {
                                None
                            }
                        })
                    })
                });
            windows.push(window(
                format!("{name} {label}"),
                fraction(remaining)?,
                field(bucket, &["resetTime", "reset_time", "resetAt", "reset_at"]),
                "antigravity_api_summary",
                now,
            )?);
        }
    }
    if windows.is_empty() {
        return Err(ProviderError::InvalidData);
    }
    Ok(windows)
}
fn models(value: Value, now: OffsetDateTime) -> Result<Vec<QuotaWindow>, ProviderError> {
    let models: BTreeMap<String, Value> = serde_json::from_value(
        value
            .get("models")
            .cloned()
            .ok_or(ProviderError::InvalidData)?,
    )
    .map_err(|_| ProviderError::InvalidData)?;
    let mut windows = Vec::new();
    for (id, model) in models {
        let label = string(model.get("displayName")).unwrap_or(&id).to_owned();
        let info = model.get("quotaInfo");
        windows.push(window(
            label,
            fraction(info.and_then(|i| i.get("remainingFraction")))?,
            info.and_then(|i| i.get("resetTime")),
            "antigravity_api_models",
            now,
        )?);
    }
    if windows.is_empty() {
        return Err(ProviderError::InvalidData);
    }
    Ok(windows)
}
impl ProviderAdapter for AntigravityProvider {
    fn id(&self) -> ProviderId {
        ProviderId("antigravity".into())
    }
    fn idempotent(&self) -> bool {
        true
    }
    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> FetchFuture<'a> {
        Box::pin(async move {
            let token = self.token(context)?;
            let authorization = http::sensitive(&format!("Bearer {}", token.0))?;
            let before: Identity = http::json(
                context
                    .http
                    .get("https://www.googleapis.com/oauth2/v2/userinfo")
                    .header("Authorization", authorization.clone()),
                context.clock.now(),
            )
            .await?;
            if !identity_valid(&before) {
                return Err(ProviderError::InvalidData);
            }
            let post = |method: &str, payload: Value| {
                context
                    .http
                    .post(format!("{BASE}{method}"))
                    .header("Authorization", authorization.clone())
                    .header("User-Agent", "quotio-cli/0.1.0")
                    .json(&payload)
            };
            let subscription: Value = http::json(
                post(
                    "loadCodeAssist",
                    json!({"metadata":{"ideType":"ANTIGRAVITY"}}),
                ),
                context.clock.now(),
            )
            .await?;
            let project = subscription.get("cloudaicompanionProject");
            let project = match project {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) => Some(s.as_str()),
                Some(value) => string(value.get("id")),
            };
            let payload = project
                .map(|p| json!({"project":p}))
                .unwrap_or_else(|| json!({}));
            let result: Result<Value, _> = http::json(
                post("retrieveUserQuotaSummary", payload.clone()),
                context.clock.now(),
            )
            .await;
            let windows = match result {
                Ok(value) => match summary(&value, context.clock.now()) {
                    Ok(windows) => windows,
                    Err(_) => models(
                        http::json(post("fetchAvailableModels", payload), context.clock.now())
                            .await?,
                        context.clock.now(),
                    )?,
                },
                Err(ProviderError::Unavailable | ProviderError::InvalidData) => models(
                    http::json(post("fetchAvailableModels", payload), context.clock.now()).await?,
                    context.clock.now(),
                )?,
                Err(error) => return Err(error),
            };
            Ok(ProviderUsage {
                provider: self.id(),
                account: AccountIdentity {
                    id: before.id,
                    label: before.email,
                },
                windows,
            })
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn summary_keeps_groups_windows_and_unknown() {
        let value = json!({"groups":[{"displayName":"Gemini","buckets":[{"bucketId":"session","remainingFraction":0.25},{"bucketId":"weekly","remaining":{"case":"remainingFraction","value":"0.75"}}]},{"name":"Claude","buckets":[{"name":"weekly"}]}]});
        let windows = summary(&value, OffsetDateTime::UNIX_EPOCH).unwrap();
        assert_eq!(windows.len(), 3);
        assert_eq!(windows[0].quota, Quota::from_used(Some(75.0)));
        assert_eq!(windows[1].quota, Quota::from_used(Some(25.0)));
        assert_eq!(windows[2].quota, Quota::Unknown);
    }
    #[test]
    fn model_fallback_preserves_missing_quota() {
        let windows = models(
            json!({"models":{"a":{"quotaInfo":{"remainingFraction":0}},"b":{}}}),
            OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap();
        assert_eq!(windows[0].quota, Quota::from_used(Some(100.0)));
        assert_eq!(windows[1].quota, Quota::Unknown);
        assert!(
            models(
                json!({"models":{"a":{"quotaInfo":{"remainingFraction":"bad"}}}}),
                OffsetDateTime::UNIX_EPOCH
            )
            .is_err()
        );
        assert!(summary(&json!({"groups":[]}), OffsetDateTime::UNIX_EPOCH).is_err());
    }
}
