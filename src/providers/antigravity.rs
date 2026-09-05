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
impl AntigravityProvider {
    async fn fetch_api(
        &self,
        context: &ProviderContext,
        base: &str,
        user_info: &str,
    ) -> Result<ProviderUsage, ProviderError> {
        let token = self.token(context)?;
        let authorization = http::sensitive(&format!("Bearer {}", token.0))?;
        let before: Identity = http::json(
            context
                .http
                .get(user_info)
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
                .post(format!("{base}{method}"))
                .header("Authorization", authorization.clone())
                .header("User-Agent", "quotio-cli/0.1.0")
                .json(&payload)
        };
        let subscription: Result<Value, _> = http::json(
            post(
                "loadCodeAssist",
                json!({"metadata":{"ideType":"ANTIGRAVITY"}}),
            ),
            context.clock.now(),
        )
        .await;
        let subscription = match subscription {
            Ok(value) => value,
            Err(ProviderError::Unavailable | ProviderError::InvalidData) => json!({}),
            Err(error) => return Err(error),
        };
        let project = subscription.get("cloudaicompanionProject");
        let project = match project {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.as_str()),
            Some(value) => string(value.get("id")),
        };
        let payload = project
            .map(|p| json!({"project":p}))
            .unwrap_or_else(|| json!({}));
        let attempts = if project.is_some() {
            vec![payload.clone(), json!({})]
        } else {
            vec![payload.clone()]
        };
        let mut selected = None;
        for body in attempts {
            let result: Result<Value, _> =
                http::json(post("retrieveUserQuotaSummary", body), context.clock.now()).await;
            match result {
                Ok(value) => {
                    if let Ok(windows) = summary(&value, context.clock.now()) {
                        selected = Some(windows);
                        break;
                    }
                }
                Err(ProviderError::Unavailable | ProviderError::InvalidData) => (),
                Err(error) => return Err(error),
            }
        }
        let windows = match selected {
            Some(windows) => windows,
            None => models(
                http::json(post("fetchAvailableModels", payload), context.clock.now()).await?,
                context.clock.now(),
            )?,
        };
        Ok(ProviderUsage {
            account_ref: None,
            provider: self.id(),
            account: AccountIdentity {
                plan: None,
                id: before.id,
                label: before.email,
            },
            windows,
        })
    }
}
impl ProviderAdapter for AntigravityProvider {
    fn id(&self) -> ProviderId {
        ProviderId("antigravity".into())
    }
    fn idempotent(&self) -> bool {
        true
    }
    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> FetchFuture<'a> {
        Box::pin(self.fetch_api(
            context,
            BASE,
            "https://www.googleapis.com/oauth2/v2/userinfo",
        ))
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
    #[tokio::test]
    async fn direct_api_sequence_and_fallback_use_same_credential() {
        let (base, task) = http::fixture::server(vec![
            json!({"id":"demo-id","email":"demo@example.com"}),
            json!({"cloudaicompanionProject":"demo-project"}),
            json!({}),
            json!({}),
            json!({"models":{"test-model":{"quotaInfo":{"remainingFraction":0.5}}}}),
        ])
        .await;
        let provider = AntigravityProvider {
            auth_directory: None,
        };
        let context = http::fixture::context();
        let usage = provider
            .fetch_api(
                &context,
                &format!("{base}/v1internal:"),
                &format!("{base}/userinfo"),
            )
            .await
            .unwrap();
        assert_eq!(usage.windows[0].provenance.source, "antigravity_api_models");
        let requests = task.await.unwrap();
        assert!(requests[0].starts_with("GET /userinfo "));
        for (request, method) in requests[1..].iter().zip([
            "loadCodeAssist",
            "retrieveUserQuotaSummary",
            "retrieveUserQuotaSummary",
            "fetchAvailableModels",
        ]) {
            assert!(request.starts_with(&format!("POST /v1internal:{method} ")));
        }
        assert!(
            requests
                .iter()
                .all(|r| r.contains("Bearer synthetic-token"))
        );
        assert!(requests[2].contains("demo-project"));
        assert!(requests[3].ends_with("{}"));
        assert!(requests[4].contains("demo-project"));
    }
    #[tokio::test]
    async fn optional_subscription_and_projectless_summary_are_supported() {
        for unavailable in [false, true] {
            let mut responses = vec![(200, json!({"id":"demo-id","email":"demo@example.com"}))];
            if unavailable {
                responses.push((404, json!({})));
            } else {
                responses.extend([
                    (200, json!({"cloudaicompanionProject":"demo-project"})),
                    (200, json!({})),
                ]);
            }
            responses.push((200,json!({"groups":[{"name":"Gemini","buckets":[{"name":"weekly","remainingFraction":0.5}]}]})));
            let (base, task) = http::fixture::server_status(responses).await;
            let provider = AntigravityProvider {
                auth_directory: None,
            };
            let context = http::fixture::context();
            let usage = provider
                .fetch_api(
                    &context,
                    &format!("{base}/v1internal:"),
                    &format!("{base}/userinfo"),
                )
                .await
                .unwrap();
            assert_eq!(
                usage.windows[0].provenance.source,
                "antigravity_api_summary"
            );
            let requests = task.await.unwrap();
            assert!(
                requests
                    .last()
                    .unwrap()
                    .starts_with("POST /v1internal:retrieveUserQuotaSummary ")
            );
            assert!(requests.last().unwrap().ends_with("{}"));
        }
    }
    #[tokio::test]
    async fn auth_and_rate_limits_do_not_trigger_source_fallback() {
        for (status, expected) in [
            (401, ProviderError::Authentication),
            (429, ProviderError::RateLimited),
        ] {
            let (base, task) = http::fixture::server_status(vec![
                (200, json!({"id":"demo-id","email":"demo@example.com"})),
                (status, json!({})),
            ])
            .await;
            let context = http::fixture::context();
            let provider = AntigravityProvider {
                auth_directory: None,
            };
            let result = provider
                .fetch_api(
                    &context,
                    &format!("{base}/v1internal:"),
                    &format!("{base}/userinfo"),
                )
                .await;
            assert_eq!(result.unwrap_err(), expected);
            assert_eq!(task.await.unwrap().len(), 2);
        }
    }
    #[test]
    fn credential_files_are_bounded_and_never_rewritten() {
        let directory =
            std::env::temp_dir().join(format!("quotio-antigravity-auth-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("auth.json");
        let contents = br#"{"access_token":"synthetic-token","refresh_token":"untouched"}"#;
        std::fs::write(&path, contents).unwrap();
        assert_eq!(read_auth(&path).unwrap().0, "synthetic-token");
        assert_eq!(std::fs::read(&path).unwrap(), contents);
        #[cfg(unix)]
        {
            let link = directory.join("link.json");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(matches!(
                read_auth(&link),
                Err(ProviderError::Authentication)
            ));
            std::fs::remove_file(link).unwrap();
        }
        std::fs::write(&path, vec![b'a'; 1024 * 1024 + 1]).unwrap();
        assert!(matches!(
            read_auth(&path),
            Err(ProviderError::Authentication)
        ));
        std::fs::write(&path, b"not-json-sentinel").unwrap();
        assert!(matches!(
            read_auth(&path),
            Err(ProviderError::Authentication)
        ));
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
