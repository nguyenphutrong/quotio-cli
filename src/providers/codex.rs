use super::{FetchFuture, ProviderAdapter, ProviderContext, process};
use crate::{domain::*, error::ProviderError};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf};
use time::OffsetDateTime;
use tokio::io::{AsyncWriteExt, BufReader};

pub struct CodexProvider {
    pub executable: PathBuf,
}
impl Default for CodexProvider {
    fn default() -> Self {
        Self {
            executable: "codex".into(),
        }
    }
}
#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Account {
    #[serde(rename = "type")]
    kind: String,
    email: Option<String>,
    plan_type: Option<String>,
}
#[derive(Deserialize)]
struct AccountResponse {
    account: Option<Account>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Window {
    used_percent: Option<f64>,
    window_duration_mins: Option<u64>,
    resets_at: Option<i64>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Bucket {
    limit_id: Option<String>,
    limit_name: Option<String>,
    primary: Option<Window>,
    secondary: Option<Window>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Limits {
    rate_limits: Option<Bucket>,
    rate_limits_by_limit_id: Option<BTreeMap<String, Bucket>>,
}

fn account(value: Value) -> Result<Account, ProviderError> {
    let value: AccountResponse =
        serde_json::from_value(value).map_err(|_| ProviderError::InvalidData)?;
    let account = value.account.ok_or(ProviderError::Authentication)?;
    if account.kind != "chatgpt" {
        return Err(ProviderError::Authentication);
    }
    if account
        .email
        .as_ref()
        .is_none_or(|email| email.trim().is_empty())
    {
        return Err(ProviderError::InvalidData);
    }
    Ok(account)
}
fn parse(
    account: Account,
    value: Value,
    now: OffsetDateTime,
) -> Result<ProviderUsage, ProviderError> {
    let limits: Limits = serde_json::from_value(value).map_err(|_| ProviderError::InvalidData)?;
    let buckets = match limits.rate_limits_by_limit_id {
        Some(map) if !map.is_empty() => map,
        _ => {
            let bucket = limits.rate_limits.ok_or(ProviderError::InvalidData)?;
            BTreeMap::from([(
                bucket.limit_id.clone().unwrap_or_else(|| "codex".into()),
                bucket,
            )])
        }
    };
    let mut windows = Vec::new();
    for (id, bucket) in buckets {
        let name = bucket.limit_name.filter(|s| !s.is_empty()).unwrap_or(id);
        for (slot, window) in [("primary", bucket.primary), ("secondary", bucket.secondary)] {
            let (quota, reset, duration) = match window {
                Some(window) => (
                    Quota::from_used(window.used_percent),
                    window
                        .resets_at
                        .map(OffsetDateTime::from_unix_timestamp)
                        .transpose()
                        .map_err(|_| ProviderError::InvalidData)?,
                    window.window_duration_mins,
                ),
                None => (Quota::Unknown, None, None),
            };
            let label = match duration {
                Some(minutes) => format!("{name} {slot} ({minutes} min)"),
                None => format!("{name} {slot}"),
            };
            let confidence = if quota == Quota::Unknown {
                Confidence::Unknown
            } else {
                Confidence::Exact
            };
            windows.push(QuotaWindow {
                amounts: None,
                label,
                quota,
                resets_at: reset,
                fetched_at: now,
                provenance: Provenance {
                    source: "codex_app_server".into(),
                    confidence,
                },
            });
        }
    }
    let email = account.email.ok_or(ProviderError::InvalidData)?;
    Ok(ProviderUsage {
        provider: ProviderId("codex".into()),
        account: AccountIdentity {
            id: email.clone(),
            label: email,
        },
        windows,
    })
}
async fn rpc(
    reader: &mut BufReader<tokio::process::ChildStdout>,
    writer: &mut tokio::process::ChildStdin,
    id: u64,
    method: &str,
    params: Value,
) -> Result<Value, ProviderError> {
    let request = format!("{}\n", json!({"id":id,"method":method,"params":params}));
    writer
        .write_all(request.as_bytes())
        .await
        .map_err(|_| ProviderError::Unavailable)?;
    // Notifications are allowed, but a peer cannot flood us indefinitely.
    for _ in 0..128 {
        let value: Value = serde_json::from_slice(&process::line(reader).await?)
            .map_err(|_| ProviderError::InvalidData)?;
        if value.get("id").and_then(Value::as_u64) != Some(id) {
            continue;
        }
        if value.get("error").is_some() {
            return Err(ProviderError::Unavailable);
        }
        return value
            .get("result")
            .cloned()
            .ok_or(ProviderError::InvalidData);
    }
    Err(ProviderError::InvalidData)
}
impl ProviderAdapter for CodexProvider {
    fn id(&self) -> ProviderId {
        ProviderId("codex".into())
    }
    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> FetchFuture<'a> {
        Box::pin(async move {
            let mut child = process::spawn(&self.executable, &["app-server", "--stdio"])?;
            let mut writer = child.stdin.take().ok_or(ProviderError::Internal)?;
            let mut reader = BufReader::new(child.stdout.take().ok_or(ProviderError::Internal)?);
            rpc(&mut reader, &mut writer, 1, "initialize", json!({"clientInfo":{"name":"quotio","version":env!("CARGO_PKG_VERSION")},"capabilities":{"experimentalApi":false}})).await?;
            writer
                .write_all(b"{\"method\":\"initialized\"}\n")
                .await
                .map_err(|_| ProviderError::Unavailable)?;
            let before = account(
                rpc(
                    &mut reader,
                    &mut writer,
                    2,
                    "account/read",
                    json!({"refreshToken":false}),
                )
                .await?,
            )?;
            let limits = rpc(
                &mut reader,
                &mut writer,
                3,
                "account/rateLimits/read",
                json!({}),
            )
            .await?;
            let after = account(
                rpc(
                    &mut reader,
                    &mut writer,
                    4,
                    "account/read",
                    json!({"refreshToken":false}),
                )
                .await?,
            )?;
            if before != after {
                return Err(ProviderError::InvalidData);
            }
            let result = parse(after, limits, context.clock.now());
            child.kill().await.map_err(|_| ProviderError::Unavailable)?;
            result
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> Account {
        account(json!({"account":{"type":"chatgpt","email":"demo@example.com","planType":"pro"}}))
            .unwrap()
    }
    #[test]
    fn prefer_all_buckets_and_keep_missing_unknown() {
        let report = parse(identity(), json!({"rateLimits":{"primary":{"usedPercent":90}},"rateLimitsByLimitId":{"a":{"primary":{"usedPercent":25,"windowDurationMins":300,"resetsAt":1780000000}},"b":{"primary":{"usedPercent":100},"secondary":{"usedPercent":0}}}}), OffsetDateTime::UNIX_EPOCH).unwrap();
        assert_eq!(report.windows.len(), 4);
        assert_eq!(report.windows[0].quota, Quota::from_used(Some(25.0)));
        assert_eq!(report.windows[1].quota, Quota::Unknown);
        assert_eq!(report.windows[2].quota, Quota::from_used(Some(100.0)));
    }
    #[test]
    fn reject_unknown_identity_and_invalid_payload() {
        assert!(account(json!({"account":{"type":"chatgpt"}})).is_err());
        assert!(parse(identity(), json!({}), OffsetDateTime::UNIX_EPOCH).is_err());
        assert!(
            parse(
                identity(),
                json!({"rateLimits":{"primary":{"usedPercent":"bad"}}}),
                OffsetDateTime::UNIX_EPOCH
            )
            .is_err()
        );
    }
}
