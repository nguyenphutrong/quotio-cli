use super::{ProviderContext, http};
use crate::{accounts::Credential, domain::*, error::ProviderError};
use serde_json::{Value, json};

fn translated_window(value: Option<&Value>) -> Result<Value, ProviderError> {
    let Some(value) = value.filter(|v| !v.is_null()) else {
        return Ok(Value::Null);
    };
    if !value.is_object() {
        return Err(ProviderError::InvalidData);
    }
    let seconds = value.get("limit_window_seconds").filter(|v| !v.is_null());
    let minutes = seconds
        .map(|v| v.as_u64().ok_or(ProviderError::InvalidData).map(|s| s / 60))
        .transpose()?;
    Ok(
        json!({"usedPercent":value.get("used_percent"),"windowDurationMins":minutes,"resetsAt":value.get("reset_at")}),
    )
}
fn translated_rate(value: &Value, name: &str) -> Result<Value, ProviderError> {
    Ok(
        json!({"limitName":name,"primary":translated_window(value.get("primary_window"))?,"secondary":translated_window(value.get("secondary_window"))?}),
    )
}
pub(crate) fn parse(
    value: Value,
    email: &str,
    now: time::OffsetDateTime,
) -> Result<ProviderUsage, ProviderError> {
    let mut buckets = serde_json::Map::new();
    if let Some(rate) = value.get("rate_limit").filter(|v| !v.is_null()) {
        buckets.insert("codex".into(), translated_rate(rate, "codex")?);
    }
    if let Some(additional) = value.get("additional_rate_limits").filter(|v| !v.is_null()) {
        for (index, entry) in additional
            .as_array()
            .ok_or(ProviderError::InvalidData)?
            .iter()
            .enumerate()
        {
            let name = entry
                .get("limit_name")
                .and_then(Value::as_str)
                .ok_or(ProviderError::InvalidData)?;
            let name = if name.to_lowercase().contains("spark") {
                "Codex Spark"
            } else {
                name
            };
            let rate = entry.get("rate_limit").ok_or(ProviderError::InvalidData)?;
            buckets.insert(format!("additional_{index}"), translated_rate(rate, name)?);
        }
    }
    if buckets.is_empty() {
        return Err(ProviderError::InvalidData);
    }
    let mut usage = super::codex::parse_direct(email, json!({"rateLimitsByLimitId":buckets}), now)?;
    // Keep the main Codex windows first, followed by model-specific limits.
    usage
        .windows
        .sort_by_key(|w| !matches!(w.label.as_str(), "Session" | "Weekly"));
    for w in &mut usage.windows {
        w.provenance.source = "codex_api".into();
    }
    Ok(usage)
}
pub async fn fetch(
    context: &ProviderContext,
    credential: &Credential,
) -> Result<ProviderUsage, ProviderError> {
    fetch_at(
        context,
        credential,
        "https://chatgpt.com/backend-api/wham/usage",
    )
    .await
}
async fn fetch_at(
    context: &ProviderContext,
    credential: &Credential,
    endpoint: &str,
) -> Result<ProviderUsage, ProviderError> {
    let Credential::CodexOAuth {
        access_token,
        account_id,
        email,
        ..
    } = credential
    else {
        return Err(ProviderError::Authentication);
    };
    let value = http::json(
        context
            .http
            .get(endpoint)
            .header(
                "Authorization",
                http::sensitive(&format!("Bearer {access_token}"))?,
            )
            .header("ChatGPT-Account-Id", http::sensitive(account_id)?)
            .header("Accept", "application/json"),
        context.clock.now(),
    )
    .await?;
    let mut usage = parse(value, email, context.clock.now())?;
    usage.account.id = account_id.clone();
    Ok(usage)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn direct_quota_preserves_identity_headers_and_sparse_windows() {
        let (url,task)=http::fixture::server(vec![json!({"rate_limit":{"primary_window":{"used_percent":20,"limit_window_seconds":604800}},"additional_rate_limits":[{"limit_name":"GPT Spark","rate_limit":{"primary_window":{"used_percent":0,"limit_window_seconds":18000}}}]})]).await;
        let credential = Credential::CodexOAuth {
            access_token: "synthetic-token".into(),
            refresh_token: "refresh".into(),
            id_token: "id".into(),
            account_id: "workspace-a".into(),
            email: "demo@example.com".into(),
            expires_at: 0,
        };
        let usage = fetch_at(&http::fixture::context(), &credential, &url)
            .await
            .unwrap();
        assert_eq!(usage.windows.len(), 2);
        assert_eq!(usage.windows[0].label, "Weekly");
        assert_eq!(usage.windows[1].label, "Codex Spark Session");
        assert_eq!(usage.account.id, "workspace-a");
        let req = task.await.unwrap();
        assert!(
            req[0]
                .to_lowercase()
                .contains("chatgpt-account-id: workspace-a")
        );
        assert!(req[0].contains("Bearer synthetic-token"));
        assert!(!req[0].to_lowercase().contains("cookie:"));
    }
}
