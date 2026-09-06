//! OpenRouter account credits and key usage, using the existing explicit API-key source.
use crate::{
    domain::{ProviderUsage, UsageDiagnostic},
    error::ProviderError,
    providers::{ProviderContext, catalog::common, http, key_api},
};
use serde_json::Value;

pub async fn fetch(context: &ProviderContext) -> Result<ProviderUsage, ProviderError> {
    fetch_at(
        context,
        "https://openrouter.ai/api/v1/credits",
        "https://openrouter.ai/api/v1/key",
    )
    .await
}
async fn fetch_at(
    context: &ProviderContext,
    credits_url: &str,
    key_url: &str,
) -> Result<ProviderUsage, ProviderError> {
    let key = common::key(context, "OPENROUTER_API_KEY")?;
    let now = context.clock.now();
    let endpoint = |url: &str| -> Result<_, ProviderError> {
        Ok(context
            .http
            .get(url)
            .header(
                "Authorization",
                http::sensitive(&format!("Bearer {}", key.0))?,
            )
            .header("Accept", "application/json"))
    };
    let (credits, key_data) = tokio::join!(
        http::json::<Value>(endpoint(credits_url)?, now),
        http::json::<Value>(endpoint(key_url)?, now)
    );
    let mut windows = Vec::new();
    let mut diagnostics = Vec::new();
    let mut plan = None;
    match credits.and_then(|root| credits_windows(&root, now)) {
        Ok(values) => windows.extend(values),
        Err(code) => diagnostics.push(UsageDiagnostic {
            source: "openrouter_credits_api".into(),
            code,
        }),
    }
    match key_data {
        Ok(root) => {
            match key_api::openrouter(&root, now) {
                Ok(values) => windows.extend(values),
                Err(code) => diagnostics.push(UsageDiagnostic {
                    source: "openrouter_key_api".into(),
                    code,
                }),
            }
            plan = root
                .pointer("/data/is_free_tier")
                .and_then(|v| {
                    v.as_bool()
                        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                })
                .map(|free| {
                    if free {
                        "openrouter-free"
                    } else {
                        "openrouter-pay-as-you-go"
                    }
                    .to_owned()
                });
        }
        Err(code) => diagnostics.push(UsageDiagnostic {
            source: "openrouter_key_api".into(),
            code,
        }),
    }
    if windows.is_empty() {
        return Err(
            if diagnostics
                .iter()
                .any(|d| d.code == ProviderError::Authentication)
            {
                ProviderError::Authentication
            } else {
                diagnostics
                    .first()
                    .map(|d| d.code)
                    .unwrap_or(ProviderError::InvalidData)
            },
        );
    }
    let mut usage = common::usage("openrouter", &key, "global", windows)?;
    usage.account.plan = plan;
    usage.account.label = "OpenRouter API key".into();
    usage.diagnostics = diagnostics;
    Ok(usage)
}
fn credits_windows(
    root: &Value,
    now: time::OffsetDateTime,
) -> Result<Vec<crate::domain::QuotaWindow>, ProviderError> {
    let payload = root.get("data").unwrap_or(root);
    let purchased = common::number(payload.get("total_credits"))?;
    let used = common::number(payload.get("total_usage"))?;
    let balance = common::number(payload.get("balance"))?.or_else(|| {
        purchased
            .zip(used)
            .map(|(limit, used)| (limit - used).max(0.0))
    });
    let mut windows = Vec::new();
    if purchased.is_some_and(|v| v > 0.0) && used.is_some() {
        windows.push(common::window(
            "Account credits",
            used,
            purchased,
            None,
            "USD",
            None,
            "openrouter_credits_api",
            now,
        )?);
    }
    if let Some(balance) = balance {
        windows.push(common::window(
            "Credit balance",
            None,
            None,
            Some(balance),
            "USD",
            None,
            "openrouter_credits_api",
            now,
        )?);
    }
    if windows.is_empty() {
        return Err(ProviderError::InvalidData);
    }
    Ok(windows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{CredentialStore, Secret};
    use serde_json::json;
    use std::sync::Arc;
    struct Keys;
    impl CredentialStore for Keys {
        fn get(&self, key: &str) -> Option<Secret> {
            (key == "OPENROUTER_API_KEY").then(|| Secret("fixture-openrouter-secret".into()))
        }
    }
    #[tokio::test]
    async fn combines_two_endpoints_without_serializing_secret_and_keeps_partial_success() {
        let mut context = http::fixture::context();
        context.credentials = Arc::new(Keys);
        let (credits, credit_requests) = http::fixture::server(vec![
            json!({"data":{"total_credits":100.25,"total_usage":40.1}}),
        ])
        .await;
        let (key, key_requests) =
            http::fixture::server_status(vec![(503, json!({"error":"fixture-openrouter-secret"}))])
                .await;
        let usage = fetch_at(&context, &credits, &key).await.unwrap();
        assert_eq!(usage.windows.len(), 2);
        assert!((usage.windows[1].amounts.as_ref().unwrap().remaining - 60.15).abs() < 1e-9);
        assert_eq!(usage.diagnostics[0].code, ProviderError::Transient);
        assert!(
            !serde_json::to_string(&usage)
                .unwrap()
                .contains("fixture-openrouter-secret")
        );
        assert!(credit_requests.await.unwrap()[0].contains("Bearer fixture-openrouter-secret"));
        key_requests.await.unwrap();
    }
    #[test]
    fn zero_balance_is_known_but_missing_credit_total_is_not_zero() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let windows =
            credits_windows(&json!({"data":{"total_credits":0,"total_usage":0}}), now).unwrap();
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].amounts.as_ref().unwrap().remaining, 0.0);
        assert!(credits_windows(&json!({"data":{"total_usage":3}}), now).is_err());
    }
}
