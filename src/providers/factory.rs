use super::{FetchFuture, ProviderAdapter, ProviderContext, http};
use crate::{domain::*, error::ProviderError};
use serde::Deserialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub struct FactoryProvider;
#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Identity {
    user_id: String,
    org_id: String,
    region: Option<String>,
    #[serde(default)]
    is_on_prem: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Response {
    limits: Limits,
    extra_usage_balance_cents: Option<f64>,
}
#[derive(Deserialize)]
struct Limits {
    standard: Option<Pool>,
    core: Option<Pool>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pool {
    five_hour: Option<Window>,
    weekly: Option<Window>,
    monthly: Option<Window>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Window {
    used_percent: Option<f64>,
    window_end: Option<String>,
}
fn parse(
    identity: Identity,
    response: Response,
    now: OffsetDateTime,
) -> Result<ProviderUsage, ProviderError> {
    if identity.user_id.trim().is_empty()
        || identity.org_id.trim().is_empty()
        || identity.is_on_prem
    {
        return Err(ProviderError::InvalidData);
    }
    if response.limits.standard.is_none() && response.limits.core.is_none() {
        return Err(ProviderError::InvalidData);
    }
    let mut windows = Vec::new();
    for (name, pool) in [
        ("Standard", response.limits.standard),
        ("Droid Core", response.limits.core),
    ] {
        let pool = pool.unwrap_or(Pool {
            five_hour: None,
            weekly: None,
            monthly: None,
        });
        for (label, window) in [
            ("5 hours", pool.five_hour),
            ("weekly", pool.weekly),
            ("monthly", pool.monthly),
        ] {
            let (used, resets_at) = match window {
                Some(window) => (
                    window.used_percent,
                    window
                        .window_end
                        .map(|s| OffsetDateTime::parse(&s, &Rfc3339))
                        .transpose()
                        .map_err(|_| ProviderError::InvalidData)?,
                ),
                None => (None, None),
            };
            // An expired bucket does not establish the value of its replacement.
            let quota = if resets_at.is_some_and(|reset| reset <= now) {
                Quota::Unknown
            } else {
                Quota::from_used(used)
            };
            let confidence = if quota == Quota::Unknown {
                Confidence::Unknown
            } else {
                Confidence::Exact
            };
            windows.push(QuotaWindow {
                reset_description: None,
                label: format!("{name} {label}"),
                quota,
                amounts: None,
                resets_at,
                fetched_at: now,
                provenance: Provenance {
                    source: "factory_billing_limits".into(),
                    confidence,
                },
            });
        }
    }
    if let Some(cents) = response.extra_usage_balance_cents {
        if !cents.is_finite() || cents < 0.0 {
            return Err(ProviderError::InvalidData);
        }
        windows.push(QuotaWindow {
            reset_description: None,
            label: "Extra usage credits".into(),
            quota: Quota::Unknown,
            amounts: Some(QuotaAmounts {
                remaining: cents / 100.0,
                limit: None,
                unit: "USD".into(),
            }),
            resets_at: None,
            fetched_at: now,
            provenance: Provenance {
                source: "factory_billing_limits".into(),
                confidence: Confidence::Exact,
            },
        });
    }
    Ok(ProviderUsage {
        account_ref: None,
        provider: ProviderId("factory".into()),
        account: AccountIdentity {
            plan: None,
            id: format!("{}:{}", identity.user_id, identity.org_id),
            label: format!("{} / {}", identity.user_id, identity.org_id),
        },
        windows,
    })
}
impl FactoryProvider {
    async fn fetch_api(
        &self,
        context: &ProviderContext,
        global: &str,
        eu: &str,
    ) -> Result<ProviderUsage, ProviderError> {
        let key = context
            .credentials
            .get("FACTORY_API_KEY")
            .filter(|key| !key.0.trim().is_empty())
            .ok_or(ProviderError::Authentication)?;
        let region = context.credentials.get("FACTORY_REGION");
        let base = match region
            .as_ref()
            .map(|value| value.0.as_str())
            .unwrap_or("global")
        {
            "global" => global,
            "eu" => eu,
            _ => return Err(ProviderError::InvalidData),
        };
        let authorization = http::sensitive(&format!("Bearer {}", key.0))?;
        let organization = context.credentials.get("FACTORY_ORG_ID");
        let mut who = context
            .http
            .get(format!("{base}/api/cli/whoami"))
            .header("Authorization", authorization.clone())
            .header("X-Factory-Whoami-Extended", "true");
        if let Some(org) = &organization {
            who = who.header("X-Factory-Org-Id", http::sensitive(&org.0)?);
        }
        let before: Identity = http::json(who, context.clock.now()).await?;
        if before.is_on_prem
            || before.org_id.is_empty()
            || before.user_id.is_empty()
            || before.region.as_deref().is_some_and(|actual| {
                actual != region.as_ref().map(|r| r.0.as_str()).unwrap_or("global")
            })
        {
            return Err(ProviderError::InvalidData);
        }
        if organization
            .as_ref()
            .is_some_and(|org| org.0 != before.org_id)
        {
            return Err(ProviderError::InvalidData);
        }
        let org = http::sensitive(&before.org_id)?;
        let response: Response = http::json(
            context
                .http
                .get(format!("{base}/api/billing/limits"))
                .header("Authorization", authorization.clone())
                .header("X-Factory-Org-Id", org.clone()),
            context.clock.now(),
        )
        .await?;
        let after: Identity = http::json(
            context
                .http
                .get(format!("{base}/api/cli/whoami"))
                .header("Authorization", authorization)
                .header("X-Factory-Whoami-Extended", "true")
                .header("X-Factory-Org-Id", org),
            context.clock.now(),
        )
        .await?;
        if before != after {
            return Err(ProviderError::InvalidData);
        }
        parse(after, response, context.clock.now())
    }
}
impl ProviderAdapter for FactoryProvider {
    fn id(&self) -> ProviderId {
        ProviderId("factory".into())
    }
    fn idempotent(&self) -> bool {
        true
    }
    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> FetchFuture<'a> {
        Box::pin(self.fetch_api(
            context,
            "https://api.factory.ai",
            "https://api.eu.factory.ai",
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> Identity {
        Identity {
            user_id: "demo-user".into(),
            org_id: "demo-org".into(),
            region: Some("global".into()),
            is_on_prem: false,
        }
    }
    #[test]
    fn pools_balances_and_expired_windows() {
        let response = serde_json::from_value(serde_json::json!({"limits":{"standard":{"fiveHour":{"usedPercent":20,"windowEnd":"2026-09-06T00:00:00Z"},"weekly":{"usedPercent":100,"windowEnd":"2026-09-01T00:00:00Z"}},"core":{"monthly":{"usedPercent":100}}},"extraUsageBalanceCents":1234})).unwrap();
        let now = OffsetDateTime::parse("2026-09-05T00:00:00Z", &Rfc3339).unwrap();
        let usage = parse(identity(), response, now).unwrap();
        assert_eq!(usage.windows.len(), 7);
        assert_eq!(usage.windows[0].quota, Quota::from_used(Some(20.0)));
        assert_eq!(usage.windows[1].quota, Quota::Unknown);
        assert_eq!(usage.windows[5].quota, Quota::from_used(Some(100.0)));
        assert_eq!(usage.windows[6].amounts.as_ref().unwrap().remaining, 12.34);
    }
    #[test]
    fn malformed_response_and_missing_pools_fail() {
        assert!(
            serde_json::from_value::<Response>(
                serde_json::json!({"limits":{"standard":{"fiveHour":{"usedPercent":"bad"}}}})
            )
            .is_err()
        );
        let response = serde_json::from_value(serde_json::json!({"limits":{}})).unwrap();
        assert!(parse(identity(), response, OffsetDateTime::UNIX_EPOCH).is_err());
    }
    #[tokio::test]
    async fn identity_and_org_are_checked_across_requests() {
        for changed in [false, true] {
            let before =
                serde_json::json!({"userId":"demo-user","orgId":"demo-org","region":"global"});
            let after = if changed {
                serde_json::json!({"userId":"different-user","orgId":"demo-org","region":"global"})
            } else {
                before.clone()
            };
            let (base, task) = http::fixture::server(vec![
                before,
                serde_json::json!({"limits":{"standard":{"fiveHour":{"usedPercent":25}}}}),
                after,
            ])
            .await;
            let context = http::fixture::context();
            let result = FactoryProvider.fetch_api(&context, &base, &base).await;
            assert_eq!(result.is_err(), changed);
            let requests = task.await.unwrap();
            assert!(requests[0].starts_with("GET /api/cli/whoami "));
            assert!(requests[1].starts_with("GET /api/billing/limits "));
            assert!(
                requests[1]
                    .to_lowercase()
                    .contains("x-factory-org-id: demo-org")
            );
            assert!(
                requests
                    .iter()
                    .all(|r| r.contains("Bearer synthetic-token"))
            );
        }
    }
}
