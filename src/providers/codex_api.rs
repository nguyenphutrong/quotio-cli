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
    let plan = value
        .get("plan_type")
        .and_then(Value::as_str)
        .map(str::to_owned);
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
    usage.account.plan = plan;
    // Keep the main Codex windows first, followed by model-specific limits.
    usage
        .windows
        .sort_by_key(|w| !matches!(w.label.as_str(), "Session" | "Weekly"));
    for w in &mut usage.windows {
        w.provenance.source = "codex_api".into();
    }
    Ok(usage)
}
#[cfg(test)]
tokio::task_local! {
    static TEST_ENDPOINTS: (String, String, String);
}

pub async fn fetch(
    context: &ProviderContext,
    credential: &Credential,
) -> Result<ProviderUsage, ProviderError> {
    #[cfg(test)]
    if let Ok((quota, inventory, profile)) = TEST_ENDPOINTS.try_with(Clone::clone) {
        return fetch_at(context, credential, &quota, &inventory, &profile).await;
    }
    fetch_at(
        context,
        credential,
        "https://chatgpt.com/backend-api/wham/usage",
        "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits",
        "https://chatgpt.com/backend-api/wham/profiles/me",
    )
    .await
}
pub(crate) async fn fetch_at(
    context: &ProviderContext,
    credential: &Credential,
    endpoint: &str,
    inventory_endpoint: &str,
    profile_endpoint: &str,
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
    let (inventory, profile) = tokio::join!(
        supplemental(context, access_token, account_id, inventory_endpoint, true),
        supplemental(context, access_token, account_id, profile_endpoint, false),
    );
    match inventory.and_then(|value| parse_inventory(value, context.clock.now())) {
        Ok(inventory) => {
            usage.reset_credits = Some(ResetCredits {
                available_count: inventory.available_count,
                earliest_expires_at: inventory
                    .credits
                    .iter()
                    .filter_map(|credit| credit.expires_at)
                    .min(),
                fetched_at: inventory.fetched_at,
                source: "codex_api".into(),
            });
            usage.codex_reset_credits = Some(inventory);
        }
        Err(code) => usage.diagnostics.push(UsageDiagnostic {
            source: "codex_reset_credits".into(),
            code,
        }),
    }
    match profile.and_then(|value| super::codex_profile::parse(value, context.clock.now())) {
        Ok(profile) => usage.codex_profile = Some(profile),
        Err(code) => usage.diagnostics.push(UsageDiagnostic {
            source: "codex_profile".into(),
            code,
        }),
    }
    Ok(usage)
}
async fn supplemental(
    context: &ProviderContext,
    access_token: &str,
    account_id: &str,
    endpoint: &str,
    inventory: bool,
) -> Result<Value, ProviderError> {
    let cap = std::time::Duration::from_secs(4);
    let budget = super::remaining_fetch_time().map_or(cap, |remaining| {
        // Leave time for the account adapter to verify identity and return the quota.
        let reserve = (remaining / 10).min(std::time::Duration::from_millis(100));
        remaining.saturating_sub(reserve).min(cap)
    });
    if budget.is_zero() {
        return Err(ProviderError::Timeout);
    }
    let mut request = context
        .http
        .get(endpoint)
        .header(
            "Authorization",
            http::sensitive(&format!("Bearer {access_token}"))?,
        )
        .header("ChatGPT-Account-Id", http::sensitive(account_id)?)
        .header("Accept", "application/json")
        .header("Originator", "Codex Desktop")
        .timeout(budget);
    if inventory {
        request = request.header("OpenAI-Beta", "codex-1");
    }
    tokio::time::timeout(budget, http::json(request, context.clock.now()))
        .await
        .map_err(|_| ProviderError::Timeout)?
}

fn parse_inventory(
    value: Value,
    now: time::OffsetDateTime,
) -> Result<CodexResetCreditInventory, ProviderError> {
    #[derive(serde::Deserialize)]
    struct Payload {
        available_count: u64,
        credits: Vec<Credit>,
    }
    #[derive(serde::Deserialize)]
    struct Credit {
        id: String,
        status: String,
        #[serde(default, with = "time::serde::rfc3339::option")]
        expires_at: Option<time::OffsetDateTime>,
    }
    let payload: Payload = serde_json::from_value(value).map_err(|_| ProviderError::InvalidData)?;
    let mut credits: Vec<_> = payload
        .credits
        .into_iter()
        .filter(|credit| {
            credit.status == "available" && credit.expires_at.is_none_or(|expiry| expiry > now)
        })
        .collect();
    credits.sort_by(|a, b| match (a.expires_at, b.expires_at) {
        (Some(a_date), Some(b_date)) => a_date.cmp(&b_date).then_with(|| a.id.cmp(&b.id)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.id.cmp(&b.id),
    });
    Ok(CodexResetCreditInventory {
        available_count: payload.available_count,
        fetched_at: now,
        credits: credits
            .into_iter()
            .map(|credit| {
                let digest = ring::digest::digest(
                    &ring::digest::SHA256,
                    format!("com.quotio.codex.reset-credit-id.v1\0{}", credit.id).as_bytes(),
                );
                CodexResetCredit {
                    id: digest
                        .as_ref()
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                    expires_at: credit.expires_at,
                }
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inventory_preserves_source_count_and_filters_without_exposing_ids() {
        let now = time::macros::datetime!(2026-09-07 0:00 UTC);
        let inventory = parse_inventory(
            json!({"available_count":9,"credits":[
                {"id":"no-expiry-secret","status":"available"},
                {"id":"future-secret","status":"available","expires_at":"2026-09-08T00:00:00.123Z"},
                {"id":"expired-secret","status":"available","expires_at":"2026-09-07T00:00:00Z"},
                {"id":"used-secret","status":"consumed"}
            ]}),
            now,
        )
        .unwrap();
        assert_eq!(inventory.available_count, 9);
        assert_eq!(inventory.credits.len(), 2);
        assert!(inventory.credits[0].expires_at.is_some());
        assert!(inventory.credits[1].expires_at.is_none());
        assert_eq!(inventory.credits[0].id.len(), 64);
        assert!(
            !serde_json::to_string(&inventory)
                .unwrap()
                .contains("secret")
        );
        for value in [
            json!({"available_count":-1,"credits":[]}),
            json!({"available_count":0,"credits":[{"id":"x","status":"available","expires_at":"bad"}]}),
        ] {
            assert!(matches!(
                parse_inventory(value, now),
                Err(ProviderError::InvalidData)
            ));
        }
    }

    #[tokio::test]
    async fn invalid_inventory_keeps_quota_and_scoped_diagnostic() {
        let (url, task) = http::fixture::server(vec![
            json!({"rate_limit":{"primary_window":{"used_percent":10,"limit_window_seconds":18000}}}),
            json!({"available_count":"provider-secret","credits":[]}),
        ]).await;
        let credential = Credential::CodexOAuth {
            access_token: "synthetic-token".into(),
            refresh_token: "refresh".into(),
            id_token: "id".into(),
            account_id: "workspace-a".into(),
            email: "demo@example.com".into(),
            expires_at: 0,
        };
        let (profile_url, profile_task) =
            http::fixture::server(vec![json!({"stats":{"lifetime_tokens":42}})]).await;
        let mut usage = fetch_at(
            &http::fixture::context(),
            &credential,
            &url,
            &url,
            &profile_url,
        )
        .await
        .unwrap();
        assert_eq!(usage.windows.len(), 1);
        assert!(usage.codex_reset_credits.is_none());
        assert_eq!(
            usage.codex_profile.as_ref().unwrap().lifetime_tokens,
            Some(42)
        );
        profile_task.await.unwrap();
        assert_eq!(usage.diagnostics[0].source, "codex_reset_credits");
        usage.account_ref = Some(AccountRef {
            id: "saved-a".into(),
            label: "A".into(),
            origin: None,
        });
        // Supplemental data and diagnostics survive the same serialization used by the cache.
        let usage = serde_json::from_value(serde_json::to_value(usage).unwrap()).unwrap();
        let mut report = UsageReport {
            schema_version: 1,
            generated_at: http::fixture::context().clock.now(),
            providers: vec![usage],
            failures: vec![],
        };
        report.include_diagnostics();
        assert_eq!(
            report.failures[0].account_ref.as_ref().unwrap().id,
            "saved-a"
        );
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("provider-secret")
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn profile_failures_preserve_inventory_and_quota() {
        for (status, body, expected) in [
            (
                401,
                json!({"error":"synthetic-private-error"}),
                ProviderError::Authentication,
            ),
            (
                200,
                json!({"unexpected":"synthetic-private-error"}),
                ProviderError::InvalidData,
            ),
        ] {
            let (url, task) = http::fixture::server(vec![
                json!({"rate_limit":{"primary_window":{"used_percent":10,"limit_window_seconds":18000}}}),
                json!({"available_count":3,"credits":[]}),
            ]).await;
            let (profile_url, profile_task) =
                http::fixture::server_status(vec![(status, body)]).await;
            let credential = Credential::CodexOAuth {
                access_token: "synthetic-token".into(),
                refresh_token: "refresh".into(),
                id_token: "id".into(),
                account_id: "workspace-a".into(),
                email: "demo@example.com".into(),
                expires_at: 0,
            };
            let usage = fetch_at(
                &http::fixture::context(),
                &credential,
                &url,
                &url,
                &profile_url,
            )
            .await
            .unwrap();
            assert_eq!(usage.windows.len(), 1);
            assert_eq!(
                usage.codex_reset_credits.as_ref().unwrap().available_count,
                3
            );
            assert!(usage.codex_profile.is_none());
            assert_eq!(usage.diagnostics.len(), 1);
            assert_eq!(usage.diagnostics[0].source, "codex_profile");
            assert_eq!(usage.diagnostics[0].code, expected);
            assert!(
                !serde_json::to_string(&usage)
                    .unwrap()
                    .contains("synthetic-private-error")
            );
            task.await.unwrap();
            profile_task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn collector_short_budget_preserves_quota_through_fetch() {
        use crate::{
            fetch::{CollectRequest, Collector},
            providers::{FetchFuture, ProviderAdapter},
        };
        use std::{sync::Arc, time::Duration};

        struct Adapter {
            endpoints: (String, String, String),
            credential: Credential,
        }
        impl ProviderAdapter for Adapter {
            fn id(&self) -> ProviderId {
                ProviderId("codex".into())
            }
            fn fetch<'a>(&'a self, context: &'a ProviderContext) -> FetchFuture<'a> {
                Box::pin(TEST_ENDPOINTS.scope(self.endpoints.clone(), async move {
                    let usage = fetch(context, &self.credential).await?;
                    // Model the account adapter's post-fetch identity verification.
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    Ok(usage)
                }))
            }
        }
        let (quota, quota_task) = http::fixture::server(vec![
            json!({"rate_limit":{"primary_window":{"used_percent":10,"limit_window_seconds":18000}}}),
        ]).await;
        let (inventory, inventory_task) =
            http::fixture::server_status_with_async_action(vec![(200, json!({}))], |_| async {
                tokio::time::sleep(Duration::from_secs(30)).await
            })
            .await;
        let (profile, profile_task) =
            http::fixture::server_status_with_async_action(vec![(200, json!({}))], |_| async {
                tokio::time::sleep(Duration::from_secs(30)).await
            })
            .await;
        let report = Collector {
            context: http::fixture::context(),
        }
        .collect(CollectRequest {
            providers: vec![Arc::new(Adapter {
                endpoints: (quota, inventory, profile),
                credential: Credential::CodexOAuth {
                    access_token: "synthetic-token".into(),
                    refresh_token: "refresh".into(),
                    id_token: "id".into(),
                    account_id: "workspace-a".into(),
                    email: "demo@example.com".into(),
                    expires_at: 0,
                },
            })],
            timeout: Duration::from_millis(500),
            cancellation: Default::default(),
        })
        .await;
        inventory_task.abort();
        profile_task.abort();
        quota_task.await.unwrap();
        assert_eq!(report.providers.len(), 1, "{:#?}", report.failures);
        let usage = &report.providers[0];
        assert_eq!(usage.windows.len(), 1);
        assert_eq!(usage.account.id, "workspace-a");
        assert!(usage.codex_reset_credits.is_none());
        assert!(usage.codex_profile.is_none());
        assert_eq!(usage.diagnostics.len(), 2);
        assert_eq!(usage.diagnostics[0].source, "codex_reset_credits");
        assert_eq!(usage.diagnostics[1].source, "codex_profile");
        assert!(
            usage
                .diagnostics
                .iter()
                .all(|d| d.code == ProviderError::Timeout)
        );
    }

    #[tokio::test]
    async fn supplemental_timeout_does_not_discard_quota() {
        let (url, task) = http::fixture::server(vec![
            json!({"rate_limit":{"primary_window":{"used_percent":10,"limit_window_seconds":18000}}}),
            json!({"available_count":0,"credits":[]}),
        ]).await;
        let (profile_url, profile_task) = http::fixture::server_status_with_async_action(
            vec![(200, json!({"stats":{}}))],
            |_| async { tokio::time::sleep(std::time::Duration::from_secs(30)).await },
        )
        .await;
        let credential = Credential::CodexOAuth {
            access_token: "synthetic-token".into(),
            refresh_token: "refresh".into(),
            id_token: "id".into(),
            account_id: "workspace-a".into(),
            email: "demo@example.com".into(),
            expires_at: 0,
        };
        let usage = tokio::time::timeout(
            std::time::Duration::from_secs(6),
            fetch_at(
                &http::fixture::context(),
                &credential,
                &url,
                &url,
                &profile_url,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(usage.windows.len(), 1);
        assert!(usage.codex_reset_credits.is_some());
        assert_eq!(usage.diagnostics[0].code, ProviderError::Timeout);
        profile_task.abort();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn direct_quota_preserves_identity_headers_and_sparse_windows() {
        let (url,task)=http::fixture::server(vec![json!({"plan_type":"pro","rate_limit":{"primary_window":{"used_percent":20,"limit_window_seconds":604800}},"additional_rate_limits":[{"limit_name":"GPT Spark","rate_limit":{"primary_window":{"used_percent":0,"limit_window_seconds":18000}}}]}), json!({"available_count":0,"credits":[]})]).await;
        let credential = Credential::CodexOAuth {
            access_token: "synthetic-token".into(),
            refresh_token: "refresh".into(),
            id_token: "id".into(),
            account_id: "workspace-a".into(),
            email: "demo@example.com".into(),
            expires_at: 0,
        };
        let (profile_url, profile_task) = http::fixture::server(vec![
            json!({"stats":{"daily_usage_buckets":{"2026-09-07":0}}}),
        ])
        .await;
        let usage = fetch_at(
            &http::fixture::context(),
            &credential,
            &url,
            &url,
            &profile_url,
        )
        .await
        .unwrap();
        assert_eq!(usage.windows.len(), 2);
        assert_eq!(usage.windows[0].label, "Weekly");
        assert_eq!(usage.windows[1].label, "Codex Spark Session");
        assert_eq!(usage.account.id, "workspace-a");
        assert_eq!(usage.account.plan.as_deref(), Some("pro"));
        let req = task.await.unwrap();
        assert!(
            req[0]
                .to_lowercase()
                .contains("chatgpt-account-id: workspace-a")
        );
        assert!(req[0].contains("Bearer synthetic-token"));
        assert!(!req[0].to_lowercase().contains("cookie:"));
        assert!(req.iter().all(|request| request.starts_with("GET ")));
        assert!(req[1].to_lowercase().contains("openai-beta: codex-1"));
        assert!(req[1].to_lowercase().contains("originator: codex desktop"));
        assert_eq!(
            usage.codex_reset_credits.as_ref().unwrap().available_count,
            0
        );
        assert_eq!(usage.reset_credits.as_ref().unwrap().available_count, 0);
        assert_eq!(
            usage.codex_profile.as_ref().unwrap().daily_usage[0].tokens,
            0
        );
        let serialized = serde_json::to_value(&usage).unwrap();
        let restored: ProviderUsage = serde_json::from_value(serialized.clone()).unwrap();
        assert_eq!(serde_json::to_value(restored).unwrap(), serialized);
        let profile_requests = profile_task.await.unwrap();
        assert!(profile_requests[0].starts_with("GET "));
        assert!(
            profile_requests[0]
                .to_lowercase()
                .contains("chatgpt-account-id: workspace-a")
        );
        assert!(
            profile_requests[0]
                .to_lowercase()
                .contains("originator: codex desktop")
        );
        assert!(!profile_requests[0].to_lowercase().contains("openai-beta:"));
    }
}
