use super::{AuthKind, Definition, Setting, common};
use crate::{
    domain::{ProviderUsage, QuotaWindow},
    error::ProviderError,
    providers::{FetchFuture, ProviderContext, Secret},
};
use serde_json::Value;
use time::OffsetDateTime;

const DEEPSEEK_BALANCE_URL: &str = "https://api.deepseek.com/user/balance";
const MOONSHOT_INTERNATIONAL_BALANCE_URL: &str = "https://api.moonshot.ai/v1/users/me/balance";
const MOONSHOT_CHINA_BALANCE_URL: &str = "https://api.moonshot.cn/v1/users/me/balance";
const VENICE_BALANCE_URL: &str = "https://api.venice.ai/api/v1/billing/balance";
const XAI_MANAGEMENT_BASE: &str = "https://management-api.x.ai";
const POE_CURRENT_BALANCE_URL: &str = "https://api.poe.com/usage/current_balance";
const ZENMUX_MANAGEMENT_BASE: &str = "https://zenmux.ai/api/v1/management";
const CROF_USAGE_URL: &str = "https://crof.ai/usage_api/";

const MOONSHOT_SETTINGS: &[Setting] = &[Setting {
    name: "region",
    env: "MOONSHOT_REGION",
    required: false,
}];
const XAI_SETTINGS: &[Setting] = &[Setting {
    name: "team_id",
    env: "XAI_TEAM_ID",
    required: true,
}];

pub const DEFINITIONS: &[Definition] = &[
    Definition {
        id: "deepseek",
        name: "DeepSeek",
        key_env: "DEEPSEEK_API_KEY",
        auth: AuthKind::ApiKey,
        settings: &[],
        fetch: fetch_deepseek,
    },
    Definition {
        id: "moonshot",
        name: "Moonshot / Kimi",
        key_env: "MOONSHOT_API_KEY",
        auth: AuthKind::ApiKey,
        settings: MOONSHOT_SETTINGS,
        fetch: fetch_moonshot,
    },
    Definition {
        id: "venice",
        name: "Venice",
        key_env: "VENICE_API_KEY",
        auth: AuthKind::ApiKey,
        settings: &[],
        fetch: fetch_venice,
    },
    Definition {
        id: "xai",
        name: "xAI",
        key_env: "XAI_MANAGEMENT_API_KEY",
        auth: AuthKind::ApiKey,
        settings: XAI_SETTINGS,
        fetch: fetch_xai,
    },
    Definition {
        id: "poe",
        name: "Poe",
        key_env: "POE_API_KEY",
        auth: AuthKind::ApiKey,
        settings: &[],
        fetch: fetch_poe,
    },
    Definition {
        id: "zenmux",
        name: "ZenMux",
        key_env: "ZENMUX_MANAGEMENT_API_KEY",
        auth: AuthKind::ApiKey,
        settings: &[],
        fetch: fetch_zenmux,
    },
    Definition {
        id: "crof",
        name: "Crof",
        key_env: "CROF_API_KEY",
        auth: AuthKind::ApiKey,
        settings: &[],
        fetch: fetch_crof,
    },
];

fn fetch_deepseek<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(fetch_deepseek_at(context, DEEPSEEK_BALANCE_URL))
}

fn fetch_moonshot<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(async move {
        let (endpoint, scope) = moonshot_endpoint(context)?;
        fetch_moonshot_at(context, endpoint, scope).await
    })
}

fn fetch_venice<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(fetch_venice_at(context, VENICE_BALANCE_URL))
}

fn fetch_xai<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(fetch_xai_at(context, XAI_MANAGEMENT_BASE))
}

fn fetch_poe<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(fetch_poe_at(context, POE_CURRENT_BALANCE_URL))
}

fn fetch_zenmux<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(fetch_zenmux_at(context, ZENMUX_MANAGEMENT_BASE))
}

fn fetch_crof<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(fetch_crof_at(context, CROF_USAGE_URL))
}

async fn get_json(
    context: &ProviderContext,
    endpoint: &str,
    key: &Secret,
    now: OffsetDateTime,
) -> Result<Value, ProviderError> {
    common::json(
        context
            .http
            .get(endpoint)
            .header(
                "Authorization",
                crate::providers::http::sensitive(&format!("Bearer {}", key.0))?,
            )
            .header("Accept", "application/json"),
        now,
    )
    .await
}

fn required_number(value: Option<&Value>) -> Result<f64, ProviderError> {
    common::number(value)?.ok_or(ProviderError::InvalidData)
}

fn required_bool(value: Option<&Value>) -> Result<bool, ProviderError> {
    value
        .and_then(Value::as_bool)
        .ok_or(ProviderError::InvalidData)
}

async fn fetch_deepseek_at(
    context: &ProviderContext,
    endpoint: &str,
) -> Result<ProviderUsage, ProviderError> {
    let key = common::key(context, "DEEPSEEK_API_KEY")?;
    let now = context.clock.now();
    let root = get_json(context, endpoint, &key, now).await?;
    common::usage(
        "deepseek",
        &key,
        "api.deepseek.com",
        parse_deepseek(&root, now)?,
    )
}

fn parse_deepseek(root: &Value, now: OffsetDateTime) -> Result<Vec<QuotaWindow>, ProviderError> {
    required_bool(root.get("is_available"))?;
    let balances = root
        .get("balance_infos")
        .and_then(Value::as_array)
        .filter(|balances| !balances.is_empty())
        .ok_or(ProviderError::InvalidData)?;
    balances
        .iter()
        .map(|balance| {
            let currency = balance
                .get("currency")
                .and_then(Value::as_str)
                .filter(|currency| matches!(*currency, "CNY" | "USD"))
                .ok_or(ProviderError::InvalidData)?;
            let total = required_number(balance.get("total_balance"))?;
            required_number(balance.get("granted_balance"))?;
            required_number(balance.get("topped_up_balance"))?;
            common::window(
                &format!("{currency} balance"),
                None,
                None,
                Some(total),
                currency,
                None,
                "deepseek_user_balance",
                now,
            )
        })
        .collect()
}

fn moonshot_endpoint(
    context: &ProviderContext,
) -> Result<(&'static str, &'static str), ProviderError> {
    let region = context
        .credentials
        .get("MOONSHOT_REGION")
        .map(|value| value.0.trim().to_owned());
    match region.as_deref().unwrap_or("international") {
        "international" => Ok((MOONSHOT_INTERNATIONAL_BALANCE_URL, "api.moonshot.ai")),
        "china" => Ok((MOONSHOT_CHINA_BALANCE_URL, "api.moonshot.cn")),
        _ => Err(ProviderError::InvalidData),
    }
}

async fn fetch_moonshot_at(
    context: &ProviderContext,
    endpoint: &str,
    scope: &str,
) -> Result<ProviderUsage, ProviderError> {
    let key = common::key(context, "MOONSHOT_API_KEY")?;
    let now = context.clock.now();
    let root = get_json(context, endpoint, &key, now).await?;
    common::usage("moonshot", &key, scope, parse_moonshot(&root, now)?)
}

fn parse_moonshot(root: &Value, now: OffsetDateTime) -> Result<Vec<QuotaWindow>, ProviderError> {
    if root.get("code").and_then(Value::as_i64) != Some(0) || !required_bool(root.get("status"))? {
        return Err(ProviderError::InvalidData);
    }
    let available = required_number(root.pointer("/data/available_balance"))?;
    Ok(vec![common::window(
        "Available balance",
        None,
        None,
        Some(available),
        "account balance",
        None,
        "moonshot_user_balance",
        now,
    )?])
}

async fn fetch_venice_at(
    context: &ProviderContext,
    endpoint: &str,
) -> Result<ProviderUsage, ProviderError> {
    let key = common::key(context, "VENICE_API_KEY")?;
    let now = context.clock.now();
    let root = get_json(context, endpoint, &key, now).await?;
    common::usage("venice", &key, "api.venice.ai", parse_venice(&root, now)?)
}

fn parse_venice(root: &Value, now: OffsetDateTime) -> Result<Vec<QuotaWindow>, ProviderError> {
    required_bool(root.get("canConsume"))?;
    if !matches!(
        root.get("consumptionCurrency"),
        Some(Value::String(_)) | Some(Value::Null)
    ) {
        return Err(ProviderError::InvalidData);
    }
    let balances = root
        .get("balances")
        .and_then(Value::as_object)
        .ok_or(ProviderError::InvalidData)?;
    let diem = common::number(balances.get("diem"))?;
    let usd = common::number(balances.get("usd"))?;
    let allocation = common::number(root.get("diemEpochAllocation"))?;
    let mut windows = Vec::new();
    if let Some(diem) = diem {
        if let Some(allocation) = allocation.filter(|allocation| *allocation > 0.0) {
            if diem > allocation {
                return Err(ProviderError::InvalidData);
            }
            windows.push(common::window(
                "DIEM balance",
                Some(allocation - diem),
                Some(allocation),
                Some(diem),
                "DIEM",
                None,
                "venice_billing_balance",
                now,
            )?);
        } else {
            windows.push(common::window(
                "DIEM balance",
                None,
                None,
                Some(diem),
                "DIEM",
                None,
                "venice_billing_balance",
                now,
            )?);
        }
    }
    if let Some(usd) = usd {
        windows.push(common::window(
            "USD balance",
            None,
            None,
            Some(usd),
            "USD",
            None,
            "venice_billing_balance",
            now,
        )?);
    }
    if windows.is_empty() {
        return Err(ProviderError::InvalidData);
    }
    Ok(windows)
}

fn xai_team_id(context: &ProviderContext) -> Result<String, ProviderError> {
    let team = context
        .credentials
        .get("XAI_TEAM_ID")
        .ok_or(ProviderError::Authentication)?;
    let team = team.0.trim();
    if team.is_empty()
        || team.len() > 128
        || !team
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(ProviderError::InvalidData);
    }
    Ok(team.into())
}

async fn fetch_xai_at(
    context: &ProviderContext,
    base: &str,
) -> Result<ProviderUsage, ProviderError> {
    let key = common::key(context, "XAI_MANAGEMENT_API_KEY")?;
    let team = xai_team_id(context)?;
    let now = context.clock.now();
    let endpoint = format!("{base}/v1/billing/teams/{team}/prepaid/balance");
    let root = get_json(context, &endpoint, &key, now).await?;
    let scope = format!("management-api.x.ai/team/{team}");
    common::usage("xai", &key, &scope, parse_xai(&root, now)?)
}

fn parse_xai(root: &Value, now: OffsetDateTime) -> Result<Vec<QuotaWindow>, ProviderError> {
    let raw = root
        .pointer("/total/val")
        .and_then(Value::as_str)
        .filter(|raw| !raw.is_empty() && raw.len() <= 64)
        .ok_or(ProviderError::InvalidData)?;
    let cents = raw.parse::<i64>().map_err(|_| ProviderError::InvalidData)?;
    let balance = cents
        .checked_neg()
        .filter(|cents| *cents >= 0)
        .ok_or(ProviderError::InvalidData)? as f64
        / 100.0;
    Ok(vec![common::window(
        "Prepaid balance",
        None,
        None,
        Some(balance),
        "USD",
        None,
        "xai_prepaid_balance",
        now,
    )?])
}

async fn fetch_poe_at(
    context: &ProviderContext,
    endpoint: &str,
) -> Result<ProviderUsage, ProviderError> {
    let key = common::key(context, "POE_API_KEY")?;
    let now = context.clock.now();
    let root = get_json(context, endpoint, &key, now).await?;
    common::usage("poe", &key, "api.poe.com", parse_poe(&root, now)?)
}

fn parse_poe(root: &Value, now: OffsetDateTime) -> Result<Vec<QuotaWindow>, ProviderError> {
    const MAX_EXACT_INTEGER: u64 = 9_007_199_254_740_991;
    let points = root
        .get("current_point_balance")
        .and_then(Value::as_u64)
        .filter(|points| *points <= MAX_EXACT_INTEGER)
        .ok_or(ProviderError::InvalidData)? as f64;
    Ok(vec![common::window(
        "Point balance",
        None,
        None,
        Some(points),
        "points",
        None,
        "poe_current_balance",
        now,
    )?])
}

async fn fetch_zenmux_at(
    context: &ProviderContext,
    base: &str,
) -> Result<ProviderUsage, ProviderError> {
    let key = common::key(context, "ZENMUX_MANAGEMENT_API_KEY")?;
    let now = context.clock.now();
    let subscription = get_json(context, &format!("{base}/subscription/detail"), &key, now).await?;
    let (mut windows, plan) = parse_zenmux_subscription(&subscription, now)?;
    if let Ok(payg) = get_json(context, &format!("{base}/payg/balance"), &key, now).await
        && let Ok(window) = parse_zenmux_payg(&payg, now)
    {
        windows.push(window);
    }
    let mut usage = common::usage("zenmux", &key, "zenmux.ai/management", windows)?;
    usage.account.plan = Some(plan);
    Ok(usage)
}

fn parse_zenmux_subscription(
    root: &Value,
    now: OffsetDateTime,
) -> Result<(Vec<QuotaWindow>, String), ProviderError> {
    if root.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(ProviderError::InvalidData);
    }
    let plan = root
        .pointer("/data/plan/tier")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|tier| !tier.is_empty() && tier.len() <= 128)
        .ok_or(ProviderError::InvalidData)?;
    let five_hour = zenmux_quota(root.pointer("/data/quota_5_hour"), "5-hour quota", now)?;
    let weekly = zenmux_quota(root.pointer("/data/quota_7_day"), "7-day quota", now)?;
    Ok((vec![five_hour, weekly], plan.into()))
}

fn zenmux_quota(
    quota: Option<&Value>,
    label: &str,
    now: OffsetDateTime,
) -> Result<QuotaWindow, ProviderError> {
    let quota = quota.ok_or(ProviderError::InvalidData)?;
    let limit = required_number(quota.get("max_flows"))?;
    let used = required_number(quota.get("used_flows"))?;
    let remaining = required_number(quota.get("remaining_flows"))?;
    if used > limit || remaining > limit {
        return Err(ProviderError::InvalidData);
    }
    common::window(
        label,
        Some(used),
        Some(limit),
        Some(remaining),
        "flows",
        common::date(quota.get("resets_at"))?,
        "zenmux_subscription_detail",
        now,
    )
}

fn parse_zenmux_payg(root: &Value, now: OffsetDateTime) -> Result<QuotaWindow, ProviderError> {
    if root.get("success").and_then(Value::as_bool) != Some(true)
        || root.pointer("/data/currency").and_then(Value::as_str) != Some("usd")
    {
        return Err(ProviderError::InvalidData);
    }
    common::window(
        "PAYG balance",
        None,
        None,
        Some(required_number(root.pointer("/data/total_credits"))?),
        "USD",
        None,
        "zenmux_payg_balance",
        now,
    )
}

async fn fetch_crof_at(
    context: &ProviderContext,
    endpoint: &str,
) -> Result<ProviderUsage, ProviderError> {
    let key = common::key(context, "CROF_API_KEY")?;
    let now = context.clock.now();
    let root = get_json(context, endpoint, &key, now).await?;
    common::usage("crof", &key, "crof.ai", parse_crof(&root, now)?)
}

fn parse_crof(root: &Value, now: OffsetDateTime) -> Result<Vec<QuotaWindow>, ProviderError> {
    let credits = required_number(root.get("credits"))?;
    let request_plan = common::number(root.get("requests_plan"))?;
    let usable_requests = common::number(root.get("usable_requests"))?;
    let mut windows = Vec::new();
    if let (Some(limit), Some(remaining)) = (request_plan, usable_requests) {
        if remaining > limit {
            return Err(ProviderError::InvalidData);
        }
        windows.push(common::window(
            "Request quota",
            Some(limit - remaining),
            Some(limit),
            Some(remaining),
            "requests",
            None,
            "crof_usage_api",
            now,
        )?);
    }
    windows.push(common::window(
        "Credit balance",
        None,
        None,
        Some(credits),
        "USD",
        None,
        "crof_usage_api",
        now,
    )?);
    Ok(windows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{Clock, CredentialStore};
    use std::{collections::BTreeMap, sync::Arc};

    struct Credentials(BTreeMap<&'static str, &'static str>);

    impl CredentialStore for Credentials {
        fn get(&self, name: &str) -> Option<Secret> {
            self.0.get(name).map(|value| Secret((*value).into()))
        }
    }

    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH
        }
    }

    fn context(values: &[(&'static str, &'static str)]) -> ProviderContext {
        ProviderContext {
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            clock: Arc::new(FixedClock),
            credentials: Arc::new(Credentials(values.iter().copied().collect())),
        }
    }

    fn assert_https_endpoint(raw: &str, host: &str, path: &str) {
        let url = reqwest::Url::parse(raw).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some(host));
        assert_eq!(url.port_or_known_default(), Some(443));
        assert_eq!(url.path(), path);
        assert!(url.query().is_none());
        assert!(url.fragment().is_none());
    }

    #[test]
    fn definitions_expose_cli_setting_identifiers_and_fixed_https_routes() {
        let moonshot = DEFINITIONS
            .iter()
            .find(|definition| definition.id == "moonshot")
            .unwrap();
        let xai = DEFINITIONS
            .iter()
            .find(|definition| definition.id == "xai")
            .unwrap();
        assert_eq!(moonshot.settings[0].name, "region");
        assert_eq!(xai.settings[0].name, "team_id");

        assert_https_endpoint(DEEPSEEK_BALANCE_URL, "api.deepseek.com", "/user/balance");
        assert_https_endpoint(
            MOONSHOT_INTERNATIONAL_BALANCE_URL,
            "api.moonshot.ai",
            "/v1/users/me/balance",
        );
        assert_https_endpoint(
            MOONSHOT_CHINA_BALANCE_URL,
            "api.moonshot.cn",
            "/v1/users/me/balance",
        );
        assert_https_endpoint(
            VENICE_BALANCE_URL,
            "api.venice.ai",
            "/api/v1/billing/balance",
        );
        assert_https_endpoint(
            &format!("{XAI_MANAGEMENT_BASE}/v1/billing/teams/team-01/prepaid/balance"),
            "management-api.x.ai",
            "/v1/billing/teams/team-01/prepaid/balance",
        );
        assert_https_endpoint(
            POE_CURRENT_BALANCE_URL,
            "api.poe.com",
            "/usage/current_balance",
        );
        assert_https_endpoint(
            &format!("{ZENMUX_MANAGEMENT_BASE}/subscription/detail"),
            "zenmux.ai",
            "/api/v1/management/subscription/detail",
        );
        assert_https_endpoint(
            &format!("{ZENMUX_MANAGEMENT_BASE}/payg/balance"),
            "zenmux.ai",
            "/api/v1/management/payg/balance",
        );
        assert_https_endpoint(CROF_USAGE_URL, "crof.ai", "/usage_api/");
    }

    #[tokio::test]
    async fn balance_handlers_use_bearer_and_parse_synthetic_routes() {
        let (base, server) = crate::providers::http::fixture::server(vec![
            serde_json::json!({
                "is_available": true,
                "balance_infos": [{
                    "currency": "CNY",
                    "total_balance": "110.00",
                    "granted_balance": "10.00",
                    "topped_up_balance": "100.00"
                }]
            }),
            serde_json::json!({
                "code": 0,
                "status": true,
                "data": {"available_balance": 49.58894}
            }),
            serde_json::json!({
                "canConsume": true,
                "consumptionCurrency": "DIEM",
                "balances": {"diem": 90.5, "usd": 25},
                "diemEpochAllocation": 100
            }),
            serde_json::json!({"total": {"val": "-1200"}}),
            serde_json::json!({"current_point_balance": 2500}),
            serde_json::json!({
                "success": true,
                "data": {
                    "plan": {"tier": "ultra"},
                    "quota_5_hour": {
                        "max_flows": 800,
                        "used_flows": 57.2,
                        "remaining_flows": 742.8,
                        "resets_at": "2026-09-06T00:00:00Z"
                    },
                    "quota_7_day": {
                        "max_flows": 6182,
                        "used_flows": 416.11,
                        "remaining_flows": 5765.89
                    }
                }
            }),
            serde_json::json!({
                "success": true,
                "data": {"currency": "usd", "total_credits": 482.74}
            }),
            serde_json::json!({
                "credits": 2.5,
                "requests_plan": 1000,
                "usable_requests": 998
            }),
        ])
        .await;
        let deepseek = fetch_deepseek_at(
            &context(&[("DEEPSEEK_API_KEY", "fixture-key")]),
            &format!("{base}/deepseek"),
        )
        .await
        .unwrap();
        let moonshot = fetch_moonshot_at(
            &context(&[("MOONSHOT_API_KEY", "fixture-key")]),
            &format!("{base}/moonshot"),
            "test.moonshot",
        )
        .await
        .unwrap();
        let venice = fetch_venice_at(
            &context(&[("VENICE_API_KEY", "fixture-key")]),
            &format!("{base}/venice"),
        )
        .await
        .unwrap();
        let xai = fetch_xai_at(
            &context(&[
                ("XAI_MANAGEMENT_API_KEY", "fixture-key"),
                ("XAI_TEAM_ID", "team-01"),
            ]),
            &format!("{base}/xai"),
        )
        .await
        .unwrap();
        let poe = fetch_poe_at(
            &context(&[("POE_API_KEY", "fixture-key")]),
            &format!("{base}/poe"),
        )
        .await
        .unwrap();
        let zenmux = fetch_zenmux_at(
            &context(&[("ZENMUX_MANAGEMENT_API_KEY", "fixture-key")]),
            &format!("{base}/zenmux"),
        )
        .await
        .unwrap();
        let crof = fetch_crof_at(
            &context(&[("CROF_API_KEY", "fixture-key")]),
            &format!("{base}/crof"),
        )
        .await
        .unwrap();

        assert_eq!(
            deepseek.windows[0].amounts.as_ref().unwrap().remaining,
            110.0
        );
        assert_eq!(
            moonshot.windows[0].amounts.as_ref().unwrap().remaining,
            49.58894
        );
        assert_eq!(venice.windows.len(), 2);
        assert_eq!(xai.windows[0].amounts.as_ref().unwrap().remaining, 12.0);
        assert_eq!(poe.windows[0].amounts.as_ref().unwrap().remaining, 2500.0);
        assert_eq!(zenmux.account.plan.as_deref(), Some("ultra"));
        assert_eq!(zenmux.windows.len(), 3);
        assert_eq!(crof.windows.len(), 2);

        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 8);
        for request in &requests {
            assert!(request.contains("Bearer fixture-key"));
        }
        assert!(requests[0].starts_with("GET /deepseek HTTP/1.1"));
        assert!(requests[1].starts_with("GET /moonshot HTTP/1.1"));
        assert!(requests[2].starts_with("GET /venice HTTP/1.1"));
        assert!(
            requests[3].starts_with("GET /xai/v1/billing/teams/team-01/prepaid/balance HTTP/1.1")
        );
        assert!(requests[4].starts_with("GET /poe HTTP/1.1"));
        assert!(requests[5].starts_with("GET /zenmux/subscription/detail HTTP/1.1"));
        assert!(requests[6].starts_with("GET /zenmux/payg/balance HTTP/1.1"));
        assert!(requests[7].starts_with("GET /crof HTTP/1.1"));
    }

    #[test]
    fn parsers_reject_semantically_invalid_values() {
        let now = OffsetDateTime::UNIX_EPOCH;
        assert!(parse_xai(&serde_json::json!({"total": {"val": "1200"}}), now).is_err());
        assert!(parse_poe(&serde_json::json!({"current_point_balance": "2500"}), now).is_err());
        assert!(
            parse_crof(
                &serde_json::json!({"credits": 1, "requests_plan": 10, "usable_requests": 11}),
                now,
            )
            .is_err()
        );
        assert!(
            parse_venice(
                &serde_json::json!({
                    "canConsume": true,
                    "consumptionCurrency": "DIEM",
                    "balances": {"diem": 101},
                    "diemEpochAllocation": 100
                }),
                now,
            )
            .is_err()
        );
    }
}
