use super::{AuthKind, Definition, Setting, common};
use crate::{
    domain::QuotaWindow,
    error::ProviderError,
    providers::{FetchFuture, ProviderContext, Secret},
};
use reqwest::Url;
use serde_json::Value;
use std::collections::BTreeSet;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const CLAWROUTER_SETTINGS: &[Setting] = &[Setting {
    name: "base_url",
    env: "CLAWROUTER_BASE_URL",
    required: false,
}];
const LITELLM_SETTINGS: &[Setting] = &[Setting {
    name: "base_url",
    env: "LITELLM_BASE_URL",
    required: true,
}];
const LLM_PROXY_SETTINGS: &[Setting] = &[Setting {
    name: "base_url",
    env: "LLM_PROXY_BASE_URL",
    required: true,
}];
const SUB2API_SETTINGS: &[Setting] = &[Setting {
    name: "base_url",
    env: "SUB2API_BASE_URL",
    required: true,
}];
const OPENAI_SETTINGS: &[Setting] = &[Setting {
    name: "project_id",
    env: "OPENAI_PROJECT_ID",
    required: false,
}];

/// Gateways only advertise APIs that expose accounting data directly. Azure OpenAI's
/// resource key and Doubao's Ark key only authorize inference requests, so their
/// validation probes are deliberately not registered here as quota adapters.
pub const DEFINITIONS: &[Definition] = &[
    Definition {
        id: "clawrouter",
        name: "ClawRouter",
        key_env: "CLAWROUTER_API_KEY",
        auth: AuthKind::ApiKey,
        settings: CLAWROUTER_SETTINGS,
        fetch: clawrouter,
    },
    Definition {
        id: "litellm",
        name: "LiteLLM",
        key_env: "LITELLM_API_KEY",
        auth: AuthKind::ApiKey,
        settings: LITELLM_SETTINGS,
        fetch: litellm,
    },
    Definition {
        id: "llmproxy",
        name: "LLM Proxy",
        key_env: "LLM_PROXY_API_KEY",
        auth: AuthKind::ApiKey,
        settings: LLM_PROXY_SETTINGS,
        fetch: llmproxy,
    },
    Definition {
        id: "sub2api",
        name: "sub2api",
        key_env: "SUB2API_API_KEY",
        auth: AuthKind::ApiKey,
        settings: SUB2API_SETTINGS,
        fetch: sub2api,
    },
    Definition {
        id: "openai",
        name: "OpenAI organization usage",
        key_env: "OPENAI_ADMIN_KEY",
        auth: AuthKind::ApiKey,
        settings: OPENAI_SETTINGS,
        fetch: openai,
    },
];

const MAX_SETTING_LENGTH: usize = 4096;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn setting(context: &ProviderContext, env: &str) -> Result<Option<String>, ProviderError> {
    let Some(value) = context.credentials.get(env) else {
        return Ok(None);
    };
    let value = value.0.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > MAX_SETTING_LENGTH || value.chars().any(char::is_control) {
        return Err(ProviderError::InvalidData);
    }
    Ok(Some(value.into()))
}

/// A bearer key can only be sent to a fully specified HTTPS authority. We reject
/// userinfo, queries, and fragments before deriving every endpoint from this base.
fn https_base(raw: &str) -> Result<Url, ProviderError> {
    let url = Url::parse(raw).map_err(|_| ProviderError::InvalidData)?;
    if url.scheme() != "https"
        || url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port() == Some(0)
    {
        return Err(ProviderError::InvalidData);
    }
    Ok(url)
}

fn required_base(context: &ProviderContext, env: &str) -> Result<Url, ProviderError> {
    let raw = setting(context, env)?.ok_or(ProviderError::InvalidData)?;
    https_base(&raw)
}

fn optional_base(
    context: &ProviderContext,
    env: &str,
    default: &str,
) -> Result<Url, ProviderError> {
    match setting(context, env)? {
        Some(raw) => https_base(&raw),
        None => https_base(default),
    }
}

fn path_parts(base: &Url) -> Vec<&str> {
    base.path()
        .split('/')
        .filter(|part| !part.is_empty())
        .collect()
}

fn with_path(base: &Url, parts: Vec<&str>) -> Url {
    let mut url = base.clone();
    url.set_path(&format!("/{}", parts.join("/")));
    url
}

fn v1_endpoint(base: &Url, endpoint: &str) -> Url {
    let mut parts = path_parts(base);
    if !parts
        .last()
        .is_some_and(|part| part.eq_ignore_ascii_case("v1"))
    {
        parts.push("v1");
    }
    parts.push(endpoint);
    with_path(base, parts)
}

fn sub2api_endpoint(base: &Url) -> Url {
    let parts = path_parts(base);
    if parts.len() >= 2
        && parts[parts.len() - 2].eq_ignore_ascii_case("v1")
        && parts
            .last()
            .is_some_and(|part| part.eq_ignore_ascii_case("usage"))
    {
        return base.clone();
    }
    v1_endpoint(base, "usage")
}

fn management_endpoint(base: &Url, endpoint: &str) -> Url {
    let mut parts = path_parts(base);
    if parts
        .last()
        .is_some_and(|part| part.eq_ignore_ascii_case("v1"))
    {
        parts.pop();
    }
    parts.extend(endpoint.split('/'));
    with_path(base, parts)
}

async fn request(
    context: &ProviderContext,
    url: Url,
    key: &Secret,
    now: OffsetDateTime,
) -> Result<Value, ProviderError> {
    let authorization = crate::providers::http::sensitive(&format!("Bearer {}", key.0))?;
    common::json(
        context
            .http
            .get(url)
            .header("Authorization", authorization)
            .header("Accept", "application/json"),
        now,
    )
    .await
}

fn object<'a>(value: &'a Value, field: &str) -> Result<&'a Value, ProviderError> {
    value
        .get(field)
        .filter(|value| value.is_object())
        .ok_or(ProviderError::InvalidData)
}

fn array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>, ProviderError> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or(ProviderError::InvalidData)
}

fn nonempty_text(value: Option<&Value>) -> Result<Option<String>, ProviderError> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let value = value.as_str().ok_or(ProviderError::InvalidData)?.trim();
    if value.is_empty() || value.len() > MAX_SETTING_LENGTH || value.chars().any(char::is_control) {
        return Err(ProviderError::InvalidData);
    }
    Ok(Some(value.into()))
}

fn required_text(value: Option<&Value>) -> Result<String, ProviderError> {
    nonempty_text(value)?.ok_or(ProviderError::InvalidData)
}

fn required_bool(value: Option<&Value>) -> Result<bool, ProviderError> {
    value
        .and_then(Value::as_bool)
        .ok_or(ProviderError::InvalidData)
}

fn required_number(value: Option<&Value>) -> Result<f64, ProviderError> {
    common::number(value)?.ok_or(ProviderError::InvalidData)
}

fn integer(value: Option<&Value>) -> Result<Option<f64>, ProviderError> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let value = value.as_u64().ok_or(ProviderError::InvalidData)?;
    if value > MAX_SAFE_INTEGER {
        return Err(ProviderError::InvalidData);
    }
    Ok(Some(value as f64))
}

fn required_integer(value: Option<&Value>) -> Result<f64, ProviderError> {
    integer(value)?.ok_or(ProviderError::InvalidData)
}

fn micros(value: Option<&Value>) -> Result<Option<f64>, ProviderError> {
    integer(value).map(|value| value.map(|value| value / 1_000_000.0))
}

fn month_reset(value: Option<&Value>) -> Result<Option<OffsetDateTime>, ProviderError> {
    let Some(raw) = nonempty_text(value)? else {
        return Ok(None);
    };
    let bytes = raw.as_bytes();
    if bytes.len() != 7
        || bytes[4] != b'-'
        || !bytes[..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..].iter().all(u8::is_ascii_digit)
    {
        return Err(ProviderError::InvalidData);
    }
    let year: i32 = raw[..4].parse().map_err(|_| ProviderError::InvalidData)?;
    let month: u8 = raw[5..].parse().map_err(|_| ProviderError::InvalidData)?;
    if !(1..=12).contains(&month) {
        return Err(ProviderError::InvalidData);
    }
    let (year, month) = if month == 12 {
        (year.checked_add(1).ok_or(ProviderError::InvalidData)?, 1)
    } else {
        (year, month + 1)
    };
    OffsetDateTime::parse(&format!("{year:04}-{month:02}-01T00:00:00Z"), &Rfc3339)
        .map(Some)
        .map_err(|_| ProviderError::InvalidData)
}

#[allow(clippy::too_many_arguments)]
fn append_window(
    windows: &mut Vec<QuotaWindow>,
    label: &str,
    used: Option<f64>,
    limit: Option<f64>,
    remaining: Option<f64>,
    unit: &str,
    resets_at: Option<OffsetDateTime>,
    source: &str,
    now: OffsetDateTime,
) -> Result<(), ProviderError> {
    if used.is_some() || remaining.is_some() {
        windows.push(common::window(
            label, used, limit, remaining, unit, resets_at, source, now,
        )?);
    }
    Ok(())
}

fn clawrouter<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(async move {
        let key = common::key(context, "CLAWROUTER_API_KEY")?;
        let base = optional_base(
            context,
            "CLAWROUTER_BASE_URL",
            "https://clawrouter.openclaw.ai",
        )?;
        let usage = fetch_clawrouter_at(context, &key, &base).await?;
        common::usage("clawrouter", &key, base.as_str(), usage)
    })
}

async fn fetch_clawrouter_at(
    context: &ProviderContext,
    key: &Secret,
    base: &Url,
) -> Result<Vec<QuotaWindow>, ProviderError> {
    let now = context.clock.now();
    let root = request(context, v1_endpoint(base, "usage"), key, now).await?;
    clawrouter_windows(&root, now)
}

fn clawrouter_windows(
    root: &Value,
    now: OffsetDateTime,
) -> Result<Vec<QuotaWindow>, ProviderError> {
    let budget = object(root, "budget")?;
    let _configured = required_bool(budget.get("configured"))?;
    let _ledger = required_text(budget.get("ledger"))?;
    let limit = micros(budget.get("limitMicros"))?;
    let spent = micros(budget.get("spentMicros"))?;
    let remaining = micros(budget.get("remainingMicros"))?;
    let reset = month_reset(budget.get("windowKey"))?;

    let usage = object(root, "usage")?;
    let summary = object(usage, "summary")?;
    let requests = required_integer(summary.get("requestCount"))?;
    let _successes = required_integer(summary.get("successCount"))?;
    let _errors = required_integer(summary.get("errorCount"))?;
    let _input_tokens = required_integer(summary.get("inputTokens"))?;
    let _output_tokens = required_integer(summary.get("outputTokens"))?;
    let tokens = required_integer(summary.get("totalTokens"))?;
    let actual_cost = micros(summary.get("actualCostMicros"))?;
    // The provider list is part of the public ledger contract. We do not turn each
    // routed provider into an unbounded number of top-level Quotio windows.
    let _providers = array(usage, "providers")?;

    let mut windows = Vec::new();
    append_window(
        &mut windows,
        "Monthly budget",
        spent,
        limit,
        remaining,
        "USD",
        reset,
        "clawrouter_usage_api",
        now,
    )?;
    append_window(
        &mut windows,
        "Monthly requests",
        Some(requests),
        None,
        None,
        "requests",
        None,
        "clawrouter_usage_api",
        now,
    )?;
    append_window(
        &mut windows,
        "Monthly tokens",
        Some(tokens),
        None,
        None,
        "tokens",
        None,
        "clawrouter_usage_api",
        now,
    )?;
    append_window(
        &mut windows,
        "Monthly actual cost",
        actual_cost,
        None,
        None,
        "USD",
        reset,
        "clawrouter_usage_api",
        now,
    )?;
    Ok(windows)
}

fn litellm<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(async move {
        let key = common::key(context, "LITELLM_API_KEY")?;
        let base = required_base(context, "LITELLM_BASE_URL")?;
        let usage = fetch_litellm_at(context, &key, &base).await?;
        common::usage("litellm", &key, base.as_str(), usage)
    })
}

async fn fetch_litellm_at(
    context: &ProviderContext,
    key: &Secret,
    base: &Url,
) -> Result<Vec<QuotaWindow>, ProviderError> {
    let now = context.clock.now();
    let key_info = request(context, management_endpoint(base, "key/info"), key, now).await?;
    let info = object(&key_info, "info")?;
    let user_id = nonempty_text(info.get("user_id"))?;
    let team_id = nonempty_text(info.get("team_id"))?;
    let key_spend = common::number(info.get("spend"))?;
    if user_id.is_none() && team_id.is_none() {
        return Err(ProviderError::InvalidData);
    }

    let mut windows = Vec::new();
    append_window(
        &mut windows,
        "API key spend",
        key_spend,
        None,
        None,
        "USD",
        None,
        "litellm_key_info_api",
        now,
    )?;
    if let Some(user_id) = user_id {
        let mut endpoint = management_endpoint(base, "user/info");
        endpoint.query_pairs_mut().append_pair("user_id", &user_id);
        let user = request(context, endpoint, key, now).await?;
        litellm_user_windows(&user, &user_id, team_id.as_deref(), now, &mut windows)?;
    } else if let Some(team_id) = team_id {
        let mut endpoint = management_endpoint(base, "team/info");
        endpoint.query_pairs_mut().append_pair("team_id", &team_id);
        let team = request(context, endpoint, key, now).await?;
        litellm_team_windows(&team, &team_id, now, &mut windows)?;
    }
    Ok(windows)
}

fn checked_identifier(value: Option<&Value>, expected: &str) -> Result<(), ProviderError> {
    if let Some(value) = nonempty_text(value)?
        && value != expected
    {
        return Err(ProviderError::InvalidData);
    }
    Ok(())
}

fn litellm_user_windows(
    root: &Value,
    user_id: &str,
    team_id: Option<&str>,
    now: OffsetDateTime,
    windows: &mut Vec<QuotaWindow>,
) -> Result<(), ProviderError> {
    let user = object(root, "user_info")?;
    checked_identifier(user.get("user_id"), user_id)?;
    checked_identifier(root.get("user_id"), user_id)?;
    let spend = common::number(user.get("spend"))?;
    let budget = common::number(user.get("max_budget"))?;
    let reset = common::date(user.get("budget_reset_at"))?;
    append_window(
        windows,
        "Personal spend",
        spend,
        budget,
        None,
        "USD",
        reset,
        "litellm_user_info_api",
        now,
    )?;

    let Some(team_id) = team_id else {
        return Ok(());
    };
    let Some(teams) = root.get("teams").filter(|teams| !teams.is_null()) else {
        return Ok(());
    };
    let teams = teams.as_array().ok_or(ProviderError::InvalidData)?;
    for team in teams {
        let team = team.as_object().ok_or(ProviderError::InvalidData)?;
        if nonempty_text(team.get("team_id"))?.as_deref() != Some(team_id) {
            continue;
        }
        let spend = common::number(team.get("spend"))?;
        let budget = common::number(team.get("max_budget"))?;
        let reset = common::date(team.get("budget_reset_at"))?;
        append_window(
            windows,
            "Team spend",
            spend,
            budget,
            None,
            "USD",
            reset,
            "litellm_user_info_api",
            now,
        )?;
        break;
    }
    Ok(())
}

fn litellm_team_windows(
    root: &Value,
    team_id: &str,
    now: OffsetDateTime,
    windows: &mut Vec<QuotaWindow>,
) -> Result<(), ProviderError> {
    let team = object(root, "team_info")?;
    checked_identifier(team.get("team_id"), team_id)?;
    checked_identifier(root.get("team_id"), team_id)?;
    let spend = common::number(team.get("spend"))?;
    let budget = common::number(team.get("max_budget"))?;
    let reset = common::date(team.get("budget_reset_at"))?;
    append_window(
        windows,
        "Team spend",
        spend,
        budget,
        None,
        "USD",
        reset,
        "litellm_team_info_api",
        now,
    )
}

fn llmproxy<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(async move {
        let key = common::key(context, "LLM_PROXY_API_KEY")?;
        let base = required_base(context, "LLM_PROXY_BASE_URL")?;
        let usage = fetch_llmproxy_at(context, &key, &base).await?;
        common::usage("llmproxy", &key, base.as_str(), usage)
    })
}

async fn fetch_llmproxy_at(
    context: &ProviderContext,
    key: &Secret,
    base: &Url,
) -> Result<Vec<QuotaWindow>, ProviderError> {
    let now = context.clock.now();
    let root = request(context, v1_endpoint(base, "quota-stats"), key, now).await?;
    llmproxy_windows(&root, now)
}

fn sum_field(values: &[Value], field: &str) -> Result<Option<f64>, ProviderError> {
    let mut total = 0.0;
    let mut found = false;
    for value in values {
        if let Some(value) = common::number(value.get(field))? {
            total += value;
            if !total.is_finite() {
                return Err(ProviderError::InvalidData);
            }
            found = true;
        }
    }
    Ok(found.then_some(total))
}

fn sum_llmproxy_tokens(values: &[Value]) -> Result<Option<f64>, ProviderError> {
    let mut total = 0.0;
    let mut found = false;
    for provider in values {
        let Some(tokens) = provider.get("tokens").filter(|tokens| !tokens.is_null()) else {
            continue;
        };
        if !tokens.is_object() {
            return Err(ProviderError::InvalidData);
        }
        for field in ["input_cached", "input_uncached", "output"] {
            if let Some(value) = common::number(tokens.get(field))? {
                total += value;
                if !total.is_finite() {
                    return Err(ProviderError::InvalidData);
                }
                found = true;
            }
        }
    }
    Ok(found.then_some(total))
}

fn llmproxy_windows(root: &Value, now: OffsetDateTime) -> Result<Vec<QuotaWindow>, ProviderError> {
    let providers = root
        .get("providers")
        .and_then(Value::as_object)
        .ok_or(ProviderError::InvalidData)?;
    let mut values = Vec::new();
    let mut minimum_remaining: Option<f64> = None;
    let mut next_reset: Option<OffsetDateTime> = None;
    for provider in providers.values() {
        if !provider.is_object() {
            return Err(ProviderError::InvalidData);
        }
        values.push(provider.clone());
        let Some(groups) = provider
            .get("quota_groups")
            .filter(|groups| !groups.is_null())
        else {
            continue;
        };
        let groups: Vec<&Value> = match groups {
            Value::Array(groups) => groups.iter().collect(),
            Value::Object(groups) => groups.values().collect(),
            _ => return Err(ProviderError::InvalidData),
        };
        for group in groups {
            if !group.is_object() {
                return Err(ProviderError::InvalidData);
            }
            if let Some(remaining) = common::number(group.get("remaining_percent"))? {
                if remaining > 100.0 {
                    return Err(ProviderError::InvalidData);
                }
                minimum_remaining =
                    Some(minimum_remaining.map_or(remaining, |current| current.min(remaining)));
            }
            if let Some(reset) = common::date(group.get("reset_time"))?
                && reset > now
                && next_reset.is_none_or(|current| reset < current)
            {
                next_reset = Some(reset);
            }
        }
    }

    let summary = match root.get("summary").filter(|summary| !summary.is_null()) {
        Some(summary) if summary.is_object() => Some(summary),
        Some(_) => return Err(ProviderError::InvalidData),
        None => None,
    };
    let requests = summary
        .map(|summary| common::number(summary.get("total_requests")))
        .transpose()?
        .flatten()
        .or(sum_field(&values, "total_requests")?);
    let tokens = summary
        .map(|summary| common::number(summary.get("total_tokens")))
        .transpose()?
        .flatten()
        .or(sum_llmproxy_tokens(&values)?);
    let cost = summary
        .map(|summary| common::number(summary.get("approx_cost")))
        .transpose()?
        .flatten()
        .or(sum_field(&values, "approx_cost")?);

    let mut windows = Vec::new();
    if let Some(remaining) = minimum_remaining {
        append_window(
            &mut windows,
            "Lowest upstream quota",
            Some(100.0 - remaining),
            Some(100.0),
            Some(remaining),
            "percent",
            next_reset,
            "llmproxy_quota_stats_api",
            now,
        )?;
    }
    append_window(
        &mut windows,
        "Proxy requests",
        requests,
        None,
        None,
        "requests",
        None,
        "llmproxy_quota_stats_api",
        now,
    )?;
    append_window(
        &mut windows,
        "Proxy tokens",
        tokens,
        None,
        None,
        "tokens",
        None,
        "llmproxy_quota_stats_api",
        now,
    )?;
    append_window(
        &mut windows,
        "Approximate spend",
        cost,
        None,
        None,
        "USD",
        next_reset,
        "llmproxy_quota_stats_api",
        now,
    )?;
    Ok(windows)
}

fn sub2api<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(async move {
        let key = common::key(context, "SUB2API_API_KEY")?;
        let base = required_base(context, "SUB2API_BASE_URL")?;
        let usage = fetch_sub2api_at(context, &key, &base).await?;
        common::usage("sub2api", &key, base.as_str(), usage)
    })
}

async fn fetch_sub2api_at(
    context: &ProviderContext,
    key: &Secret,
    base: &Url,
) -> Result<Vec<QuotaWindow>, ProviderError> {
    let now = context.clock.now();
    let mut endpoint = sub2api_endpoint(base);
    endpoint
        .query_pairs_mut()
        .append_pair("days", "30")
        .append_pair("timezone", "UTC");
    let root = request(context, endpoint, key, now).await?;
    sub2api_windows(&root, now)
}

fn sub2api_windows(root: &Value, now: OffsetDateTime) -> Result<Vec<QuotaWindow>, ProviderError> {
    if let Some(valid) = root.get("isValid").filter(|valid| !valid.is_null()) {
        match valid.as_bool() {
            Some(true) => (),
            Some(false) => return Err(ProviderError::Authentication),
            None => return Err(ProviderError::InvalidData),
        }
    }
    let unit = nonempty_text(root.get("unit"))?.unwrap_or_else(|| "USD".into());
    let mut windows = Vec::new();

    if let Some(quota) = root.get("quota").filter(|quota| !quota.is_null()) {
        if !quota.is_object() {
            return Err(ProviderError::InvalidData);
        }
        let quota_unit = nonempty_text(quota.get("unit"))?.unwrap_or_else(|| unit.clone());
        windows.push(common::window(
            "Key quota",
            Some(required_number(quota.get("used"))?),
            Some(required_number(quota.get("limit"))?),
            Some(required_number(quota.get("remaining"))?),
            &quota_unit,
            None,
            "sub2api_usage_api",
            now,
        )?);
    }

    if let Some(subscription) = root.get("subscription").filter(|value| !value.is_null()) {
        if !subscription.is_object() {
            return Err(ProviderError::InvalidData);
        }
        for (label, used_key, limit_key) in [
            (
                "Daily subscription spend",
                "daily_usage_usd",
                "daily_limit_usd",
            ),
            (
                "Weekly subscription spend",
                "weekly_usage_usd",
                "weekly_limit_usd",
            ),
            (
                "Monthly subscription spend",
                "monthly_usage_usd",
                "monthly_limit_usd",
            ),
        ] {
            append_window(
                &mut windows,
                label,
                common::number(subscription.get(used_key))?,
                common::number(subscription.get(limit_key))?,
                None,
                "USD",
                None,
                "sub2api_usage_api",
                now,
            )?;
        }
    }

    if let Some(rates) = root.get("rate_limits").filter(|rates| !rates.is_null()) {
        let rates = rates.as_array().ok_or(ProviderError::InvalidData)?;
        for rate in rates {
            if !rate.is_object() {
                return Err(ProviderError::InvalidData);
            }
            let window = required_text(rate.get("window"))?;
            let label = match window.as_str() {
                "5h" => "5-hour rate limit".to_owned(),
                "1d" => "Daily rate limit".to_owned(),
                "7d" => "7-day rate limit".to_owned(),
                _ => format!("{window} rate limit"),
            };
            windows.push(common::window(
                &label,
                Some(required_number(rate.get("used"))?),
                Some(required_number(rate.get("limit"))?),
                Some(required_number(rate.get("remaining"))?),
                &unit,
                common::date(rate.get("reset_at"))?,
                "sub2api_usage_api",
                now,
            )?);
        }
    }

    if let Some(balance) = common::number(root.get("balance"))? {
        windows.push(common::window(
            "Wallet balance",
            None,
            None,
            Some(balance),
            &unit,
            None,
            "sub2api_usage_api",
            now,
        )?);
    }
    if let Some(usage) = root.get("usage").filter(|usage| !usage.is_null()) {
        if !usage.is_object() {
            return Err(ProviderError::InvalidData);
        }
        if let Some(today) = usage.get("today").filter(|today| !today.is_null()) {
            if !today.is_object() {
                return Err(ProviderError::InvalidData);
            }
            append_window(
                &mut windows,
                "UTC-day requests",
                common::number(today.get("requests"))?,
                None,
                None,
                "requests",
                None,
                "sub2api_usage_api",
                now,
            )?;
            append_window(
                &mut windows,
                "UTC-day tokens",
                common::number(today.get("total_tokens"))?,
                None,
                None,
                "tokens",
                None,
                "sub2api_usage_api",
                now,
            )?;
            append_window(
                &mut windows,
                "UTC-day actual cost",
                common::number(today.get("actual_cost"))?,
                None,
                None,
                "USD",
                None,
                "sub2api_usage_api",
                now,
            )?;
        }
    }
    Ok(windows)
}

fn openai<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(async move {
        let key = common::key(context, "OPENAI_ADMIN_KEY")?;
        let project = setting(context, "OPENAI_PROJECT_ID")?;
        let usage = fetch_openai_at(
            context,
            &key,
            Url::parse("https://api.openai.com/v1/organization/costs")
                .expect("fixed OpenAI costs URL"),
            Url::parse("https://api.openai.com/v1/organization/usage/completions")
                .expect("fixed OpenAI completions URL"),
            project.as_deref(),
        )
        .await?;
        common::usage(
            "openai",
            &key,
            project.as_deref().unwrap_or("organization"),
            usage,
        )
    })
}

const OPENAI_HISTORY_SECONDS: i64 = 30 * 24 * 60 * 60;
const OPENAI_MAX_PAGES: usize = 100;

fn openai_endpoint(
    mut url: Url,
    now: OffsetDateTime,
    group_by: &str,
    project: Option<&str>,
    page: Option<&str>,
) -> Url {
    let start = now.unix_timestamp().saturating_sub(OPENAI_HISTORY_SECONDS);
    let end = now.unix_timestamp();
    let mut pairs = url.query_pairs_mut();
    pairs.clear();
    pairs.append_pair("start_time", &start.to_string());
    pairs.append_pair("end_time", &end.to_string());
    pairs.append_pair("bucket_width", "1d");
    pairs.append_pair("limit", "31");
    pairs.append_pair("group_by", group_by);
    if let Some(project) = project {
        pairs.append_pair("project_ids", project);
    }
    if let Some(page) = page {
        pairs.append_pair("page", page);
    }
    drop(pairs);
    url
}

#[derive(Default)]
struct OpenAiCostTotals {
    used: f64,
    has_used: bool,
}

#[derive(Default)]
struct OpenAiCompletionTotals {
    requests: f64,
    has_requests: bool,
    input_tokens: f64,
    has_input_tokens: bool,
    output_tokens: f64,
    has_output_tokens: bool,
}

fn accumulate_number(
    total: &mut f64,
    has_total: &mut bool,
    value: Option<f64>,
) -> Result<(), ProviderError> {
    if let Some(value) = value {
        *total += value;
        if !total.is_finite() {
            return Err(ProviderError::InvalidData);
        }
        *has_total = true;
    }
    Ok(())
}

fn openai_page(root: &Value) -> Result<(&[Value], Option<String>), ProviderError> {
    let data = array(root, "data")?;
    match root.get("has_more").and_then(Value::as_bool) {
        Some(false) => Ok((data.as_slice(), None)),
        Some(true) => Ok((data.as_slice(), Some(required_text(root.get("next_page"))?))),
        None => Err(ProviderError::InvalidData),
    }
}

async fn fetch_openai_pages<F>(
    context: &ProviderContext,
    key: &Secret,
    base: Url,
    now: OffsetDateTime,
    group_by: &str,
    project: Option<&str>,
    mut append: F,
) -> Result<(), ProviderError>
where
    F: FnMut(&[Value]) -> Result<(), ProviderError>,
{
    let mut page = None;
    let mut seen = BTreeSet::new();
    for _ in 0..OPENAI_MAX_PAGES {
        let root = request(
            context,
            openai_endpoint(base.clone(), now, group_by, project, page.as_deref()),
            key,
            now,
        )
        .await?;
        let (buckets, next_page) = openai_page(&root)?;
        append(buckets)?;
        let Some(next_page) = next_page else {
            return Ok(());
        };
        if !seen.insert(next_page.clone()) {
            return Err(ProviderError::InvalidData);
        }
        page = Some(next_page);
    }
    Err(ProviderError::InvalidData)
}

fn extend_openai_costs(
    totals: &mut OpenAiCostTotals,
    buckets: &[Value],
) -> Result<(), ProviderError> {
    for bucket in buckets {
        for result in array(bucket, "results")? {
            let Some(amount) = result.get("amount").filter(|amount| !amount.is_null()) else {
                continue;
            };
            if !amount.is_object() {
                return Err(ProviderError::InvalidData);
            }
            let currency = required_text(amount.get("currency"))?;
            if !currency.eq_ignore_ascii_case("usd") {
                return Err(ProviderError::InvalidData);
            }
            accumulate_number(
                &mut totals.used,
                &mut totals.has_used,
                Some(required_number(amount.get("value"))?),
            )?;
        }
    }
    Ok(())
}

fn extend_openai_completions(
    totals: &mut OpenAiCompletionTotals,
    buckets: &[Value],
) -> Result<(), ProviderError> {
    for bucket in buckets {
        for result in array(bucket, "results")? {
            accumulate_number(
                &mut totals.requests,
                &mut totals.has_requests,
                common::number(result.get("num_model_requests"))?,
            )?;
            accumulate_number(
                &mut totals.input_tokens,
                &mut totals.has_input_tokens,
                common::number(result.get("input_tokens"))?,
            )?;
            accumulate_number(
                &mut totals.input_tokens,
                &mut totals.has_input_tokens,
                common::number(result.get("input_audio_tokens"))?,
            )?;
            accumulate_number(
                &mut totals.output_tokens,
                &mut totals.has_output_tokens,
                common::number(result.get("output_tokens"))?,
            )?;
            accumulate_number(
                &mut totals.output_tokens,
                &mut totals.has_output_tokens,
                common::number(result.get("output_audio_tokens"))?,
            )?;
        }
    }
    Ok(())
}

async fn fetch_openai_at(
    context: &ProviderContext,
    key: &Secret,
    costs: Url,
    completions: Url,
    project: Option<&str>,
) -> Result<Vec<QuotaWindow>, ProviderError> {
    let now = context.clock.now();
    let mut cost_totals = OpenAiCostTotals::default();
    fetch_openai_pages(context, key, costs, now, "line_item", project, |buckets| {
        extend_openai_costs(&mut cost_totals, buckets)
    })
    .await?;

    let mut completion_totals = OpenAiCompletionTotals::default();
    fetch_openai_pages(
        context,
        key,
        completions,
        now,
        "model",
        project,
        |buckets| extend_openai_completions(&mut completion_totals, buckets),
    )
    .await?;
    openai_windows(&cost_totals, &completion_totals, now)
}

fn openai_windows(
    costs: &OpenAiCostTotals,
    completions: &OpenAiCompletionTotals,
    now: OffsetDateTime,
) -> Result<Vec<QuotaWindow>, ProviderError> {
    let mut windows = Vec::new();
    append_window(
        &mut windows,
        "Past 30 days organization spend",
        costs.has_used.then_some(costs.used),
        None,
        None,
        "USD",
        None,
        "openai_organization_costs_api",
        now,
    )?;
    append_window(
        &mut windows,
        "Past 30 days completion requests",
        completions.has_requests.then_some(completions.requests),
        None,
        None,
        "requests",
        None,
        "openai_organization_usage_api",
        now,
    )?;
    append_window(
        &mut windows,
        "Past 30 days input tokens",
        completions
            .has_input_tokens
            .then_some(completions.input_tokens),
        None,
        None,
        "tokens",
        None,
        "openai_organization_usage_api",
        now,
    )?;
    append_window(
        &mut windows,
        "Past 30 days output tokens",
        completions
            .has_output_tokens
            .then_some(completions.output_tokens),
        None,
        None,
        "tokens",
        None,
        "openai_organization_usage_api",
        now,
    )?;
    Ok(windows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::http::fixture;
    use serde_json::json;

    #[test]
    fn custom_bases_require_a_clean_https_origin() {
        for value in [
            "http://proxy.example.test",
            "https://key@proxy.example.test",
            "https://proxy.example.test/?key=value",
            "https://proxy.example.test/#fragment",
            "proxy.example.test",
        ] {
            assert_eq!(https_base(value).unwrap_err(), ProviderError::InvalidData);
        }
        let base = https_base("https://proxy.example.test/gateway/v1").unwrap();
        assert_eq!(
            v1_endpoint(&base, "usage").as_str(),
            "https://proxy.example.test/gateway/v1/usage"
        );
        assert_eq!(
            management_endpoint(&base, "key/info").as_str(),
            "https://proxy.example.test/gateway/key/info"
        );
    }

    #[test]
    fn clawrouter_preserves_budget_and_ledger_totals() {
        let windows = clawrouter_windows(
            &json!({
                "budget": {"configured": true, "ledger": "acct", "limitMicros": 10_000_000u64, "spentMicros": 2_500_000u64, "remainingMicros": 7_500_000u64, "windowKey": "2026-09"},
                "usage": {"summary": {"requestCount": 3, "successCount": 3, "errorCount": 0, "inputTokens": 5, "outputTokens": 7, "totalTokens": 12, "actualCostMicros": 2_000_000u64}, "providers": []}
            }),
            OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap();
        assert_eq!(windows[0].amounts.as_ref().unwrap().remaining, 7.5);
        assert_eq!(windows[0].consumption.as_ref().unwrap().used, 2.5);
        assert!(windows[0].resets_at.is_some());
        assert_eq!(windows[2].consumption.as_ref().unwrap().used, 12.0);
    }

    #[tokio::test]
    async fn gateway_requests_use_usage_endpoints_and_sensitive_bearer_auth() {
        let key = Secret("synthetic-key".into());

        let (base, task) = fixture::server(vec![json!({
            "budget": {"configured": false, "ledger": "ledger", "windowKey": "2026-09"},
            "usage": {"summary": {"requestCount": 0, "successCount": 0, "errorCount": 0, "inputTokens": 0, "outputTokens": 0, "totalTokens": 0, "actualCostMicros": 0}, "providers": []}
        })])
        .await;
        let context = fixture::context();
        let windows = fetch_clawrouter_at(&context, &key, &Url::parse(&base).unwrap())
            .await
            .unwrap();
        assert_eq!(windows.len(), 3);
        let requests = task.await.unwrap();
        assert!(requests[0].starts_with("GET /v1/usage "));
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains("authorization: bearer synthetic-key")
        );

        let (base, task) = fixture::server(vec![
            json!({"info": {"user_id": "user-1", "spend": 1.25}}),
            json!({"user_id": "user-1", "user_info": {"user_id": "user-1", "spend": 3.0, "max_budget": 10.0, "budget_reset_at": "2026-10-01T00:00:00Z"}, "teams": []}),
        ])
        .await;
        let windows = fetch_litellm_at(&context, &key, &Url::parse(&base).unwrap())
            .await
            .unwrap();
        assert_eq!(windows.len(), 2);
        let requests = task.await.unwrap();
        assert!(requests[0].starts_with("GET /key/info "));
        assert!(requests[1].starts_with("GET /user/info?user_id=user-1 "));

        let (base, task) = fixture::server(vec![json!({
            "providers": {"openai": {"total_requests": 4, "tokens": {"input_cached": 1, "input_uncached": 2, "output": 3}, "approx_cost": 0.5, "quota_groups": [{"remaining_percent": 75, "reset_time": "2026-10-01T00:00:00Z"}]}},
            "summary": {"total_requests": 4, "approx_cost": 0.5}
        })])
        .await;
        let windows = fetch_llmproxy_at(&context, &key, &Url::parse(&base).unwrap())
            .await
            .unwrap();
        assert_eq!(
            windows[0].quota,
            crate::domain::Quota::from_remaining(Some(75.0))
        );
        assert_eq!(windows.len(), 4);
        assert_eq!(windows[2].consumption.as_ref().unwrap().used, 6.0);
        let requests = task.await.unwrap();
        assert!(requests[0].starts_with("GET /v1/quota-stats "));

        let (base, task) = fixture::server(vec![json!({
            "isValid": true,
            "quota": {"used": 2, "limit": 10, "remaining": 8, "unit": "USD"},
            "rate_limits": [{"window": "5h", "used": 1, "limit": 5, "remaining": 4, "reset_at": "2026-10-01T00:00:00Z"}],
            "usage": {"today": {"requests": 3, "total_tokens": 9, "actual_cost": 0.25}}
        })])
        .await;
        let windows = fetch_sub2api_at(&context, &key, &Url::parse(&base).unwrap())
            .await
            .unwrap();
        assert_eq!(windows.len(), 5);
        let requests = task.await.unwrap();
        assert!(requests[0].starts_with("GET /v1/usage?days=30&timezone=UTC "));

        let (base, task) = fixture::server(vec![
            json!({"data": [{"results": [{"amount": {"value": 1.5, "currency": "usd"}}]}], "has_more": true, "next_page": "cost-page"}),
            json!({"data": [{"results": [{"amount": {"value": 0.5, "currency": "usd"}}]}], "has_more": false, "next_page": null}),
            json!({"data": [{"results": [{"num_model_requests": 2, "input_tokens": 3, "input_audio_tokens": 5, "output_tokens": 4, "output_audio_tokens": 6}]}], "has_more": true, "next_page": "usage-page"}),
            json!({"data": [{"results": [{"num_model_requests": 1, "input_tokens": 2, "output_tokens": 3}]}], "has_more": false, "next_page": null}),
        ])
        .await;
        let costs = Url::parse(&format!("{base}/costs")).unwrap();
        let completions = Url::parse(&format!("{base}/usage/completions")).unwrap();
        let windows = fetch_openai_at(&context, &key, costs, completions, Some("proj_1"))
            .await
            .unwrap();
        assert_eq!(windows.len(), 4);
        assert_eq!(windows[0].consumption.as_ref().unwrap().used, 2.0);
        assert_eq!(windows[1].consumption.as_ref().unwrap().used, 3.0);
        assert_eq!(windows[2].consumption.as_ref().unwrap().used, 10.0);
        assert_eq!(windows[3].consumption.as_ref().unwrap().used, 13.0);
        let requests = task.await.unwrap();
        assert_eq!(requests.len(), 4);
        assert!(requests[0].starts_with("GET /costs?"));
        assert!(requests[0].contains("start_time=-2592000"));
        assert!(requests[0].contains("group_by=line_item"));
        assert!(requests[0].contains("project_ids=proj_1"));
        assert!(requests[1].starts_with("GET /costs?"));
        assert!(requests[1].contains("page=cost-page"));
        assert!(requests[2].starts_with("GET /usage/completions?"));
        assert!(requests[2].contains("group_by=model"));
        assert!(requests[3].starts_with("GET /usage/completions?"));
        assert!(requests[3].contains("page=usage-page"));
    }

    #[test]
    fn sub2api_does_not_turn_missing_usage_into_zero() {
        let windows =
            sub2api_windows(&json!({"isValid": true}), OffsetDateTime::UNIX_EPOCH).unwrap();
        assert!(windows.is_empty());
        assert!(matches!(
            common::usage("sub2api", &Secret("key".into()), "scope", windows),
            Err(ProviderError::InvalidData)
        ));
    }

    #[test]
    fn gateway_parsers_fail_closed_on_unusable_accounting_data() {
        assert_eq!(
            sub2api_windows(&json!({"isValid": false}), OffsetDateTime::UNIX_EPOCH).unwrap_err(),
            ProviderError::Authentication
        );
        assert_eq!(
            llmproxy_windows(
                &json!({"providers": {"openai": {"quota_groups": [{"remaining_percent": 101}]}}}),
                OffsetDateTime::UNIX_EPOCH,
            )
            .unwrap_err(),
            ProviderError::InvalidData
        );
    }

    #[tokio::test]
    async fn openai_rejects_repeated_page_cursors_without_returning_partial_totals() {
        let (base, task) = fixture::server(vec![
            json!({"data": [{"results": [{"amount": {"value": 1.0, "currency": "usd"}}]}], "has_more": true, "next_page": "same-page"}),
            json!({"data": [{"results": [{"amount": {"value": 2.0, "currency": "usd"}}]}], "has_more": true, "next_page": "same-page"}),
        ])
        .await;
        let context = fixture::context();
        let error = fetch_openai_at(
            &context,
            &Secret("synthetic-key".into()),
            Url::parse(&format!("{base}/costs")).unwrap(),
            Url::parse(&format!("{base}/usage/completions")).unwrap(),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error, ProviderError::InvalidData);
        let requests = task.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("page=same-page"));
    }
}
