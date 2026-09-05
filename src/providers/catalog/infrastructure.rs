use super::{AuthKind, Definition, Setting, common};
use crate::{
    domain::QuotaWindow,
    error::ProviderError,
    providers::{FetchFuture, ProviderContext, Secret},
};
use reqwest::{
    Url,
    header::{ACCEPT, AUTHORIZATION, HeaderName},
};
use serde_json::{Map, Value};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const CHUTES_USAGE_URL: &str = "https://api.chutes.ai/users/me/subscription_usage";
const DEEPINFRA_CHECKLIST_URL: &str =
    "https://api.deepinfra.com/payment/checklist?compute_owed=true";
const DEEPINFRA_USAGE_URL: &str = "https://api.deepinfra.com/payment/usage?from=current";
const FIREWORKS_API_BASE: &str = "https://api.fireworks.ai";
const GROQ_PROMETHEUS_QUERY_URL: &str = "https://api.groq.com/v1/metrics/prometheus/api/v1/query?query=sum%28model_project_id_status_code%3Arequests%3Arate5m%29";
const DEEPGRAM_API_BASE: &str = "https://api.deepgram.com/v1";
const ELEVENLABS_SUBSCRIPTION_URL: &str = "https://api.elevenlabs.io/v1/user/subscription";
const NEURALWATT_QUOTA_URL: &str = "https://api.neuralwatt.com/v1/quota";

const FIREWORKS_SETTINGS: &[Setting] = &[Setting {
    name: "account_id",
    env: "FIREWORKS_ACCOUNT_ID",
    required: true,
}];
const DEEPGRAM_SETTINGS: &[Setting] = &[Setting {
    name: "project_id",
    env: "DEEPGRAM_PROJECT_ID",
    required: true,
}];

pub const DEFINITIONS: &[Definition] = &[
    Definition {
        id: "chutes",
        name: "Chutes",
        key_env: "CHUTES_API_KEY",
        auth: AuthKind::ApiKey,
        settings: &[],
        fetch: chutes,
    },
    Definition {
        id: "deepinfra",
        name: "DeepInfra",
        key_env: "DEEPINFRA_API_KEY",
        auth: AuthKind::ApiKey,
        settings: &[],
        fetch: deepinfra,
    },
    Definition {
        id: "fireworks",
        name: "Fireworks",
        key_env: "FIREWORKS_API_KEY",
        auth: AuthKind::ApiKey,
        settings: FIREWORKS_SETTINGS,
        fetch: fireworks,
    },
    Definition {
        id: "groq",
        name: "Groq",
        key_env: "GROQ_API_KEY",
        auth: AuthKind::ApiKey,
        settings: &[],
        fetch: groq,
    },
    Definition {
        id: "deepgram",
        name: "Deepgram",
        key_env: "DEEPGRAM_API_KEY",
        auth: AuthKind::ApiKey,
        settings: DEEPGRAM_SETTINGS,
        fetch: deepgram,
    },
    Definition {
        id: "elevenlabs",
        name: "ElevenLabs",
        key_env: "ELEVENLABS_API_KEY",
        auth: AuthKind::ApiKey,
        settings: &[],
        fetch: elevenlabs,
    },
    Definition {
        id: "neuralwatt",
        name: "NeuralWatt",
        key_env: "NEURALWATT_API_KEY",
        auth: AuthKind::ApiKey,
        settings: &[],
        fetch: neuralwatt,
    },
];

fn chutes<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(fetch_chutes_at(context, CHUTES_USAGE_URL))
}

async fn fetch_chutes_at(
    context: &ProviderContext,
    endpoint: &str,
) -> Result<crate::domain::ProviderUsage, ProviderError> {
    let key = common::key(context, "CHUTES_API_KEY")?;
    let now = context.clock.now();
    let body = bearer_json(context, endpoint, &key).await?;
    common::usage(
        "chutes",
        &key,
        "subscription_usage",
        parse_chutes(&body, now)?,
    )
}

fn deepinfra<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(fetch_deepinfra_at(
        context,
        DEEPINFRA_CHECKLIST_URL,
        DEEPINFRA_USAGE_URL,
    ))
}

async fn fetch_deepinfra_at(
    context: &ProviderContext,
    checklist_endpoint: &str,
    usage_endpoint: &str,
) -> Result<crate::domain::ProviderUsage, ProviderError> {
    let key = common::key(context, "DEEPINFRA_API_KEY")?;
    let now = context.clock.now();
    let checklist = bearer_json(context, checklist_endpoint, &key).await?;
    let usage = bearer_json(context, usage_endpoint, &key).await?;
    common::usage(
        "deepinfra",
        &key,
        "billing",
        parse_deepinfra(&checklist, &usage, now)?,
    )
}

fn fireworks<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(async move {
        let account = account_id(context, "FIREWORKS_ACCOUNT_ID")?;
        let now = context.clock.now();
        let endpoint = fireworks_endpoint(FIREWORKS_API_BASE, &account, now)?;
        fetch_fireworks_at(context, &endpoint, &account, now).await
    })
}

async fn fetch_fireworks_at(
    context: &ProviderContext,
    endpoint: &str,
    account: &str,
    now: OffsetDateTime,
) -> Result<crate::domain::ProviderUsage, ProviderError> {
    let key = common::key(context, "FIREWORKS_API_KEY")?;
    let body = bearer_json(context, endpoint, &key).await?;
    common::usage("fireworks", &key, account, parse_fireworks(&body, now)?)
}

fn fireworks_endpoint(
    api_base: &str,
    account: &str,
    now: OffsetDateTime,
) -> Result<String, ProviderError> {
    let start = (now - Duration::days(30))
        .format(&Rfc3339)
        .map_err(|_| ProviderError::Internal)?;
    let end = now.format(&Rfc3339).map_err(|_| ProviderError::Internal)?;
    let mut url = Url::parse(api_base).map_err(|_| ProviderError::InvalidData)?;
    let prefix = url.path().trim_end_matches('/').to_owned();
    url.set_path(&format!("{prefix}/v1/accounts/{account}/billing/summary"));
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("startTime", &start);
        query.append_pair("endTime", &end);
    }
    Ok(url.into())
}

fn groq<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(fetch_groq_at(context, GROQ_PROMETHEUS_QUERY_URL))
}

async fn fetch_groq_at(
    context: &ProviderContext,
    endpoint: &str,
) -> Result<crate::domain::ProviderUsage, ProviderError> {
    let key = common::key(context, "GROQ_API_KEY")?;
    let now = context.clock.now();
    let body = bearer_json(context, endpoint, &key).await?;
    common::usage(
        "groq",
        &key,
        "enterprise-prometheus",
        parse_groq(&body, now)?,
    )
}

fn deepgram<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(async move {
        let project = project_id(context, "DEEPGRAM_PROJECT_ID")?;
        let endpoint = format!("{DEEPGRAM_API_BASE}/projects/{project}/usage/breakdown");
        fetch_deepgram_at(context, &endpoint, &project).await
    })
}

async fn fetch_deepgram_at(
    context: &ProviderContext,
    endpoint: &str,
    project: &str,
) -> Result<crate::domain::ProviderUsage, ProviderError> {
    let key = common::key(context, "DEEPGRAM_API_KEY")?;
    let now = context.clock.now();
    let body = token_json(context, endpoint, &key).await?;
    common::usage("deepgram", &key, project, parse_deepgram(&body, now)?)
}

fn elevenlabs<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(fetch_elevenlabs_at(context, ELEVENLABS_SUBSCRIPTION_URL))
}

async fn fetch_elevenlabs_at(
    context: &ProviderContext,
    endpoint: &str,
) -> Result<crate::domain::ProviderUsage, ProviderError> {
    let key = common::key(context, "ELEVENLABS_API_KEY")?;
    let now = context.clock.now();
    let body = named_key_json(context, endpoint, "xi-api-key", &key).await?;
    let (windows, plan) = parse_elevenlabs(&body, now)?;
    let mut usage = common::usage("elevenlabs", &key, "subscription", windows)?;
    usage.account.plan = plan;
    Ok(usage)
}

fn neuralwatt<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(fetch_neuralwatt_at(context, NEURALWATT_QUOTA_URL))
}

async fn fetch_neuralwatt_at(
    context: &ProviderContext,
    endpoint: &str,
) -> Result<crate::domain::ProviderUsage, ProviderError> {
    let key = common::key(context, "NEURALWATT_API_KEY")?;
    let now = context.clock.now();
    let body = bearer_json(context, endpoint, &key).await?;
    let (windows, plan) = parse_neuralwatt(&body, now)?;
    let mut usage = common::usage("neuralwatt", &key, "quota", windows)?;
    usage.account.plan = plan;
    Ok(usage)
}

fn account_id(context: &ProviderContext, env: &str) -> Result<String, ProviderError> {
    identifier(context, env, |character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
    })
}

fn project_id(context: &ProviderContext, env: &str) -> Result<String, ProviderError> {
    identifier(context, env, |character| {
        character.is_ascii_alphanumeric() || character == '-'
    })
}

fn identifier(
    context: &ProviderContext,
    env: &str,
    allowed: impl Fn(char) -> bool,
) -> Result<String, ProviderError> {
    let value = common::key(context, env)?.0;
    if value.len() > 128 || value.is_empty() || !value.chars().all(allowed) {
        return Err(ProviderError::InvalidData);
    }
    Ok(value)
}

async fn bearer_json(
    context: &ProviderContext,
    url: &str,
    key: &Secret,
) -> Result<Value, ProviderError> {
    let value = format!("Bearer {}", key.0);
    protected_json(context, url, AUTHORIZATION, &value).await
}

async fn token_json(
    context: &ProviderContext,
    url: &str,
    key: &Secret,
) -> Result<Value, ProviderError> {
    let value = format!("Token {}", key.0);
    protected_json(context, url, AUTHORIZATION, &value).await
}

async fn named_key_json(
    context: &ProviderContext,
    url: &str,
    name: &'static str,
    key: &Secret,
) -> Result<Value, ProviderError> {
    protected_json(context, url, HeaderName::from_static(name), &key.0).await
}

async fn protected_json(
    context: &ProviderContext,
    url: &str,
    header: HeaderName,
    value: &str,
) -> Result<Value, ProviderError> {
    common::json(
        context
            .http
            .get(url)
            .header(header, crate::providers::http::sensitive(value)?)
            .header(ACCEPT, "application/json"),
        context.clock.now(),
    )
    .await
}

fn wrapped(value: &Value) -> Result<&Map<String, Value>, ProviderError> {
    let root = object(value)?;
    match root.get("data") {
        Some(Value::Object(data)) => Ok(data),
        Some(_) => Err(ProviderError::InvalidData),
        None => Ok(root),
    }
}

fn object(value: &Value) -> Result<&Map<String, Value>, ProviderError> {
    value.as_object().ok_or(ProviderError::InvalidData)
}

fn optional_object<'a>(
    fields: &'a Map<String, Value>,
    name: &str,
) -> Result<Option<&'a Map<String, Value>>, ProviderError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => object(value).map(Some),
    }
}

fn array(value: Option<&Value>) -> Result<&Vec<Value>, ProviderError> {
    value
        .and_then(Value::as_array)
        .ok_or(ProviderError::InvalidData)
}

fn field<'a>(object: &'a Map<String, Value>, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|name| object.get(*name))
}

fn number(object: &Map<String, Value>, names: &[&str]) -> Result<Option<f64>, ProviderError> {
    common::number(field(object, names))
}

fn whole_number(object: &Map<String, Value>, names: &[&str]) -> Result<Option<f64>, ProviderError> {
    let value = number(object, names)?;
    if value.is_some_and(|value| value.fract() != 0.0) {
        return Err(ProviderError::InvalidData);
    }
    Ok(value)
}

fn date(
    object: &Map<String, Value>,
    names: &[&str],
) -> Result<Option<OffsetDateTime>, ProviderError> {
    common::date(field(object, names))
}

fn string(object: &Map<String, Value>, names: &[&str]) -> Result<Option<String>, ProviderError> {
    match field(object, names) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            let value = value.trim();
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err(ProviderError::InvalidData);
            }
            Ok(Some(value.into()))
        }
        Some(_) => Err(ProviderError::InvalidData),
    }
}

fn signed_number(value: Option<&Value>) -> Result<Option<f64>, ProviderError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let number = match value {
        Value::Number(value) => value.as_f64(),
        Value::String(value) => value.trim().parse::<f64>().ok(),
        _ => None,
    }
    .filter(|value| value.is_finite());
    number.ok_or(ProviderError::InvalidData).map(Some)
}

// This mirrors common::window exactly while preserving the call sites' source semantics.
#[allow(clippy::too_many_arguments)]
fn push_window(
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
    if used.is_some() || limit.is_some() || remaining.is_some() {
        windows.push(common::window(
            label, used, limit, remaining, unit, resets_at, source, now,
        )?);
    }
    Ok(())
}

fn parse_chutes(value: &Value, now: OffsetDateTime) -> Result<Vec<QuotaWindow>, ProviderError> {
    let root = wrapped(value)?;
    let mut windows = Vec::new();
    for (name, label) in [
        ("rolling", "Rolling quota"),
        ("rolling_window", "Rolling quota"),
        ("monthly", "Monthly quota"),
        ("monthly_usage", "Monthly quota"),
        ("subscription_usage", "Subscription quota"),
    ] {
        let Some(candidate) = root.get(name) else {
            continue;
        };
        let candidate = object(candidate)?;
        let unit = string(candidate, &["unit", "quota_unit"])?;
        push_window(
            &mut windows,
            label,
            number(candidate, &["used", "usage", "current_usage", "requests"])?,
            number(candidate, &["limit", "quota_limit", "quota"])?,
            number(candidate, &["remaining", "available"])?,
            unit.as_deref().unwrap_or("credits"),
            date(candidate, &["reset_at", "resets_at", "period_end"])?,
            "Chutes subscription usage",
            now,
        )?;
    }
    if let Some(quotas) = root.get("quotas") {
        for quota in array(Some(quotas))? {
            let quota = object(quota)?;
            let label =
                string(quota, &["label", "name", "chute_id"])?.unwrap_or_else(|| "Quota".into());
            let unit = string(quota, &["unit", "quota_unit"])?;
            push_window(
                &mut windows,
                &label,
                number(quota, &["used", "usage", "current_usage", "requests"])?,
                number(quota, &["limit", "quota_limit", "quota"])?,
                number(quota, &["remaining", "available"])?,
                unit.as_deref().unwrap_or("credits"),
                date(quota, &["reset_at", "resets_at", "period_end"])?,
                "Chutes quota usage",
                now,
            )?;
        }
    }
    if windows.is_empty() {
        return Err(ProviderError::InvalidData);
    }
    Ok(windows)
}

fn parse_deepinfra(
    checklist: &Value,
    usage: &Value,
    now: OffsetDateTime,
) -> Result<Vec<QuotaWindow>, ProviderError> {
    let checklist = object(checklist)?;
    let stripe_balance =
        signed_number(checklist.get("stripe_balance"))?.ok_or(ProviderError::InvalidData)?;
    let recent = number(checklist, &["recent"])?.ok_or(ProviderError::InvalidData)?;
    let net_balance = stripe_balance + recent;
    let available = (-net_balance).max(0.0);
    let owed = net_balance.max(0.0);
    let usage = object(usage)?;
    let months = array(usage.get("months"))?;
    let current_month = months
        .last()
        .map(object)
        .transpose()?
        .map(|month| number(month, &["total_cost"]))
        .transpose()?
        .flatten()
        .map(|cents| cents / 100.0)
        .unwrap_or(recent);
    let limit = number(checklist, &["limit"])?.filter(|limit| *limit > 0.0);
    let mut windows = Vec::new();
    push_window(
        &mut windows,
        "Prepaid balance",
        None,
        None,
        Some(available),
        "USD",
        None,
        "DeepInfra billing checklist",
        now,
    )?;
    push_window(
        &mut windows,
        "Current-month spend",
        Some(current_month),
        None,
        None,
        "USD",
        None,
        "DeepInfra billing usage",
        now,
    )?;
    if owed > 0.0 {
        push_window(
            &mut windows,
            "Outstanding balance",
            Some(owed),
            None,
            None,
            "USD",
            None,
            "DeepInfra billing checklist",
            now,
        )?;
    }
    if let Some(limit) = limit {
        push_window(
            &mut windows,
            "Spending limit",
            Some(current_month),
            Some(limit),
            Some((limit - current_month).max(0.0)),
            "USD",
            None,
            "DeepInfra billing checklist",
            now,
        )?;
    }
    Ok(windows)
}

fn parse_fireworks(value: &Value, now: OffsetDateTime) -> Result<Vec<QuotaWindow>, ProviderError> {
    let root = object(value)?;
    let line_items = array(root.get("lineItems"))?;
    let mut currency = None;
    let mut total = 0.0;
    for item in line_items {
        let item = object(item)?;
        let Some(cost) = item.get("totalCost") else {
            continue;
        };
        let cost = object(cost)?;
        // Fireworks uses Google Money: `units` and `nanos` jointly encode the amount.
        // The source reference accepts a line only when both are present, so an omitted
        // component is never assumed to be zero.
        let (Some(units), Some(nanos)) = (
            whole_number(cost, &["units"])?,
            whole_number(cost, &["nanos"])?,
        ) else {
            continue;
        };
        if nanos > 999_999_999.0 {
            return Err(ProviderError::InvalidData);
        }
        let code = string(cost, &["currencyCode"])?.ok_or(ProviderError::InvalidData)?;
        if currency.is_none() {
            currency = Some(code.clone());
        }
        if currency.as_deref() == Some(code.as_str()) {
            total += units + nanos / 1_000_000_000.0;
        }
    }
    let currency = currency.ok_or(ProviderError::InvalidData)?;
    let mut windows = Vec::new();
    push_window(
        &mut windows,
        "Last 30 days spend",
        Some(total),
        None,
        None,
        &currency,
        None,
        "Fireworks billing summary",
        now,
    )?;
    Ok(windows)
}
fn parse_groq(value: &Value, now: OffsetDateTime) -> Result<Vec<QuotaWindow>, ProviderError> {
    let root = object(value)?;
    if string(root, &["status"])?.as_deref() != Some("success") {
        return Err(ProviderError::InvalidData);
    }
    let data = root
        .get("data")
        .map(object)
        .transpose()?
        .ok_or(ProviderError::InvalidData)?;
    let result = array(data.get("result"))?;
    let mut rate = 0.0;
    for series in result {
        let series = object(series)?;
        let value = array(series.get("value"))?;
        let scalar = value.get(1).ok_or(ProviderError::InvalidData)?;
        rate += common::number(Some(scalar))?.ok_or(ProviderError::InvalidData)?;
    }
    let mut windows = Vec::new();
    push_window(
        &mut windows,
        "5-minute request rate",
        Some(rate),
        None,
        None,
        "requests/s",
        None,
        "Groq Enterprise Prometheus",
        now,
    )?;
    Ok(windows)
}

fn parse_deepgram(value: &Value, now: OffsetDateTime) -> Result<Vec<QuotaWindow>, ProviderError> {
    let root = object(value)?;
    let results = array(root.get("results"))?;
    if results.is_empty() {
        return Err(ProviderError::InvalidData);
    }
    let mut requests = Sum::default();
    let mut audio_hours = Sum::default();
    let mut total_hours = Sum::default();
    let mut agent_hours = Sum::default();
    let mut tokens = Sum::default();
    let mut tts_characters = Sum::default();
    for result in results {
        let result = object(result)?;
        requests.add(number(result, &["requests"])?);
        audio_hours.add(number(result, &["hours"])?);
        total_hours.add(number(result, &["total_hours"])?);
        agent_hours.add(number(result, &["agent_hours"])?);
        tokens.add(number(result, &["tokens_in"])?);
        tokens.add(number(result, &["tokens_out"])?);
        tts_characters.add(number(result, &["tts_characters"])?);
    }
    let mut windows = Vec::new();
    add_consumption(
        &mut windows,
        "Requests",
        requests,
        "requests",
        "Deepgram usage breakdown",
        now,
    )?;
    add_consumption(
        &mut windows,
        "Audio",
        audio_hours,
        "hours",
        "Deepgram usage breakdown",
        now,
    )?;
    add_consumption(
        &mut windows,
        "Billable audio",
        total_hours,
        "hours",
        "Deepgram usage breakdown",
        now,
    )?;
    add_consumption(
        &mut windows,
        "Agent audio",
        agent_hours,
        "hours",
        "Deepgram usage breakdown",
        now,
    )?;
    add_consumption(
        &mut windows,
        "Tokens",
        tokens,
        "tokens",
        "Deepgram usage breakdown",
        now,
    )?;
    add_consumption(
        &mut windows,
        "TTS characters",
        tts_characters,
        "characters",
        "Deepgram usage breakdown",
        now,
    )?;
    if windows.is_empty() {
        return Err(ProviderError::InvalidData);
    }
    Ok(windows)
}

fn parse_elevenlabs(
    value: &Value,
    now: OffsetDateTime,
) -> Result<(Vec<QuotaWindow>, Option<String>), ProviderError> {
    let root = object(value)?;
    let count = number(root, &["character_count"])?.ok_or(ProviderError::InvalidData)?;
    let limit = number(root, &["character_limit"])?.ok_or(ProviderError::InvalidData)?;
    let reset = date(root, &["next_character_count_reset_unix"])?;
    let mut windows = Vec::new();
    push_window(
        &mut windows,
        "Characters",
        Some(count),
        Some(limit),
        Some((limit - count).max(0.0)),
        "characters",
        reset,
        "ElevenLabs user subscription",
        now,
    )?;
    add_limit_window(
        &mut windows,
        "Voice slots",
        root,
        "voice_slots_used",
        "voice_limit",
        now,
    )?;
    add_limit_window(
        &mut windows,
        "Professional voice slots",
        root,
        "professional_voice_slots_used",
        "professional_voice_limit",
        now,
    )?;
    Ok((windows, string(root, &["tier"])?))
}

fn parse_neuralwatt(
    value: &Value,
    now: OffsetDateTime,
) -> Result<(Vec<QuotaWindow>, Option<String>), ProviderError> {
    let root = object(value)?;
    let balance = root
        .get("balance")
        .map(object)
        .transpose()?
        .ok_or(ProviderError::InvalidData)?;
    let remaining = number(balance, &["credits_remaining_usd"])?;
    let total = number(balance, &["total_credits_usd"])?;
    let used = number(balance, &["credits_used_usd"])?;
    let remaining =
        remaining.or_else(|| total.zip(used).map(|(total, used)| (total - used).max(0.0)));
    if remaining.is_none() && total.is_none() && used.is_none() {
        return Err(ProviderError::InvalidData);
    }
    let mut windows = Vec::new();
    if let Some(remaining) = remaining {
        push_window(
            &mut windows,
            "Prepaid balance",
            None,
            None,
            Some(remaining),
            "USD",
            None,
            "NeuralWatt quota",
            now,
        )?;
    }
    let subscription = optional_object(root, "subscription")?;
    if let Some(subscription) = subscription {
        let included = number(subscription, &["kwh_included"])?;
        let used = number(subscription, &["kwh_used"])?;
        let remaining = number(subscription, &["kwh_remaining"])?;
        let total = included.or_else(|| {
            used.zip(remaining)
                .map(|(used, remaining)| used + remaining)
        });
        let used = used.or_else(|| {
            total
                .zip(remaining)
                .map(|(total, remaining)| (total - remaining).max(0.0))
        });
        push_window(
            &mut windows,
            "Subscription energy",
            used,
            total,
            remaining,
            "kWh",
            date(subscription, &["current_period_end"])?,
            "NeuralWatt quota",
            now,
        )?;
    }
    if let Some(key) = optional_object(root, "key")?
        && let Some(allowance) = optional_object(key, "allowance")?
    {
        let label = string(allowance, &["period"])?
            .map(|period| format!("Key {period} allowance"))
            .unwrap_or_else(|| "Key allowance".into());
        push_window(
            &mut windows,
            &label,
            number(allowance, &["spent_usd"])?,
            number(allowance, &["limit_usd"])?,
            number(allowance, &["remaining_usd"])?,
            "USD",
            None,
            "NeuralWatt key allowance",
            now,
        )?;
    }
    if let Some(usage) = optional_object(root, "usage")?
        && let Some(current_month) = optional_object(usage, "current_month")?
    {
        push_window(
            &mut windows,
            "Current-month spend",
            number(current_month, &["cost_usd"])?,
            None,
            None,
            "USD",
            None,
            "NeuralWatt quota",
            now,
        )?;
    }
    if windows.is_empty() {
        return Err(ProviderError::InvalidData);
    }
    let plan = subscription
        .map(|subscription| string(subscription, &["plan"]))
        .transpose()?
        .flatten();
    Ok((windows, plan))
}

#[derive(Default)]
struct Sum {
    value: f64,
    seen: bool,
}

impl Sum {
    fn add(&mut self, value: Option<f64>) {
        if let Some(value) = value {
            self.value += value;
            self.seen = true;
        }
    }
}

fn add_consumption(
    windows: &mut Vec<QuotaWindow>,
    label: &str,
    sum: Sum,
    unit: &str,
    source: &str,
    now: OffsetDateTime,
) -> Result<(), ProviderError> {
    if sum.seen {
        push_window(
            windows,
            label,
            Some(sum.value),
            None,
            None,
            unit,
            None,
            source,
            now,
        )?;
    }
    Ok(())
}

fn add_limit_window(
    windows: &mut Vec<QuotaWindow>,
    label: &str,
    root: &Map<String, Value>,
    used_field: &str,
    limit_field: &str,
    now: OffsetDateTime,
) -> Result<(), ProviderError> {
    let (Some(used), Some(limit)) = (number(root, &[used_field])?, number(root, &[limit_field])?)
    else {
        return Ok(());
    };
    if limit <= 0.0 {
        return Ok(());
    }
    push_window(
        windows,
        label,
        Some(used),
        Some(limit),
        Some((limit - used).max(0.0)),
        "slots",
        None,
        "ElevenLabs user subscription",
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{Clock, CredentialStore, http::fixture};
    use std::{collections::HashMap, sync::Arc};

    struct TestCredentials(HashMap<String, String>);

    impl CredentialStore for TestCredentials {
        fn get(&self, name: &str) -> Option<Secret> {
            self.0.get(name).cloned().map(Secret)
        }
    }

    struct TestClock;

    impl Clock for TestClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH
        }
    }

    fn test_context(values: Vec<(&str, String)>) -> ProviderContext {
        ProviderContext {
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            clock: Arc::new(TestClock),
            credentials: Arc::new(TestCredentials(
                values
                    .into_iter()
                    .map(|(name, value)| (name.into(), value))
                    .collect(),
            )),
        }
    }

    #[tokio::test]
    async fn routes_use_private_fixture_endpoints_and_documented_auth_schemes() {
        let (base, server) = fixture::server(vec![serde_json::json!({
            "rolling":{"requests":25,"limit":100,"reset_at":"2026-09-06T00:00:00Z"},
            "monthly":{"used":2,"limit":10}
        })])
        .await;
        let context = test_context(vec![("CHUTES_API_KEY", "test-key".into())]);
        let usage = fetch_chutes_at(&context, &format!("{base}/users/me/subscription_usage"))
            .await
            .unwrap();
        assert_eq!(usage.provider.0, "chutes");
        assert_eq!(usage.windows.len(), 2);
        let requests = server.await.unwrap();
        assert!(requests[0].starts_with("GET /users/me/subscription_usage"));
        assert!(requests[0].contains("authorization: Bearer test-key"));

        let (base, server) = fixture::server(vec![
            serde_json::json!({"stripe_balance":-5,"recent":1,"limit":10}),
            serde_json::json!({"months":[{"total_cost":250}]}),
        ])
        .await;
        let context = test_context(vec![("DEEPINFRA_API_KEY", "test-key".into())]);
        let usage = fetch_deepinfra_at(
            &context,
            &format!("{base}/payment/checklist?compute_owed=true"),
            &format!("{base}/payment/usage?from=current"),
        )
        .await
        .unwrap();
        assert_eq!(usage.provider.0, "deepinfra");
        assert!(usage.windows.len() >= 3);
        let requests = server.await.unwrap();
        assert!(requests[0].starts_with("GET /payment/checklist?compute_owed=true"));
        assert!(requests[1].starts_with("GET /payment/usage?from=current"));
        assert!(
            requests
                .iter()
                .all(|request| request.contains("authorization: Bearer test-key"))
        );

        let (base, server) = fixture::server(vec![serde_json::json!({"lineItems":[{
            "totalCost":{"currencyCode":"USD","units":"2","nanos":500000000}
        }]})])
        .await;
        let context = test_context(vec![("FIREWORKS_API_KEY", "test-key".into())]);
        let endpoint = fireworks_endpoint(&base, "account-1", OffsetDateTime::UNIX_EPOCH).unwrap();
        let usage =
            fetch_fireworks_at(&context, &endpoint, "account-1", OffsetDateTime::UNIX_EPOCH)
                .await
                .unwrap();
        assert_eq!(usage.provider.0, "fireworks");
        assert_eq!(usage.windows[0].consumption.as_ref().unwrap().used, 2.5);
        let requests = server.await.unwrap();
        assert!(requests[0].starts_with("GET /v1/accounts/account-1/billing/summary?"));
        assert!(requests[0].contains("authorization: Bearer test-key"));

        let (base, server) = fixture::server(vec![serde_json::json!({
            "status":"success", "data":{"result":[{"value":[0,"1.5"]}]}
        })])
        .await;
        let context = test_context(vec![("GROQ_API_KEY", "test-key".into())]);
        let usage = fetch_groq_at(
            &context,
            &format!(
                "{base}/v1/metrics/prometheus/api/v1/query?query=sum%28model_project_id_status_code%3Arequests%3Arate5m%29"
            ),
        )
        .await
        .unwrap();
        assert_eq!(usage.provider.0, "groq");
        assert_eq!(usage.windows[0].consumption.as_ref().unwrap().used, 1.5);
        let requests = server.await.unwrap();
        assert!(requests[0].starts_with("GET /v1/metrics/prometheus/api/v1/query?query="));
        assert!(requests[0].contains("authorization: Bearer test-key"));

        let (base, server) = fixture::server(vec![serde_json::json!({"results":[{
            "requests":2,"hours":1.5,"tokens_in":3,"tokens_out":4
        }]})])
        .await;
        let context = test_context(vec![("DEEPGRAM_API_KEY", "test-key".into())]);
        let usage = fetch_deepgram_at(
            &context,
            &format!("{base}/v1/projects/project-1/usage/breakdown"),
            "project-1",
        )
        .await
        .unwrap();
        assert_eq!(usage.provider.0, "deepgram");
        let requests = server.await.unwrap();
        assert!(requests[0].starts_with("GET /v1/projects/project-1/usage/breakdown"));
        assert!(requests[0].contains("authorization: Token test-key"));

        let (base, server) = fixture::server(vec![serde_json::json!({
            "tier":"starter", "character_count":25, "character_limit":100,
            "next_character_count_reset_unix":1788652800
        })])
        .await;
        let context = test_context(vec![("ELEVENLABS_API_KEY", "test-key".into())]);
        let usage = fetch_elevenlabs_at(&context, &format!("{base}/v1/user/subscription"))
            .await
            .unwrap();
        assert_eq!(usage.provider.0, "elevenlabs");
        assert_eq!(usage.account.plan.as_deref(), Some("starter"));
        let requests = server.await.unwrap();
        assert!(requests[0].starts_with("GET /v1/user/subscription"));
        assert!(requests[0].contains("xi-api-key: test-key"));

        let (base, server) = fixture::server(vec![serde_json::json!({
            "balance":{"credits_remaining_usd":5},
            "subscription":{"plan":"standard","kwh_included":10,"kwh_used":2,
                "current_period_end":"2026-09-06T00:00:00Z"}
        })])
        .await;
        let context = test_context(vec![("NEURALWATT_API_KEY", "test-key".into())]);
        let usage = fetch_neuralwatt_at(&context, &format!("{base}/v1/quota"))
            .await
            .unwrap();
        assert_eq!(usage.provider.0, "neuralwatt");
        assert_eq!(usage.account.plan.as_deref(), Some("standard"));
        let requests = server.await.unwrap();
        assert!(requests[0].starts_with("GET /v1/quota"));
        assert!(requests[0].contains("authorization: Bearer test-key"));
    }

    #[test]
    fn sparse_payloads_do_not_become_zero_usage() {
        let now = OffsetDateTime::UNIX_EPOCH;
        assert!(matches!(
            parse_chutes(&serde_json::json!({}), now),
            Err(ProviderError::InvalidData)
        ));
        assert!(matches!(
            parse_fireworks(&serde_json::json!({"lineItems":[]}), now),
            Err(ProviderError::InvalidData)
        ));
        assert!(matches!(
            parse_deepgram(&serde_json::json!({"results":[]}), now),
            Err(ProviderError::InvalidData)
        ));
        assert!(matches!(
            parse_neuralwatt(&serde_json::json!({"balance":{}}), now),
            Err(ProviderError::InvalidData)
        ));
    }

    #[test]
    fn fireworks_money_and_elevenlabs_slots_require_complete_source_fields() {
        let now = OffsetDateTime::UNIX_EPOCH;
        assert!(matches!(
            parse_fireworks(
                &serde_json::json!({
                    "lineItems":[{"totalCost":{"currencyCode":"USD"}}]
                }),
                now
            ),
            Err(ProviderError::InvalidData)
        ));

        let windows = parse_fireworks(
            &serde_json::json!({
                "lineItems":[
                    {"totalCost":{"currencyCode":"USD","units":"1"}},
                    {"totalCost":{"currencyCode":"EUR","units":"2","nanos":0}},
                    {"totalCost":{"currencyCode":"USD","units":"3","nanos":0}}
                ]
            }),
            now,
        )
        .unwrap();
        assert_eq!(windows[0].consumption.as_ref().unwrap().used, 2.0);
        assert_eq!(windows[0].consumption.as_ref().unwrap().unit, "EUR");

        let (sparse_slots, _) = parse_elevenlabs(
            &serde_json::json!({
                "character_count":5,
                "character_limit":100,
                "voice_limit":3,
                "professional_voice_slots_used":1,
                "professional_voice_limit":0
            }),
            now,
        )
        .unwrap();
        assert_eq!(sparse_slots.len(), 1);
        assert_eq!(sparse_slots[0].label, "Characters");

        let (complete_slots, _) = parse_elevenlabs(
            &serde_json::json!({
                "character_count":5,
                "character_limit":100,
                "voice_slots_used":1,
                "voice_limit":3
            }),
            now,
        )
        .unwrap();
        assert_eq!(complete_slots.len(), 2);
        assert_eq!(complete_slots[1].label, "Voice slots");
    }

    #[test]
    fn hosted_definitions_use_fixed_origins_and_expose_only_required_nonsecret_metadata() {
        for (endpoint, host) in [
            (CHUTES_USAGE_URL, "api.chutes.ai"),
            (DEEPINFRA_CHECKLIST_URL, "api.deepinfra.com"),
            (DEEPINFRA_USAGE_URL, "api.deepinfra.com"),
            (FIREWORKS_API_BASE, "api.fireworks.ai"),
            (GROQ_PROMETHEUS_QUERY_URL, "api.groq.com"),
            (DEEPGRAM_API_BASE, "api.deepgram.com"),
            (ELEVENLABS_SUBSCRIPTION_URL, "api.elevenlabs.io"),
            (NEURALWATT_QUOTA_URL, "api.neuralwatt.com"),
        ] {
            let endpoint = Url::parse(endpoint).unwrap();
            assert_eq!(endpoint.scheme(), "https");
            assert_eq!(endpoint.host_str(), Some(host));
            assert_eq!(endpoint.port_or_known_default(), Some(443));
        }
        for id in ["chutes", "deepinfra", "groq", "elevenlabs", "neuralwatt"] {
            assert!(
                DEFINITIONS
                    .iter()
                    .find(|definition| definition.id == id)
                    .unwrap()
                    .settings
                    .is_empty()
            );
        }
        for (id, setting) in [
            ("fireworks", "FIREWORKS_ACCOUNT_ID"),
            ("deepgram", "DEEPGRAM_PROJECT_ID"),
        ] {
            let definition = DEFINITIONS
                .iter()
                .find(|definition| definition.id == id)
                .unwrap();
            assert_eq!(definition.settings.len(), 1);
            assert_eq!(definition.settings[0].env, setting);
        }
    }
}
