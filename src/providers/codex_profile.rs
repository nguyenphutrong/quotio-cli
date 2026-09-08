use crate::{
    domain::{CodexDailyUsage, CodexProfileAnalytics},
    error::ProviderError,
};
use serde_json::Value;
use std::collections::BTreeMap;
use time::OffsetDateTime;

fn alias<'a>(value: &'a Value, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|name| value.get(*name))
}

// Swift accepts integer, floating-point and numeric-string values, truncating fractions.
fn count(value: &Value) -> Option<u64> {
    if let Some(value) = value.as_u64() {
        return Some(value);
    }
    if let Some(value) = value.as_str().and_then(|value| value.parse::<u64>().ok()) {
        return Some(value);
    }
    let value = value
        .as_f64()
        .or_else(|| value.as_str()?.parse::<f64>().ok())?;
    (value.is_finite() && value >= 0.0 && value < u64::MAX as f64).then_some(value as u64)
}
fn tokens(value: &Value) -> Option<u64> {
    if !value.is_object() {
        return count(value);
    }
    if let Some(total) = alias(
        value,
        &[
            "tokens",
            "token_count",
            "tokenCount",
            "total_tokens",
            "totalTokens",
            "value",
            "count",
        ],
    )
    .and_then(count)
    {
        return Some(total);
    }
    let input = alias(value, &["input_tokens", "inputTokens"])
        .and_then(count)
        .unwrap_or(0);
    let output = alias(value, &["output_tokens", "outputTokens"])
        .and_then(count)
        .unwrap_or(0);
    input.checked_add(output).filter(|total| *total > 0)
}
fn date(value: &str) -> Option<String> {
    let day: String = value.chars().take(10).collect();
    time::Date::parse(
        &day,
        time::macros::format_description!("[year]-[month]-[day]"),
    )
    .ok()?;
    Some(day)
}

pub(super) fn parse(
    value: Value,
    now: OffsetDateTime,
) -> Result<CodexProfileAnalytics, ProviderError> {
    let stats = value
        .get("stats")
        .filter(|value| value.is_object())
        .ok_or(ProviderError::InvalidData)?;
    let mut buckets = BTreeMap::new();
    let mut insert = |day: Option<String>, tokens: Option<u64>| -> Result<(), ProviderError> {
        if let (Some(day), Some(tokens)) = (day, tokens) {
            // Duplicate normalized dates are ambiguous; Swift's dictionary initializer traps.
            if buckets.insert(day, tokens).is_some() {
                return Err(ProviderError::InvalidData);
            }
        }
        Ok(())
    };
    match alias(stats, &["daily_usage_buckets", "dailyUsageBuckets"]) {
        Some(Value::Array(values)) => {
            for value in values {
                let day = alias(
                    value,
                    &[
                        "date",
                        "day",
                        "start_date",
                        "startDate",
                        "bucket",
                        "bucket_start",
                        "bucketStart",
                    ],
                )
                .and_then(Value::as_str)
                .and_then(date);
                insert(day, tokens(value))?;
            }
        }
        Some(Value::Object(values)) => {
            for (day, value) in values {
                insert(date(day), tokens(value))?;
            }
        }
        _ => {}
    }
    let latest_30_buckets_tokens = buckets
        .values()
        .rev()
        .take(30)
        .try_fold(0u64, |sum, tokens| sum.checked_add(*tokens))
        .ok_or(ProviderError::InvalidData)?;
    let daily_usage = buckets
        .into_iter()
        .rev()
        .take(371)
        .map(|(date, tokens)| CodexDailyUsage { date, tokens })
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    Ok(CodexProfileAnalytics {
        daily_usage,
        latest_30_buckets_tokens,
        lifetime_tokens: alias(stats, &["lifetime_tokens", "lifetimeTokens"]).and_then(count),
        peak_daily_tokens: alias(stats, &["peak_daily_tokens", "peakDailyTokens"]).and_then(count),
        longest_running_turn_seconds: alias(
            stats,
            &["longest_running_turn_sec", "longestRunningTurnSec"],
        )
        .and_then(count),
        current_streak_days: alias(stats, &["current_streak_days", "currentStreakDays"])
            .and_then(count),
        longest_streak_days: alias(stats, &["longest_streak_days", "longestStreakDays"])
            .and_then(count),
        fetched_at: now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use time::macros::datetime;

    #[test]
    fn aliases_numeric_coercion_sparse_dates_and_zero_match_swift() {
        let result = parse(
            json!({"stats":{
                "dailyUsageBuckets":[
                    {"startDate":"2026-09-07T01:02:03Z","inputTokens":"12","outputTokens":3.8},
                    {"bucket_start":"2020-01-01","total_tokens":"100.9"},
                    {"day":"2026-09-06","count":0},
                    {"date":"invalid-provider-secret","tokens":99},
                    {"date":"2026-09-05","tokens":-9}
                ],
                "lifetimeTokens":"8000", "peak_daily_tokens":100,
                "longestRunningTurnSec":"3661", "current_streak_days":0,
                "longestStreakDays":"3", "ignored":"provider-secret"
            }}),
            datetime!(2026-09-07 0:00 UTC),
        )
        .unwrap();
        assert_eq!(result.latest_30_buckets_tokens, 115);
        assert_eq!(result.daily_usage.len(), 3);
        assert_eq!(result.daily_usage[1].tokens, 0);
        assert_eq!(result.daily_usage[2].tokens, 15);
        assert_eq!(result.lifetime_tokens, Some(8000));
        assert_eq!(result.longest_running_turn_seconds, Some(3661));
        assert_eq!(result.current_streak_days, Some(0));
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("provider-secret")
        );
    }

    #[test]
    fn latest_thirty_is_bucket_count_and_trend_is_latest_371() {
        let now = datetime!(2026-09-07 0:00 UTC);
        let buckets: serde_json::Map<String, Value> = (0..400)
            .map(|index| {
                let day = (now - time::Duration::days(index * 2)).date().to_string();
                (day, json!(index + 1))
            })
            .collect();
        let result = parse(json!({"stats":{"daily_usage_buckets":buckets}}), now).unwrap();
        assert_eq!(result.latest_30_buckets_tokens, 465);
        assert_eq!(result.daily_usage.len(), 371);
        assert_eq!(result.daily_usage[0].tokens, 371);
        assert_eq!(result.daily_usage[370].tokens, 1);
    }

    #[test]
    fn missing_unknown_duplicate_and_overflow_are_safe() {
        let now = datetime!(2026-09-07 0:00 UTC);
        assert!(parse(json!({}), now).is_err());
        let empty = parse(json!({"stats":{}}), now).unwrap();
        assert!(empty.daily_usage.is_empty());
        assert_eq!(empty.lifetime_tokens, None);
        for buckets in [
            json!([{"date":"2026-09-07","tokens":1},{"date":"2026-09-07T01:00:00Z","tokens":2}]),
            json!({"2026-09-07":u64::MAX,"2026-09-06":1}),
        ] {
            assert!(parse(json!({"stats":{"daily_usage_buckets":buckets}}), now).is_err());
        }
    }
}
