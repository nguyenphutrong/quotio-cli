use crate::domain::{ProviderFailure, Quota, UsageReport};
use std::fmt::Write;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
fn timestamp(time: Option<OffsetDateTime>) -> String {
    time.and_then(|value| value.format(&Rfc3339).ok())
        .unwrap_or_else(|| "unknown".into())
}
// Prevent provider metadata from injecting terminal escape sequences or lines.
fn safe(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}
pub fn render(report: &UsageReport) -> String {
    let mut text = format!("Usage as of {}\n", timestamp(Some(report.generated_at)));
    if report.providers.is_empty() {
        text.push_str("No provider returned usage.\n");
    }
    for usage in &report.providers {
        let _ = writeln!(
            text,
            "{} | {} ({})",
            safe(&usage.provider.0),
            safe(&usage.account.label),
            safe(&usage.account.id)
        );
        if let Some(account) = &usage.account_ref {
            let _ = writeln!(
                text,
                "  Account: {} [{}]",
                safe(&account.label),
                safe(&account.id)
            );
        }
        if let Some(credits) = &usage.reset_credits {
            let _ = writeln!(
                text,
                "  Banked reset credits: {} available as of {}; earliest expiry {}; source {}",
                credits.available_count,
                timestamp(Some(credits.fetched_at)),
                timestamp(credits.earliest_expires_at),
                safe(&credits.source)
            );
        }
        for window in &usage.windows {
            let balance_only = window.quota == Quota::Unknown
                && window.amounts.as_ref().is_some_and(|a| a.limit.is_none());
            let consumption_only = window.quota == Quota::Unknown
                && window.consumption.is_some()
                && window.amounts.is_none();
            let quota = match window.quota {
                Quota::Unknown if consumption_only => {
                    let amount = window.consumption.as_ref().expect("consumption amount");
                    format!("used {:.2} {}", amount.used, safe(&amount.unit))
                }
                Quota::Unknown if balance_only => {
                    let amounts = window.amounts.as_ref().expect("balance amount");
                    format!(
                        "balance {:.2} {} remaining",
                        amounts.remaining,
                        safe(&amounts.unit)
                    )
                }
                Quota::Disabled => "disabled".into(),
                Quota::Limit { amount, ref unit } => format!("limit {amount:.2} {}", safe(unit)),
                Quota::Unlimited => window.consumption.as_ref().map_or_else(
                    || "unlimited".into(),
                    |amount| format!("unlimited; used {:.2} {}", amount.used, safe(&amount.unit)),
                ),
                Quota::Unknown => "usage unknown; remaining unknown".into(),
                Quota::Available {
                    used_percent,
                    remaining_percent,
                } => format!("used {used_percent:.1}%; remaining {remaining_percent:.1}%"),
                Quota::Exhausted { .. } => "exhausted; used 100.0%; remaining 0.0%".into(),
            };
            let reset = if window.resets_at.is_some() {
                format!("; reset {}", timestamp(window.resets_at))
            } else if let Some(description) = window
                .reset_description
                .as_deref()
                .filter(|s| !s.trim().is_empty())
            {
                format!("; reset {}", safe(description))
            } else if balance_only || consumption_only {
                String::new()
            } else {
                "; reset unknown".into()
            };
            let _ = writeln!(
                text,
                "  {}: {}{}; source {} ({:?}); fetched {}",
                safe(&window.label),
                quota,
                reset,
                safe(&window.provenance.source),
                window.provenance.confidence,
                timestamp(Some(window.fetched_at))
            );
            if let Some(amounts) = &window.amounts
                && !balance_only
            {
                if let Some(limit) = amounts.limit.filter(|limit| *limit >= amounts.remaining) {
                    let _ = writeln!(
                        text,
                        "    used {:.2} of {limit} {}; remaining {:.2} {}",
                        window
                            .consumption
                            .as_ref()
                            .map_or(limit - amounts.remaining, |c| c.used),
                        safe(&amounts.unit),
                        amounts.remaining,
                        safe(&amounts.unit)
                    );
                    continue;
                }
                let limit = amounts
                    .limit
                    .map(|v| format!(" of {v}"))
                    .unwrap_or_default();
                let _ = writeln!(
                    text,
                    "    balance {}{} {} remaining",
                    amounts.remaining,
                    limit,
                    safe(&amounts.unit)
                );
            }
        }
    }
    for failure in &report.failures {
        let _ = writeln!(text, "{}", self::failure(failure));
    }
    text
}

pub fn failure(failure: &ProviderFailure) -> String {
    let account = failure
        .account_ref
        .as_ref()
        .map(|a| format!(" [{}: {}]", safe(&a.id), safe(&a.label)))
        .unwrap_or_default();
    format!("{}{account}: {}", safe(&failure.provider.0), failure.code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reset_credits_render_zero_positive_and_unknown_without_money_or_tokens() {
        for count in [None, Some(0), Some(2)] {
            let usage = crate::providers::codex::parse_direct("demo@example.com", json!({
                "rateLimits":{"primary":{"usedPercent":20}},
                "rateLimitResetCredits":count.map(|available| json!({"availableCount":available}))
            }), OffsetDateTime::UNIX_EPOCH).unwrap();
            let report = UsageReport {
                schema_version: 1,
                generated_at: OffsetDateTime::UNIX_EPOCH,
                providers: vec![usage],
                failures: vec![],
            };
            let text = render(&report);
            let value: serde_json::Value =
                serde_json::from_str(&crate::output::json::render(&report).unwrap()).unwrap();
            match count {
                Some(count) => {
                    assert!(text.contains(&format!("Banked reset credits: {count} available as of 1970-01-01T00:00:00Z; earliest expiry unknown; source codex_app_server")));
                    assert_eq!(
                        value["providers"][0]["reset_credits"]["available_count"],
                        count
                    );
                }
                None => {
                    assert!(!text.contains("Banked reset credits"));
                    assert!(value["providers"][0].get("reset_credits").is_none());
                }
            }
            assert!(!text.contains("USD"));
            assert!(text.contains("remaining 80.0%"));
            println!("{text}");
        }
    }
}
