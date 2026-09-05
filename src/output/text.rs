use crate::domain::{Quota, UsageReport};
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
        for window in &usage.windows {
            let quota = match window.quota {
                Quota::Unknown => "usage unknown; remaining unknown".into(),
                Quota::Available {
                    used_percent,
                    remaining_percent,
                } => format!("used {used_percent:.1}%; remaining {remaining_percent:.1}%"),
                Quota::Exhausted { .. } => "exhausted; used 100.0%; remaining 0.0%".into(),
            };
            let _ = writeln!(
                text,
                "  {}: {}; reset {}; source {} ({:?}); fetched {}",
                safe(&window.label),
                quota,
                timestamp(window.resets_at),
                safe(&window.provenance.source),
                window.provenance.confidence,
                timestamp(Some(window.fetched_at))
            );
        }
    }
    for failure in &report.failures {
        let _ = writeln!(text, "{}: {}", safe(&failure.provider.0), failure.code);
    }
    text
}
