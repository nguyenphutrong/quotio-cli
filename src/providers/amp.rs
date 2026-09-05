use super::{FetchFuture, ProviderAdapter, ProviderContext, process};
use crate::{domain::*, error::ProviderError};
use std::path::PathBuf;
use time::OffsetDateTime;

pub struct AmpProvider {
    pub executable: PathBuf,
}
impl Default for AmpProvider {
    fn default() -> Self {
        Self {
            executable: "amp".into(),
        }
    }
}
fn number(input: &str) -> Result<f64, ProviderError> {
    let value: f64 = input
        .trim()
        .replace(',', "")
        .parse()
        .map_err(|_| ProviderError::InvalidData)?;
    if !value.is_finite() || value < 0.0 {
        return Err(ProviderError::InvalidData);
    }
    Ok(value)
}
fn percent(input: &str) -> Result<f64, ProviderError> {
    let prefix = input.split_once('%').ok_or(ProviderError::InvalidData)?.0;
    let numeric = prefix.trim();
    if numeric.is_empty() || !numeric.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(ProviderError::InvalidData);
    }
    let value = number(numeric)?;
    if value > 100.0 {
        return Err(ProviderError::InvalidData);
    }
    Ok(value)
}
fn window(
    label: &str,
    quota: Quota,
    amounts: Option<QuotaAmounts>,
    now: OffsetDateTime,
) -> QuotaWindow {
    QuotaWindow {
        label: label.into(),
        provenance: Provenance {
            source: "amp_cli_usage".into(),
            confidence: if quota == Quota::Unknown {
                Confidence::Unknown
            } else {
                Confidence::Estimated
            },
        },
        quota,
        amounts,
        resets_at: None,
        fetched_at: now,
    }
}
fn balance(input: &str, unit: &str) -> Result<QuotaAmounts, ProviderError> {
    let (remaining, rest) = input.split_once(unit).ok_or(ProviderError::InvalidData)?;
    let limit = rest
        .strip_prefix(" of ")
        .map(|rest| {
            rest.split_once(unit)
                .ok_or(ProviderError::InvalidData)
                .and_then(|(value, _)| number(value))
        })
        .transpose()?;
    Ok(QuotaAmounts {
        remaining: number(remaining)?,
        limit,
        unit: "hours".into(),
    })
}
fn dollars(input: &str) -> Result<QuotaAmounts, ProviderError> {
    let rest = input.strip_prefix('$').ok_or(ProviderError::InvalidData)?;
    let (remaining, rest) = rest.split_once(' ').ok_or(ProviderError::InvalidData)?;
    let limit = rest
        .strip_prefix("of $")
        .map(|rest| {
            rest.split_once(' ')
                .ok_or(ProviderError::InvalidData)
                .and_then(|(value, _)| number(value))
        })
        .transpose()?;
    Ok(QuotaAmounts {
        remaining: number(remaining)?,
        limit,
        unit: "USD".into(),
    })
}
fn quota(amounts: &QuotaAmounts) -> Quota {
    Quota::from_remaining(
        amounts
            .limit
            .filter(|limit| *limit > 0.0)
            .map(|limit| 100.0 * amounts.remaining / limit),
    )
}
pub(crate) fn parse(input: &str, now: OffsetDateTime) -> Result<ProviderUsage, ProviderError> {
    let identity = input
        .lines()
        .find_map(|line| line.strip_prefix("Signed in as "))
        .ok_or(ProviderError::Authentication)?;
    let email = identity
        .split(" (")
        .next()
        .filter(|s| s.contains('@') && !s.contains(char::is_whitespace))
        .ok_or(ProviderError::InvalidData)?;
    let mut windows = Vec::new();
    for line in input.lines() {
        if let Some(rest) = line.strip_prefix("**Amp Free:** ") {
            windows.push(window(
                "Amp Free daily",
                Quota::from_remaining(Some(percent(rest)?)),
                None,
                now,
            ));
        } else if let Some(rest) = line.strip_prefix("**Amp Megawatt Subscription:** agent usage ")
        {
            let amounts = dollars(rest)?;
            windows.push(window(
                "Megawatt agent subscription",
                quota(&amounts),
                Some(amounts),
                now,
            ));
            if let Some((_, rest)) = rest.split_once(", orb usage ") {
                let amounts = balance(rest, "h")?;
                windows.push(window(
                    "Megawatt orb subscription",
                    quota(&amounts),
                    Some(amounts),
                    now,
                ));
            }
        } else if let Some(rest) = line.strip_prefix("**Individual credits:** ") {
            let amounts = dollars(rest)?;
            windows.push(window(
                "Individual credits",
                Quota::Unknown,
                Some(amounts),
                now,
            ));
        } else if let Some(rest) = line.strip_prefix("**Workspace ") {
            let (name, rest) = rest.split_once(":** ").ok_or(ProviderError::InvalidData)?;
            let amounts = dollars(rest)?;
            windows.push(window(
                &format!("Workspace {name} credits"),
                Quota::Unknown,
                Some(amounts),
                now,
            ));
        } else if line.starts_with("**") && !line.trim().is_empty() {
            // Do not silently omit a newly introduced quota category.
            return Err(ProviderError::InvalidData);
        }
    }
    if windows.is_empty() {
        return Err(ProviderError::InvalidData);
    }
    Ok(ProviderUsage {
        provider: ProviderId("amp".into()),
        account: AccountIdentity {
            id: email.into(),
            label: email.into(),
        },
        windows,
    })
}
pub struct AmpApiProvider;
impl AmpApiProvider {
    async fn fetch_api(
        &self,
        context: &ProviderContext,
        endpoint: &str,
    ) -> Result<ProviderUsage, ProviderError> {
        let key = context
            .credentials
            .get("AMP_API_KEY")
            .ok_or(ProviderError::Authentication)?;
        let response: serde_json::Value = super::http::json(
            context
                .http
                .post(endpoint)
                .header(
                    "Authorization",
                    super::http::sensitive(&format!("Bearer {}", key.0))?,
                )
                .header("Accept", "application/json")
                .json(&serde_json::json!({"method":"userDisplayBalanceInfo","params":{}})),
            context.clock.now(),
        )
        .await?;
        if response
            .pointer("/error/code")
            .and_then(serde_json::Value::as_str)
            == Some("auth-required")
        {
            return Err(ProviderError::Authentication);
        }
        if response.get("ok").and_then(serde_json::Value::as_bool) == Some(false) {
            return Err(ProviderError::InvalidData);
        }
        let text = response
            .pointer("/result/displayText")
            .and_then(serde_json::Value::as_str)
            .ok_or(ProviderError::InvalidData)?;
        let mut usage = parse(text, context.clock.now())?;
        for window in &mut usage.windows {
            window.provenance.source = "amp_api".into();
        }
        Ok(usage)
    }
}
impl ProviderAdapter for AmpApiProvider {
    fn id(&self) -> ProviderId {
        ProviderId("amp".into())
    }
    fn idempotent(&self) -> bool {
        true
    }
    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> FetchFuture<'a> {
        Box::pin(self.fetch_api(
            context,
            "https://ampcode.com/api/internal?userDisplayBalanceInfo",
        ))
    }
}
impl ProviderAdapter for AmpProvider {
    fn id(&self) -> ProviderId {
        ProviderId("amp".into())
    }
    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> FetchFuture<'a> {
        Box::pin(async move {
            let bytes = process::output(&self.executable, &["usage"]).await?;
            let text = std::str::from_utf8(&bytes).map_err(|_| ProviderError::InvalidData)?;
            parse(text, context.clock.now())
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const FIXTURE: &str = "Signed in as demo@example.com (demo)\n**Amp Free:** 75% remaining today (resets daily) - https://ampcode.com/settings#amp-free\n**Amp Megawatt Subscription:** agent usage $12 of $20 remaining (60%), orb usage 500.5h of 750h a1.small orb hours remaining (67%) - period 2026-08-19 to 2026-09-19, resets upon renewal in 13 days\n**Individual credits:** $10.25 remaining (set up auto-reload to avoid running out) - https://ampcode.com/settings\n**Workspace Example:** $0 remaining - https://ampcode.com/workspaces/example\n";
    #[test]
    fn parse_all_categories_without_inventing_credit_quota() {
        let usage = parse(FIXTURE, OffsetDateTime::UNIX_EPOCH).unwrap();
        assert_eq!(usage.windows.len(), 5);
        assert_eq!(usage.windows[0].quota, Quota::from_used(Some(25.0)));
        assert_eq!(usage.windows[1].quota, Quota::from_used(Some(40.0)));
        assert_eq!(usage.windows[2].amounts.as_ref().unwrap().remaining, 500.5);
        assert_eq!(usage.windows[4].quota, Quota::Unknown);
        assert_eq!(usage.windows[4].amounts.as_ref().unwrap().remaining, 0.0);
        assert!(usage.windows.iter().all(|w| w.resets_at.is_none()));
    }
    #[test]
    fn format_drift_and_missing_identity_fail() {
        assert!(
            parse(
                "Signed in as demo@example.com (demo)\n**New quota:** 50%",
                OffsetDateTime::UNIX_EPOCH
            )
            .is_err()
        );
        assert!(parse("Please log in", OffsetDateTime::UNIX_EPOCH).is_err());
        assert!(
            parse(
                &FIXTURE.replace("75%", "unknown%"),
                OffsetDateTime::UNIX_EPOCH
            )
            .is_err()
        );
    }
    #[test]
    fn reject_malformed_percentage_tokens() {
        for token in ["-5%", "1e2%", "1,2%", "105%"] {
            assert!(
                parse(&FIXTURE.replace("75%", token), OffsetDateTime::UNIX_EPOCH).is_err(),
                "accepted malformed percentage"
            );
        }
    }
    #[tokio::test]
    async fn api_uses_bearer_and_preserves_parsed_balances() {
        use std::sync::Arc;
        struct Keys;
        impl super::super::CredentialStore for Keys {
            fn get(&self, name: &str) -> Option<super::super::Secret> {
                (name == "AMP_API_KEY").then(|| super::super::Secret("synthetic-key".into()))
            }
        }
        let (url, task) = super::super::http::fixture::server(vec![
            serde_json::json!({"ok":true,"result":{"displayText":FIXTURE}}),
        ])
        .await;
        let mut context = super::super::http::fixture::context();
        context.credentials = Arc::new(Keys);
        let usage = AmpApiProvider.fetch_api(&context, &url).await.unwrap();
        assert_eq!(usage.windows.len(), 5);
        assert_eq!(usage.windows[0].provenance.source, "amp_api");
        let requests = task.await.unwrap();
        assert!(requests[0].starts_with("POST / "));
        assert!(requests[0].contains("Bearer synthetic-key"));
        assert!(requests[0].contains("userDisplayBalanceInfo"));
        assert!(!requests[0].to_lowercase().contains("cookie:"));
    }
}
