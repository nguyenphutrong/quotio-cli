use super::{AuthKind, Definition, common};
use crate::{
    domain::{ProviderUsage, UsageDiagnostic},
    error::ProviderError,
    providers::{FetchFuture, ProviderContext, Secret},
};
use serde_json::Value;
use time::OffsetDateTime;

const STATUS_URL: &str =
    "https://server.codeium.com/exa.seat_management_pb.SeatManagementService/GetUserStatus";
const SOURCE: &str = "devin_desktop_user_status";

pub const DEFINITIONS: &[Definition] = &[Definition {
    id: "devin-desktop",
    name: "Devin Desktop",
    key_env: "DEVIN_DESKTOP_API_KEY",
    auth: AuthKind::ApiKey,
    settings: &[],
    fetch,
}];

fn fetch<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(fetch_at(context, STATUS_URL))
}

async fn fetch_at(context: &ProviderContext, url: &str) -> Result<ProviderUsage, ProviderError> {
    let key = common::key(context, "DEVIN_DESKTOP_API_KEY")?;
    let now = context.clock.now();
    let root: Value = common::json(
        context
            .http
            .post(url)
            .header("Connect-Protocol-Version", "1")
            .json(&serde_json::json!({
                "metadata": {
                    "apiKey": key.0,
                    "ideName": "devin",
                    "ideVersion": "1.108.2",
                    "extensionName": "devin",
                    "extensionVersion": "1.108.2",
                    "locale": "en"
                }
            })),
        now,
    )
    .await?;
    parse_usage(&root, &key, now)
}

// Unlike the shared nonnegative amount parser, Swift clamps negative quota/balance values.
fn number(value: Option<&Value>) -> Result<Option<f64>, ProviderError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_f64()
            .or_else(|| {
                value
                    .as_str()
                    .filter(|text| text.len() <= 64)
                    .and_then(|text| text.trim().parse().ok())
            })
            .filter(|number: &f64| number.is_finite())
            .map(Some)
            .ok_or(ProviderError::InvalidData),
    }
}

fn partial<T>(
    result: Result<Option<T>, ProviderError>,
    source: &str,
    diagnostics: &mut Vec<UsageDiagnostic>,
) -> Option<T> {
    match result {
        Ok(value) => value,
        Err(code) => {
            diagnostics.push(UsageDiagnostic {
                source: source.into(),
                code,
            });
            None
        }
    }
}

fn reset(value: Option<&Value>) -> Result<Option<OffsetDateTime>, ProviderError> {
    number(value)?
        .map(|seconds| {
            // This field is Unix seconds, never a millisecond timestamp or an ISO date.
            OffsetDateTime::from_unix_timestamp_nanos((seconds * 1_000_000_000.0) as i128)
                .map_err(|_| ProviderError::InvalidData)
        })
        .transpose()
}

fn parse_usage(
    root: &Value,
    key: &Secret,
    now: OffsetDateTime,
) -> Result<ProviderUsage, ProviderError> {
    let status = root
        .get("userStatus")
        .and_then(Value::as_object)
        .ok_or(ProviderError::InvalidData)?;
    let plan = status
        .get("planStatus")
        .and_then(Value::as_object)
        .ok_or(ProviderError::InvalidData)?;
    let info = plan.get("planInfo").and_then(Value::as_object);
    let hide_daily = match info.and_then(|info| info.get("hideDailyQuota")) {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => value.as_f64().is_some_and(|value| value != 0.0),
        Some(Value::String(value)) if value == "true" => true,
        Some(Value::String(value)) if value == "false" => false,
        _ => return Err(ProviderError::InvalidData),
    };
    let mut diagnostics = Vec::new();
    let daily = partial(
        number(plan.get("dailyQuotaRemainingPercent")),
        "devin-daily",
        &mut diagnostics,
    );
    let weekly = partial(
        number(plan.get("weeklyQuotaRemainingPercent")),
        "devin-weekly",
        &mut diagnostics,
    );
    let mut windows = Vec::new();
    for (id, label, remaining, reset_field) in [
        (
            "devin-daily",
            "Daily",
            daily.filter(|_| !hide_daily),
            "dailyQuotaResetAtUnix",
        ),
        (
            "devin-weekly",
            "Weekly",
            weekly.or_else(|| daily.filter(|_| hide_daily)),
            "weeklyQuotaResetAtUnix",
        ),
    ] {
        let Some(remaining) = remaining else { continue };
        let resets_at = partial(reset(plan.get(reset_field)), reset_field, &mut diagnostics);
        let mut window = common::window(
            label,
            None,
            Some(100.0),
            Some(remaining.clamp(0.0, 100.0)),
            "percent",
            resets_at,
            SOURCE,
            now,
        )?;
        window.metric_id = Some(id.into());
        windows.push(window);
    }
    if let Some(micros) = partial(
        number(plan.get("overageBalanceMicros")),
        "devin-extra-balance",
        &mut diagnostics,
    ) {
        let mut window = common::window(
            "Extra balance",
            None,
            None,
            Some(micros.max(0.0) / 1_000_000.0),
            "USD",
            None,
            SOURCE,
            now,
        )?;
        window.metric_id = Some("devin-extra-balance".into());
        windows.push(window);
    }
    let mut usage = common::usage("devin-desktop", key, "desktop", windows)?;
    usage.account.plan = info
        .and_then(|info| info.get("planName"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned);
    usage.diagnostics = diagnostics;
    Ok(usage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::Quota,
        providers::{CredentialStore, http},
    };
    use serde_json::json;
    use std::sync::Arc;

    fn parse(plan: Value) -> Result<ProviderUsage, ProviderError> {
        parse_usage(
            &json!({"userStatus": {"planStatus": plan}}),
            &Secret("synthetic-desktop-key".into()),
            OffsetDateTime::UNIX_EPOCH,
        )
    }

    #[test]
    fn remaining_percentages_balance_plan_and_unix_resets() {
        let usage = parse(json!({
            "planInfo": {"planName": " Pro "},
            "dailyQuotaRemainingPercent": "25.5",
            "weeklyQuotaRemainingPercent": 80,
            "dailyQuotaResetAtUnix": "1788696000",
            "weeklyQuotaResetAtUnix": 1788696001,
            "overageBalanceMicros": "1250000"
        }))
        .unwrap();
        assert_eq!(usage.provider.0, "devin-desktop");
        assert_eq!(usage.account.plan.as_deref(), Some("Pro"));
        assert_eq!(usage.windows.len(), 3);
        assert_eq!(usage.windows[0].quota, Quota::from_remaining(Some(25.5)));
        assert_eq!(usage.windows[1].quota, Quota::from_remaining(Some(80.0)));
        assert_eq!(
            usage.windows[0].resets_at.unwrap().unix_timestamp(),
            1788696000
        );
        assert_eq!(
            usage.windows[1].resets_at.unwrap().unix_timestamp(),
            1788696001
        );
        let balance = &usage.windows[2];
        assert_eq!(balance.metric_id.as_deref(), Some("devin-extra-balance"));
        assert_eq!(balance.quota, Quota::Unknown);
        assert_eq!(balance.amounts.as_ref().unwrap().remaining, 1.25);
        assert_eq!(balance.amounts.as_ref().unwrap().unit, "USD");
        assert_eq!(balance.amounts.as_ref().unwrap().limit, None);
        assert!(
            usage
                .windows
                .iter()
                .all(|window| window.consumption.is_none())
        );
    }

    #[test]
    fn hidden_daily_uses_weekly_or_falls_back_with_weekly_reset() {
        for hidden in [json!(true), json!("true"), json!(1)] {
            for (weekly, expected) in [(json!(80), 80.0), (Value::Null, 30.0)] {
                let usage = parse(json!({
                    "planInfo": {"hideDailyQuota": hidden},
                    "dailyQuotaRemainingPercent": 30,
                    "weeklyQuotaRemainingPercent": weekly,
                    "dailyQuotaResetAtUnix": 100,
                    "weeklyQuotaResetAtUnix": "200"
                }))
                .unwrap();
                assert_eq!(usage.windows.len(), 1);
                assert_eq!(usage.windows[0].metric_id.as_deref(), Some("devin-weekly"));
                assert_eq!(
                    usage.windows[0].quota,
                    Quota::from_remaining(Some(expected))
                );
                assert_eq!(usage.windows[0].resets_at.unwrap().unix_timestamp(), 200);
            }
        }
    }

    #[test]
    fn clamps_finite_values_and_preserves_zero_balance() {
        for balance in [json!(-1), json!(0)] {
            let usage = parse(json!({
                "dailyQuotaRemainingPercent": -5,
                "weeklyQuotaRemainingPercent": 150,
                "overageBalanceMicros": balance
            }))
            .unwrap();
            assert_eq!(usage.windows[0].quota, Quota::from_remaining(Some(0.0)));
            assert_eq!(usage.windows[1].quota, Quota::from_remaining(Some(100.0)));
            assert_eq!(usage.windows[2].amounts.as_ref().unwrap().remaining, 0.0);
            assert!(
                usage
                    .windows
                    .iter()
                    .all(|window| window.resets_at.is_none())
            );
        }
        assert!(parse(json!({"overageBalanceMicros": 0})).is_ok());
    }

    #[test]
    fn malformed_siblings_and_resets_preserve_valid_quota_with_diagnostics() {
        for bad in [json!("NaN"), json!("inf"), json!({}), json!(true)] {
            let usage = parse(json!({
                "dailyQuotaRemainingPercent": 10,
                "dailyQuotaResetAtUnix": bad,
                "weeklyQuotaRemainingPercent": bad,
                "overageBalanceMicros": bad
            }))
            .unwrap();
            assert_eq!(usage.windows.len(), 1);
            assert_eq!(usage.windows[0].quota, Quota::from_remaining(Some(10.0)));
            assert!(usage.windows[0].resets_at.is_none());
            assert_eq!(usage.diagnostics.len(), 3);
            assert!(
                usage
                    .diagnostics
                    .iter()
                    .all(|d| d.code == ProviderError::InvalidData)
            );
        }
        assert!(reset(Some(&json!("1e300"))).is_err());
        assert!(reset(Some(&json!("2026-01-01T00:00:00Z"))).is_err());
        for plan in [
            json!({}),
            json!({"dailyQuotaRemainingPercent": "bad"}),
            Value::Null,
        ] {
            assert_eq!(parse(plan).unwrap_err(), ProviderError::InvalidData);
        }
        assert_eq!(
            parse_usage(
                &json!({}),
                &Secret("fixture".into()),
                OffsetDateTime::UNIX_EPOCH
            )
            .unwrap_err(),
            ProviderError::InvalidData
        );
    }

    struct Keys;
    impl CredentialStore for Keys {
        fn get(&self, name: &str) -> Option<Secret> {
            (name == "DEVIN_DESKTOP_API_KEY").then(|| Secret("synthetic-desktop-key".into()))
        }
    }

    #[tokio::test]
    async fn request_matches_swift_contract_and_errors_do_not_expose_credentials() {
        assert_eq!(
            STATUS_URL,
            "https://server.codeium.com/exa.seat_management_pb.SeatManagementService/GetUserStatus"
        );
        assert!(DEFINITIONS[0].settings.is_empty());
        let mut context = http::fixture::context();
        context.credentials = Arc::new(Keys);
        let (base, task) = http::fixture::server(vec![json!({
            "userStatus": {"planStatus": {"dailyQuotaRemainingPercent": 50}}
        })])
        .await;
        let url = format!("{base}/exa.seat_management_pb.SeatManagementService/GetUserStatus");
        let usage = fetch_at(&context, &url).await.unwrap();
        assert!(
            !serde_json::to_string(&usage)
                .unwrap()
                .contains("synthetic-desktop-key")
        );
        let requests = task.await.unwrap();
        let request = &requests[0];
        assert!(
            request
                .starts_with("POST /exa.seat_management_pb.SeatManagementService/GetUserStatus ")
        );
        assert!(
            request
                .to_lowercase()
                .contains("connect-protocol-version: 1")
        );
        assert!(
            request
                .to_lowercase()
                .contains("content-type: application/json")
        );
        let body: Value = serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(
            body,
            json!({"metadata": {
                "apiKey": "synthetic-desktop-key", "ideName": "devin", "ideVersion": "1.108.2",
                "extensionName": "devin", "extensionVersion": "1.108.2", "locale": "en"
            }})
        );
        for status in [401, 403] {
            let (base, task) = http::fixture::server_status(vec![(
                status,
                json!({"secret": "synthetic-desktop-key"}),
            )])
            .await;
            assert_eq!(
                fetch_at(&context, &base).await.unwrap_err(),
                ProviderError::Authentication
            );
            task.await.unwrap();
        }
    }
}
