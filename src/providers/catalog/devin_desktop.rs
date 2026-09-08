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

pub(crate) async fn load_native(
    source: &crate::accounts::sources::DevinDesktopNativeReference,
) -> Result<Secret, ProviderError> {
    use crate::accounts::sources::DevinDesktopLocation;
    let path = source.path.clone();
    match source.location {
        DevinDesktopLocation::CredentialsToml => {
            let bytes = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                tokio::task::spawn_blocking(move || {
                    super::oauth_editors::read_regular_file(&path, 1024 * 1024)
                }),
            )
            .await
            .map_err(|_| ProviderError::Timeout)?
            .map_err(|_| ProviderError::CredentialStorage)??;
            parse_credentials_toml(&bytes)
        }
        DevinDesktopLocation::StateDatabase => {
            let bytes = super::oauth_editors::native_sqlite_rows(path,
                "SELECT json_group_array(json_object('value',value)) FROM ItemTable WHERE key = 'windsurfAuthStatus';"
            ).await?;
            parse_database_rows(&bytes)
        }
    }
}

fn native_key(value: &str) -> Result<Secret, ProviderError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 16384 || value.chars().any(char::is_control) {
        return Err(ProviderError::Authentication);
    }
    Ok(Secret(value.into()))
}

fn parse_credentials_toml(bytes: &[u8]) -> Result<Secret, ProviderError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ProviderError::InvalidData)?;
    let root: toml::Table = toml::from_str(text).map_err(|_| ProviderError::InvalidData)?;
    // Never silently send credentials intended for another server to Codeium.
    if let Some(server) = root.get("api_server_url") {
        match server.as_str().map(str::trim) {
            Some("https://server.codeium.com" | "https://server.codeium.com/") => (),
            _ => return Err(ProviderError::InvalidData),
        }
    }
    native_key(
        root.get("windsurf_api_key")
            .and_then(toml::Value::as_str)
            .ok_or(ProviderError::Authentication)?,
    )
}

fn parse_database_rows(bytes: &[u8]) -> Result<Secret, ProviderError> {
    let rows: Vec<Value> = serde_json::from_slice(bytes).map_err(|_| ProviderError::InvalidData)?;
    if rows.len() != 1 {
        return Err(ProviderError::Authentication);
    }
    let value = rows[0]
        .get("value")
        .and_then(Value::as_str)
        .ok_or(ProviderError::InvalidData)?;
    let auth: Value = serde_json::from_str(value).map_err(|_| ProviderError::InvalidData)?;
    native_key(
        auth.get("apiKey")
            .and_then(Value::as_str)
            .ok_or(ProviderError::Authentication)?,
    )
}

fn fetch<'a>(context: &'a ProviderContext) -> FetchFuture<'a> {
    Box::pin(fetch_at(context, STATUS_URL))
}

pub(crate) async fn fetch_at(
    context: &ProviderContext,
    url: &str,
) -> Result<ProviderUsage, ProviderError> {
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

    #[test]
    fn native_parsers_reject_other_servers_and_ambiguous_credentials() {
        for suffix in [
            "",
            "api_server_url = 'https://server.codeium.com'",
            "api_server_url = 'https://server.codeium.com/'",
        ] {
            assert_eq!(
                parse_credentials_toml(
                    format!("windsurf_api_key = ' fixture-key ' # comment\n{suffix}").as_bytes()
                )
                .unwrap()
                .0,
                "fixture-key"
            );
        }
        for server in [
            "''",
            "'http://server.codeium.com'",
            "'https://evil.example'",
            "'https://server.codeium.com@evil.example'",
            "'https://server.codeium.com/path'",
            "42",
        ] {
            assert!(
                parse_credentials_toml(
                    format!("windsurf_api_key = 'fixture-key'\napi_server_url = {server}")
                        .as_bytes()
                )
                .is_err()
            );
        }
        for text in [
            "",
            "windsurf_api_key = ''",
            "windsurf_api_key = 42",
            "windsurf_api_key='one'\nwindsurf_api_key='two'",
        ] {
            assert!(parse_credentials_toml(text.as_bytes()).is_err());
        }
        let row = json!({"value": "{\"apiKey\":\"fixture-key\"}"});
        assert_eq!(
            parse_database_rows(serde_json::to_string(&vec![&row]).unwrap().as_bytes())
                .unwrap()
                .0,
            "fixture-key"
        );
        for rows in [
            json!([]),
            json!([row, row]),
            json!([{"value":"{}"}]),
            json!([{"value":"not-json"}]),
        ] {
            assert!(parse_database_rows(serde_json::to_string(&rows).unwrap().as_bytes()).is_err());
        }
    }

    #[tokio::test]
    async fn native_toml_read_is_bounded_read_only_and_does_not_fall_back() {
        use crate::accounts::sources::{DevinDesktopLocation, DevinDesktopNativeReference};
        let dir = std::env::temp_dir().join(crate::accounts::random_string().unwrap());
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("credentials.toml");
        let source = DevinDesktopNativeReference {
            path: path.clone(),
            location: DevinDesktopLocation::CredentialsToml,
        };
        let original = b"windsurf_api_key='fixture-key'\n";
        std::fs::write(&path, original).unwrap();
        assert_eq!(load_native(&source).await.unwrap().0, "fixture-key");
        assert_eq!(std::fs::read(&path).unwrap(), original);
        std::fs::write(&path, vec![b'x'; 1024 * 1024 + 1]).unwrap();
        assert!(load_native(&source).await.is_err());
        std::fs::remove_file(&path).unwrap();
        #[cfg(unix)]
        {
            let other = dir.join("other");
            std::fs::write(&other, original).unwrap();
            std::os::unix::fs::symlink(&other, &path).unwrap();
            assert!(load_native(&source).await.is_err());
            assert_eq!(std::fs::read(&other).unwrap(), original);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn native_database_reads_committed_wal_without_source_writes() {
        use crate::accounts::sources::{DevinDesktopLocation, DevinDesktopNativeReference};
        use std::io::{BufRead, Write};
        let dir = std::env::temp_dir().join(crate::accounts::random_string().unwrap());
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("state.vscdb");
        let mut owner = std::process::Command::new("/usr/bin/sqlite3")
            .args(["-init", "/dev/null", "-batch", "-bail"])
            .arg(&path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let input = owner.stdin.as_mut().unwrap();
        writeln!(input, "PRAGMA journal_mode=WAL; CREATE TABLE ItemTable(key TEXT, value TEXT); INSERT INTO ItemTable VALUES('windsurfAuthStatus','{{\"apiKey\":\"fixture-wal-key\"}}'); SELECT 'ready';").unwrap();
        input.flush().unwrap();
        let mut output = std::io::BufReader::new(owner.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert!(output.read_line(&mut line).unwrap() > 0);
            if line.trim() == "ready" {
                break;
            }
        }
        let files: Vec<_> = ["state.vscdb", "state.vscdb-wal", "state.vscdb-shm"]
            .map(|name| {
                let p = dir.join(name);
                let b = std::fs::read(&p).unwrap();
                (p, b)
            })
            .into();
        let source = DevinDesktopNativeReference {
            path: path.clone(),
            location: DevinDesktopLocation::StateDatabase,
        };
        assert_eq!(load_native(&source).await.unwrap().0, "fixture-wal-key");
        for (p, bytes) in &files {
            assert_eq!(std::fs::read(p).unwrap(), *bytes);
        }
        let link = dir.join("linked.vscdb");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(
            load_native(&DevinDesktopNativeReference {
                path: link,
                ..source.clone()
            })
            .await
            .is_err()
        );
        owner.stdin.take();
        owner.wait().unwrap();
        std::fs::write(dir.join("state.vscdb-wal"), b"malformed").unwrap();
        assert!(load_native(&source).await.is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

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
