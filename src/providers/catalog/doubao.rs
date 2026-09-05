use super::{AuthKind, Definition, Setting, common};
use crate::{
    domain::{ProviderUsage, QuotaWindow},
    error::ProviderError,
    providers::{FetchFuture, ProviderContext, Secret, http},
};
use reqwest::{
    Url,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST, HeaderValue},
};
use ring::{digest, hmac};
use serde_json::Value;
use std::fmt::Write;
use time::{OffsetDateTime, UtcOffset, macros::format_description};

const ACCESS_KEY_ID_ENV: &str = "DOUBAO_ACCESS_KEY_ID";
const SECRET_ACCESS_KEY_ENV: &str = "DOUBAO_SECRET_ACCESS_KEY";
const ENDPOINT: &str =
    "https://open.volcengineapi.com/?Action=GetCodingPlanUsage&Version=2024-01-01";
const REGION: &str = "cn-beijing";
const SERVICE: &str = "ark";
const CONTENT_TYPE_VALUE: &str = "application/x-www-form-urlencoded; charset=utf-8";
const SIGNED_HEADERS: &str = "content-type;host;x-content-sha256;x-date";

const SETTINGS: &[Setting] = &[Setting {
    name: "access_key_id",
    env: ACCESS_KEY_ID_ENV,
    required: true,
}];

pub const DEFINITIONS: &[Definition] = &[Definition {
    id: "doubao",
    name: "Doubao Coding Plan",
    key_env: SECRET_ACCESS_KEY_ENV,
    auth: AuthKind::ApiKey,
    settings: SETTINGS,
    fetch: doubao,
}];

fn doubao(context: &ProviderContext) -> FetchFuture<'_> {
    Box::pin(fetch_at(context, ENDPOINT))
}

async fn fetch_at(
    context: &ProviderContext,
    endpoint: &str,
) -> Result<ProviderUsage, ProviderError> {
    let secret_access_key = common::key(context, SECRET_ACCESS_KEY_ENV)?;
    let access_key_id = access_key_id(context)?;
    let now = context.clock.now();
    let endpoint = Url::parse(endpoint).map_err(|_| ProviderError::InvalidData)?;
    let headers = signed_headers(&endpoint, &access_key_id, &secret_access_key, now)?;
    let host = HeaderValue::from_str(&headers.host).map_err(|_| ProviderError::InvalidData)?;

    let root: Value = common::json(
        context
            .http
            .post(endpoint)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, CONTENT_TYPE_VALUE)
            .header(HOST, host)
            .header("X-Date", headers.x_date)
            .header("X-Content-Sha256", headers.payload_hash)
            .header(AUTHORIZATION, http::sensitive(&headers.authorization)?)
            .body(Vec::new()),
        now,
    )
    .await?;
    let windows = coding_plan_windows(&root, now)?;
    let mut usage = common::usage(
        "doubao",
        &secret_access_key,
        &format!("access-key:{access_key_id}"),
        windows,
    )?;
    usage.account.label = "Doubao access key".into();
    Ok(usage)
}

fn access_key_id(context: &ProviderContext) -> Result<String, ProviderError> {
    let value = context
        .credentials
        .get(ACCESS_KEY_ID_ENV)
        .ok_or(ProviderError::Authentication)?;
    let value = value.0.trim();
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(ProviderError::InvalidData);
    }
    Ok(value.into())
}

struct SignedHeaders {
    host: String,
    x_date: String,
    payload_hash: String,
    authorization: String,
}

fn signed_headers(
    endpoint: &Url,
    access_key_id: &str,
    secret_access_key: &Secret,
    now: OffsetDateTime,
) -> Result<SignedHeaders, ProviderError> {
    let now = now.to_offset(UtcOffset::UTC);
    let x_date = now
        .format(format_description!(
            "[year][month][day]T[hour][minute][second]Z"
        ))
        .map_err(|_| ProviderError::Internal)?;
    let date = now
        .format(format_description!("[year][month][day]"))
        .map_err(|_| ProviderError::Internal)?;
    let host = canonical_host(endpoint)?;
    let payload_hash = sha256_hex(&[]);
    let canonical_request = [
        "POST".into(),
        canonical_uri(endpoint),
        canonical_query(endpoint),
        format!("content-type:{CONTENT_TYPE_VALUE}"),
        format!("host:{host}"),
        format!("x-content-sha256:{payload_hash}"),
        format!("x-date:{x_date}"),
        String::new(),
        SIGNED_HEADERS.into(),
        payload_hash.clone(),
    ]
    .join("\n");
    let credential_scope = format!("{date}/{REGION}/{SERVICE}/request");
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());
    let string_to_sign = [
        "HMAC-SHA256",
        &x_date,
        &credential_scope,
        &canonical_request_hash,
    ]
    .join("\n");
    let signing_key = signing_key(&secret_access_key.0, &date);
    let signature = hex(&hmac(&signing_key, &string_to_sign));

    Ok(SignedHeaders {
        host,
        x_date,
        payload_hash,
        authorization: format!(
            "HMAC-SHA256 Credential={access_key_id}/{credential_scope}, \
             SignedHeaders={SIGNED_HEADERS}, Signature={signature}"
        ),
    })
}

fn canonical_host(endpoint: &Url) -> Result<String, ProviderError> {
    let host = endpoint.host_str().ok_or(ProviderError::InvalidData)?;
    Ok(match endpoint.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.into(),
    })
}

fn canonical_uri(endpoint: &Url) -> String {
    let path = endpoint.path();
    if path.is_empty() {
        "/".into()
    } else {
        path.into()
    }
}

fn canonical_query(endpoint: &Url) -> String {
    let mut pairs: Vec<_> = endpoint
        .query_pairs()
        .map(|(name, value)| (percent_encode(&name), percent_encode(&value)))
        .collect();
    pairs.sort_unstable();
    pairs
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            write!(encoded, "%{byte:02X}").expect("writing into String cannot fail");
        }
    }
    encoded
}

fn signing_key(secret_access_key: &str, date: &str) -> Vec<u8> {
    let date = hmac(secret_access_key.as_bytes(), date);
    let region = hmac(&date, REGION);
    let service = hmac(&region, SERVICE);
    hmac(&service, "request")
}

fn hmac(key: &[u8], value: &str) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, value.as_bytes()).as_ref().into()
}

fn sha256_hex(value: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, value).as_ref())
}

fn hex(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(output, "{byte:02x}").expect("writing into String cannot fail");
    }
    output
}

fn coding_plan_windows(
    root: &Value,
    now: OffsetDateTime,
) -> Result<Vec<QuotaWindow>, ProviderError> {
    response_error(root)?;
    let result = root
        .get("Result")
        .and_then(Value::as_object)
        .ok_or(ProviderError::InvalidData)?;
    let quotas = match result.get("QuotaUsage") {
        None | Some(Value::Null) => return Err(ProviderError::QuotaUnavailable),
        Some(Value::Array(quotas)) if quotas.is_empty() => {
            return Err(ProviderError::QuotaUnavailable);
        }
        Some(Value::Array(quotas)) => quotas,
        Some(_) => return Err(ProviderError::InvalidData),
    };
    let mut known = std::collections::BTreeMap::new();
    for quota in quotas {
        let quota = quota.as_object().ok_or(ProviderError::InvalidData)?;
        let level = quota
            .get("Level")
            .and_then(Value::as_str)
            .ok_or(ProviderError::InvalidData)?
            .trim()
            .to_ascii_lowercase();
        let level = match level.as_str() {
            "session" => "session",
            "weekly" => "weekly",
            "monthly" => "monthly",
            _ => continue,
        };
        if known.insert(level, quota).is_some() {
            return Err(ProviderError::InvalidData);
        }
    }

    let mut windows = Vec::new();
    for (level, label) in [
        ("session", "Session"),
        ("weekly", "Weekly"),
        ("monthly", "Monthly"),
    ] {
        let Some(quota) = known.get(level) else {
            continue;
        };
        let percent = common::number(quota.get("Percent"))?.ok_or(ProviderError::InvalidData)?;
        if percent > 100.0 {
            return Err(ProviderError::InvalidData);
        }
        windows.push(common::window(
            label,
            Some(percent),
            Some(100.0),
            None,
            "percent",
            reset_at(quota.get("ResetTimestamp"))?,
            "volcengine_get_coding_plan_usage",
            now,
        )?);
    }
    if windows.is_empty() {
        return Err(ProviderError::QuotaUnavailable);
    }
    Ok(windows)
}

fn response_error(root: &Value) -> Result<(), ProviderError> {
    let Some(error) = root.pointer("/ResponseMetadata/Error") else {
        return Ok(());
    };
    if error.is_null() {
        return Ok(());
    }
    let error = error.as_object().ok_or(ProviderError::InvalidData)?;
    let mut description = String::new();
    for field in ["Code", "CodeN", "Message"] {
        if let Some(value) = error.get(field).and_then(Value::as_str) {
            description.push_str(value);
            description.push(' ');
        }
    }
    let description = description.to_ascii_lowercase();
    if [
        "accessdenied",
        "invalidaccesskey",
        "signature",
        "unauthorized",
        "forbidden",
    ]
    .iter()
    .any(|needle| description.contains(needle))
    {
        return Err(ProviderError::Authentication);
    }
    Err(ProviderError::Unavailable)
}

fn reset_at(value: Option<&Value>) -> Result<Option<OffsetDateTime>, ProviderError> {
    if value
        .and_then(Value::as_i64)
        .is_some_and(|timestamp| timestamp <= 0)
    {
        return Ok(None);
    }
    common::date(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::Quota,
        providers::{Clock, CredentialStore},
    };
    use serde_json::json;
    use std::sync::Arc;

    struct TestCredentials(Vec<(&'static str, &'static str)>);

    impl CredentialStore for TestCredentials {
        fn get(&self, name: &str) -> Option<Secret> {
            self.0
                .iter()
                .find(|(candidate, _)| *candidate == name)
                .map(|(_, value)| Secret((*value).into()))
        }
    }

    struct TestClock;

    impl Clock for TestClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::from_unix_timestamp(1_781_654_400).unwrap()
        }
    }

    fn context(entries: &[(&'static str, &'static str)]) -> ProviderContext {
        let mut context = http::fixture::context();
        context.clock = Arc::new(TestClock);
        context.credentials = Arc::new(TestCredentials(entries.to_vec()));
        context
    }

    #[test]
    fn v4_signature_matches_the_documented_canonical_request() {
        let endpoint = Url::parse(
            "https://open.volcengineapi.com/?Version=2024-01-01&Action=GetCodingPlanUsage",
        )
        .unwrap();
        let headers = signed_headers(
            &endpoint,
            "AKLTTEST",
            &Secret("synthetic-secret".into()),
            OffsetDateTime::from_unix_timestamp(1_781_654_400).unwrap(),
        )
        .unwrap();

        assert_eq!(headers.host, "open.volcengineapi.com");
        assert_eq!(headers.x_date, "20260617T000000Z");
        assert_eq!(
            headers.payload_hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            headers.authorization,
            "HMAC-SHA256 Credential=AKLTTEST/20260617/cn-beijing/ark/request, \
             SignedHeaders=content-type;host;x-content-sha256;x-date, \
             Signature=ed2060a8159cf467246072ae8c43105b7406220ed623ccd35f226c19e06afe5b"
        );
    }

    #[test]
    fn canonical_query_is_rfc3986_encoded_and_sorted() {
        let endpoint = Url::parse("https://example.test/?z=two+words&a=%2F&a=~").unwrap();
        assert_eq!(canonical_query(&endpoint), "a=%2F&a=~&z=two%20words");
    }

    #[test]
    fn coding_plan_parser_preserves_percentages_and_reset_sentinels() {
        let now = OffsetDateTime::from_unix_timestamp(1_781_654_400).unwrap();
        let windows = coding_plan_windows(
            &json!({
                "Result": {
                    "QuotaUsage": [
                        {"Level": "monthly", "Percent": 100, "ResetTimestamp": 1_782_403_199},
                        {"Level": "session", "Percent": 12.5, "ResetTimestamp": 0},
                        {"Level": "weekly", "Percent": "25", "ResetTimestamp": -1},
                        {"Level": "daily", "Percent": 3, "ResetTimestamp": 1}
                    ]
                }
            }),
            now,
        )
        .unwrap();

        assert_eq!(windows.len(), 3);
        assert_eq!(windows[0].label, "Session");
        assert_eq!(windows[0].resets_at, None);
        assert_eq!(windows[0].amounts.as_ref().unwrap().remaining, 87.5);
        assert!(matches!(windows[2].quota, Quota::Exhausted { .. }));
        assert_eq!(
            windows[2].resets_at,
            Some(OffsetDateTime::from_unix_timestamp(1_782_403_199).unwrap())
        );
        assert!(matches!(
            coding_plan_windows(&json!({"Result": {"QuotaUsage": []}}), now),
            Err(ProviderError::QuotaUnavailable)
        ));
    }

    #[tokio::test]
    async fn signed_request_uses_the_coding_plan_endpoint_and_maps_quota_response() {
        let (base, server) = http::fixture::server(vec![json!({
            "ResponseMetadata": {
                "Action": "GetCodingPlanUsage",
                "Version": "2024-01-01",
                "Service": "ark",
                "Region": "cn-beijing"
            },
            "Result": {
                "Status": "Running",
                "UpdateTimestamp": 1_782_226_444,
                "QuotaUsage": [
                    {"Level": "session", "Percent": 12.5, "ResetTimestamp": 1_782_226_478},
                    {"Level": "weekly", "Percent": 25, "ResetTimestamp": 0}
                ]
            }
        })])
        .await;
        let usage = fetch_at(
            &context(&[
                (ACCESS_KEY_ID_ENV, "AKLTTEST"),
                (SECRET_ACCESS_KEY_ENV, "synthetic-secret"),
            ]),
            &format!("{base}/?Version=2024-01-01&Action=GetCodingPlanUsage"),
        )
        .await
        .unwrap();

        assert_eq!(usage.provider.0, "doubao");
        assert_eq!(usage.account.label, "Doubao access key");
        assert_eq!(usage.windows.len(), 2);
        assert_eq!(usage.windows[0].label, "Session");
        assert_eq!(usage.windows[0].amounts.as_ref().unwrap().remaining, 87.5);
        assert_eq!(usage.windows[1].resets_at, None);

        let request = server.await.unwrap().pop().unwrap();
        let request = request.to_ascii_lowercase();
        assert!(request.starts_with("post /?version=2024-01-01&action=getcodingplanusage "));
        assert!(request.contains("content-type: application/x-www-form-urlencoded; charset=utf-8"));
        assert!(request.contains("x-date: 20260617t000000z"));
        assert!(request.contains(
            "x-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
        assert!(request.contains(
            "authorization: hmac-sha256 credential=aklttest/20260617/cn-beijing/ark/request, signedheaders=content-type;host;x-content-sha256;x-date, signature="
        ));
        assert!(!request.contains("synthetic-secret"));
        assert!(!request.contains("x-security-token:"));
    }
}
