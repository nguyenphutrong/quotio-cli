//! The versioned OpenAPI description of Quotio's local HTTP API.

use axum::Json;
use serde_json::Value;

/// Return the checked-in API contract. Keeping the source as JSON makes it
/// useful to clients and avoids duplicating the domain serializers here.
pub(super) async fn document() -> Json<Value> {
    Json(serde_json::from_str(include_str!("../../docs/openapi.json")).expect("valid OpenAPI JSON"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document_value() -> Value {
        serde_json::from_str(include_str!("../../docs/openapi.json")).unwrap()
    }

    #[test]
    fn document_is_openapi_31_and_resolves_local_references() {
        let document = document_value();
        assert_eq!(document["openapi"], "3.1.0");
        assert!(document["paths"].as_object().is_some_and(|p| p.len() >= 16));

        fn visit(value: &Value, root: &Value) {
            match value {
                Value::Object(map) => {
                    if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
                        assert!(reference.starts_with("#/"), "external ref: {reference}");
                        let mut current = root;
                        for part in reference[2..].split('/') {
                            let part = part.replace("~1", "/").replace("~0", "~");
                            current = &current[part];
                            assert!(!current.is_null(), "unresolved ref: {reference}");
                        }
                    }
                    for child in map.values() {
                        visit(child, root);
                    }
                }
                Value::Array(values) => {
                    for child in values {
                        visit(child, root);
                    }
                }
                _ => {}
            }
        }
        visit(&document, &document);
    }

    #[test]
    fn document_covers_routes_schemas_statuses_nullable_fields_and_auth() {
        let d = document_value();
        let paths = d["paths"].as_object().unwrap();
        for path in [
            "/openapi.json",
            "/health",
            "/v1/status",
            "/v1/providers",
            "/v1/providers/{id}",
            "/v1/usage",
            "/v1/usage/{id}",
            "/v1/accounts",
            "/v1/accounts/{id}",
            "/v1/accounts/{id}/usage",
            "/v1/auth/sessions",
            "/v1/auth/sessions/{id}",
            "/v1/auth/sessions/{id}/callback",
            "/v1/settings",
            "/v1/refresh",
            "/v1/operations/{id}",
        ] {
            assert!(paths.contains_key(path), "missing path {path}");
        }
        for status in ["running", "completed", "failed"] {
            assert!(
                d["components"]["schemas"]["Operation"]["properties"]["status"]["enum"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v == status)
            );
        }
        for schema in [
            "Quota",
            "QuotaAmounts",
            "UsageReport",
            "SettingsView",
            "SettingsPatch",
            "Session",
        ] {
            assert!(
                d["components"]["schemas"].get(schema).is_some(),
                "missing {schema}"
            );
        }
        assert_eq!(
            d["components"]["schemas"]["QuotaWindow"]["properties"]["resets_at"]["type"][1],
            "null"
        );
        assert_eq!(
            d["components"]["schemas"]["QuotaAmounts"]["properties"]["limit"]["type"][1],
            "null"
        );
        assert!(
            d["components"]["schemas"]["Operation"]["properties"]["message"]["type"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "null")
        );
        assert!(
            paths["/v1/accounts"]["post"]["security"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["bearerAuth"].is_array())
        );
        assert!(
            paths["/v1/usage"]["get"]["security"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value.as_object().is_some_and(|object| object.is_empty()))
        );
        assert!(
            paths["/v1/accounts"]["post"]["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["name"] == "Idempotency-Key")
        );
    }

    fn resolve<'a>(schema: &'a Value, root: &'a Value) -> &'a Value {
        if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            let mut current = root;
            for part in reference[2..].split('/') {
                let part = part.replace("~1", "/").replace("~0", "~");
                current = &current[part];
            }
            current
        } else {
            schema
        }
    }

    fn validate(schema: &Value, value: &Value, root: &Value, path: &str) {
        let schema = resolve(schema, root);
        if let Some(options) = schema.get("oneOf").and_then(Value::as_array) {
            assert!(
                options.iter().any(|option| std::panic::catch_unwind(
                    std::panic::AssertUnwindSafe(|| validate(option, value, root, path))
                )
                .is_ok()),
                "{path}: no oneOf branch"
            );
            return;
        }
        if let Some(types) = schema.get("type").and_then(Value::as_array) {
            assert!(
                types
                    .iter()
                    .any(|kind| type_matches(kind.as_str().unwrap(), value)),
                "{path}: wrong type"
            );
        } else if let Some(kind) = schema.get("type").and_then(Value::as_str) {
            assert!(type_matches(kind, value), "{path}: wrong type");
        }
        if let Some(expected) = schema.get("const") {
            assert_eq!(value, expected, "{path}: const");
        }
        if let Some(values) = schema.get("enum").and_then(Value::as_array) {
            assert!(values.contains(value), "{path}: enum");
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            if let Some(required) = schema.get("required").and_then(Value::as_array) {
                for key in required {
                    assert!(
                        value.get(key.as_str().unwrap()).is_some(),
                        "{path}: missing {key}"
                    );
                }
            }
            if let Some(object) = value.as_object() {
                if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                    for key in object.keys() {
                        assert!(properties.contains_key(key), "{path}: additional {key}");
                    }
                }
                for (key, child) in properties {
                    if let Some(actual) = object.get(key) {
                        validate(child, actual, root, &format!("{path}/{key}"));
                    }
                }
            }
        }
        if let Some(items) = schema.get("items")
            && let Some(array) = value.as_array()
        {
            for (i, item) in array.iter().enumerate() {
                validate(items, item, root, &format!("{path}/{i}"));
            }
        }
    }
    fn type_matches(kind: &str, value: &Value) -> bool {
        match kind {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "number" => value.is_number(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => true,
        }
    }

    #[test]
    fn schemas_validate_runtime_serialized_values() {
        let document = document_value();
        let schemas = &document["components"]["schemas"];
        for capability in crate::providers::capabilities::all() {
            let value = serde_json::to_value(capability).unwrap();
            validate(
                &schemas["ProviderCapability"],
                &value,
                &document,
                "capability",
            );
        }
        let mut operations = crate::server::operations::Operations::default();
        let (operation, _) = operations.start("refresh", None, "runtime".into()).unwrap();
        validate(
            &schemas["Operation"],
            &serde_json::to_value(operation).unwrap(),
            &document,
            "operation",
        );
        let account = crate::accounts::api::AccountDto {
            id: "synthetic-account".into(),
            provider: crate::cli::Provider::Mock,
            label: "Demo".into(),
            active: true,
        };
        validate(
            &schemas["Account"],
            &serde_json::to_value(account).unwrap(),
            &document,
            "account",
        );
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let report = crate::domain::UsageReport {
            schema_version: 1,
            generated_at: now,
            providers: vec![crate::domain::ProviderUsage {
                account_ref: None,
                provider: crate::domain::ProviderId("mock".into()),
                account: crate::domain::AccountIdentity {
                    plan: None,
                    id: "demo".into(),
                    label: "Demo".into(),
                },
                windows: vec![crate::domain::QuotaWindow {
                    consumption: None,
                    label: "daily".into(),
                    quota: crate::domain::Quota::Unknown,
                    amounts: None,
                    resets_at: None,
                    reset_description: None,
                    provenance: crate::domain::Provenance {
                        source: "fixture".into(),
                        confidence: crate::domain::Confidence::Unknown,
                    },
                    fetched_at: now,
                }],
            }],
            failures: vec![],
        };
        validate(
            &schemas["UsageReport"],
            &serde_json::to_value(report).unwrap(),
            &document,
            "usage",
        );
        let settings = crate::settings::SettingsView {
            revision: "runtime".into(),
            values: crate::config::Config::default(),
            overridden: vec![],
        };
        validate(
            &schemas["SettingsView"],
            &serde_json::to_value(settings).unwrap(),
            &document,
            "settings",
        );
        for status in [
            crate::accounts::oauth::SessionStatus::Waiting,
            crate::accounts::oauth::SessionStatus::Processing,
            crate::accounts::oauth::SessionStatus::Completed,
            crate::accounts::oauth::SessionStatus::Failed,
            crate::accounts::oauth::SessionStatus::Cancelled,
            crate::accounts::oauth::SessionStatus::Expired,
        ] {
            let session = crate::accounts::oauth::SessionDto {
                id: "runtime-session".into(),
                url: "https://auth.openai.com/oauth/authorize".into(),
                expires_at: 1,
                status,
                account_id: None,
                error_code: None,
            };
            validate(
                &schemas["Session"],
                &serde_json::to_value(session).unwrap(),
                &document,
                "session",
            );
        }
    }
}
