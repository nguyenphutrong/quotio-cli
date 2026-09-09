//! Read-only WHAM and app-server reset-credit normalization.
use crate::{domain::*, error::ProviderError};
use serde::Deserialize;
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Deserialize)]
struct Credit {
    #[serde(alias = "resetType")]
    reset_type: String,
    status: String,
    #[serde(alias = "expiresAt")]
    expires_at: Option<Value>,
}

pub(super) fn parse(
    value: Value,
    native: bool,
    now: OffsetDateTime,
) -> Result<ResetCredits, ProviderError> {
    let invalid = || ProviderError::InvalidData;
    // The server may cap detail rows. Never infer the total from list length.
    let available_count = value
        .get(if native {
            "availableCount"
        } else {
            "available_count"
        })
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    let mut earliest = None;
    match value.get("credits").filter(|v| !v.is_null()) {
        Some(credits) => {
            let credits: Vec<Credit> =
                serde_json::from_value(credits.clone()).map_err(|_| invalid())?;
            for credit in credits {
                if credit.status != "available"
                    || credit.reset_type
                        != if native {
                            "codexRateLimits"
                        } else {
                            "codex_rate_limits"
                        }
                {
                    continue;
                }
                let expires = credit
                    .expires_at
                    .map(|value| {
                        if native {
                            OffsetDateTime::from_unix_timestamp(value.as_i64().ok_or_else(invalid)?)
                                .map_err(|_| invalid())
                        } else {
                            OffsetDateTime::parse(value.as_str().ok_or_else(invalid)?, &Rfc3339)
                                .map_err(|_| invalid())
                        }
                    })
                    .transpose()?;
                if expires.is_some_and(|at| at <= now) {
                    continue;
                }
                if let Some(at) = expires {
                    earliest =
                        Some(earliest.map_or(at, |previous: OffsetDateTime| previous.min(at)));
                }
            }
        }
        None if native => (),
        None => return Err(invalid()),
    };
    Ok(ResetCredits {
        available_count,
        earliest_expires_at: earliest,
        fetched_at: now,
        source: if native {
            "codex_app_server"
        } else {
            "codex_api"
        }
        .into(),
    })
}

pub(super) fn attach(usage: &mut ProviderUsage, result: Result<ResetCredits, ProviderError>) {
    match result {
        Ok(credits) => usage.reset_credits = Some(credits),
        Err(code) => usage.diagnostics.push(UsageDiagnostic {
            source: "codex_reset_credits".into(),
            code,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn authoritative_total_and_earliest_eligible_expiry_in_both_protocols() {
        for native in [false, true] {
            let credit = |status: &str, kind: &str, seconds: i64| {
                if native {
                    json!({"status":status,"resetType":kind,"expiresAt":seconds})
                } else {
                    json!({"status":status,"reset_type":kind,"expires_at":OffsetDateTime::from_unix_timestamp(seconds).unwrap().format(&Rfc3339).unwrap()})
                }
            };
            let kind = if native {
                "codexRateLimits"
            } else {
                "codex_rate_limits"
            };
            let mut value = json!({"credits":[
                credit("available",kind,200), credit("available",kind,100),
                credit("available",kind,0), credit("available",kind,-1),
                credit("redeemed",kind,1), credit("redeeming",kind,2),
                credit("unknown",kind,3), credit("available","monetary",4)
            ]});
            // The detail list is capped: its length must never become the total.
            value[if native {
                "availableCount"
            } else {
                "available_count"
            }] = json!(9);
            let result = parse(value, native, OffsetDateTime::UNIX_EPOCH).unwrap();
            assert_eq!(result.available_count, 9);
            assert_eq!(result.earliest_expires_at.unwrap().unix_timestamp(), 100);
            assert_eq!(result.fetched_at, OffsetDateTime::UNIX_EPOCH);
            assert!(result.valid_at(OffsetDateTime::from_unix_timestamp(99).unwrap()));
            assert!(!result.valid_at(OffsetDateTime::from_unix_timestamp(100).unwrap()));
            assert!(!result.valid_at(OffsetDateTime::from_unix_timestamp(-1).unwrap()));
        }
    }

    #[test]
    fn zero_count_only_missing_expiry_and_malformed_responses() {
        for value in [
            json!({"availableCount":0}),
            json!({"availableCount":0,"credits":null}),
            json!({"availableCount":0,"credits":[]}),
        ] {
            let credits = parse(value, true, OffsetDateTime::UNIX_EPOCH).unwrap();
            assert_eq!(credits.available_count, 0);
            assert!(credits.earliest_expires_at.is_none());
        }
        let credits = parse(
            json!({"available_count":2,"credits":[
                {"status":"available","reset_type":"codex_rate_limits"},
                {"status":"available","reset_type":"codex_rate_limits","expires_at":null}
            ]}),
            false,
            OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap();
        assert_eq!(credits.available_count, 2);
        assert!(credits.earliest_expires_at.is_none());
        for native in [true, false] {
            for value in [
                Value::Null,
                json!({}),
                json!({"credits":[]}),
                json!({"availableCount":-1,"available_count":-1,"credits":[]}),
                json!({"availableCount":1,"available_count":1,"credits":{}}),
                json!({"availableCount":1,"available_count":1,"credits":[{}]}),
            ] {
                assert!(parse(value, native, OffsetDateTime::UNIX_EPOCH).is_err());
            }
        }
        assert!(parse(json!({"available_count":1,"credits":[{"status":"available","reset_type":"codex_rate_limits","expires_at":"bad"}]}), false, OffsetDateTime::UNIX_EPOCH).is_err());
        assert!(parse(json!({"availableCount":1,"credits":[{"status":"available","resetType":"codexRateLimits","expiresAt":"bad"}]}), true, OffsetDateTime::UNIX_EPOCH).is_err());
        assert!(
            parse(
                json!({"available_count":0}),
                false,
                OffsetDateTime::UNIX_EPOCH
            )
            .is_err()
        );
    }
}
