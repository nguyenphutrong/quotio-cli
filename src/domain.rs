use crate::error::ProviderError;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ProviderId(pub String);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountIdentity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    pub id: String,
    pub label: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Quota {
    Unknown,
    Available {
        used_percent: f64,
        remaining_percent: f64,
    },
    Exhausted {
        used_percent: f64,
        remaining_percent: f64,
    },
}
impl Quota {
    pub fn from_used(used: Option<f64>) -> Self {
        match used.filter(|v| v.is_finite()) {
            None => Self::Unknown,
            Some(v) => {
                let used = v.clamp(0.0, 100.0);
                if used == 100.0 {
                    Self::Exhausted {
                        used_percent: used,
                        remaining_percent: 0.0,
                    }
                } else {
                    Self::Available {
                        used_percent: used,
                        remaining_percent: 100.0 - used,
                    }
                }
            }
        }
    }
    pub fn is_valid(&self) -> bool {
        match *self {
            Self::Unknown => true,
            Self::Available {
                used_percent,
                remaining_percent,
            } => {
                used_percent.is_finite()
                    && remaining_percent.is_finite()
                    && (0.0..100.0).contains(&used_percent)
                    && remaining_percent > 0.0
                    && remaining_percent <= 100.0
                    && (used_percent + remaining_percent - 100.0).abs() < 1e-9
            }
            Self::Exhausted {
                used_percent,
                remaining_percent,
            } => used_percent == 100.0 && remaining_percent == 0.0,
        }
    }
    pub fn from_remaining(remaining: Option<f64>) -> Self {
        Self::from_used(remaining.map(|v| 100.0 - v))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Exact,
    Estimated,
    Unknown,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Provenance {
    pub source: String,
    pub confidence: Confidence,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct QuotaAmounts {
    pub remaining: f64,
    pub limit: Option<f64>,
    pub unit: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Consumption {
    pub used: f64,
    pub unit: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QuotaWindow {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumption: Option<Consumption>,
    pub label: String,
    pub quota: Quota,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amounts: Option<QuotaAmounts>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub resets_at: Option<OffsetDateTime>,
    /// Source-provided reset information when an exact timestamp is unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_description: Option<String>,
    pub provenance: Provenance,
    #[serde(with = "time::serde::rfc3339")]
    pub fetched_at: OffsetDateTime,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountRef {
    pub id: String,
    pub label: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderUsage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_ref: Option<AccountRef>,
    pub provider: ProviderId,
    pub account: AccountIdentity,
    pub windows: Vec<QuotaWindow>,
}
#[derive(Debug, Serialize)]
pub struct ProviderFailure {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_ref: Option<AccountRef>,
    pub provider: ProviderId,
    pub code: ProviderError,
    pub message: String,
}
#[derive(Debug, Serialize)]
pub struct UsageReport {
    pub schema_version: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub providers: Vec<ProviderUsage>,
    pub failures: Vec<ProviderFailure>,
}
impl UsageReport {
    pub fn exit_code(&self) -> u8 {
        if self.providers.is_empty() {
            3
        } else if self.failures.is_empty() {
            0
        } else {
            1
        }
    }
}
