//! Optional loadCodeAssist metadata, matching Swift QuotaSubscriptionInfo,
//! QuotaSubscriptionTier and QuotaPrivacyNotice (QuotaModels.swift).
//! Fields are independent: invalid metadata never discards quota or valid siblings.
//! Text is trimmed, control-free and bounded in bytes; URLs must be HTTPS without
//! userinfo. No effective-tier, payment or upgrade eligibility is computed here.
use crate::domain::{
    AntigravityPrivacyNotice, AntigravitySubscriptionInfo, AntigravitySubscriptionTier,
};
use serde_json::Value;

#[derive(Default)]
struct Parser {
    invalid: bool,
}
impl Parser {
    fn text(&mut self, value: Option<&Value>, max: usize) -> Option<String> {
        let value = value.filter(|v| !v.is_null())?;
        match value.as_str() {
            Some(s)
                if s.len() <= max && !s.chars().any(char::is_control) && !s.trim().is_empty() =>
            {
                Some(s.trim().to_owned())
            }
            _ => {
                self.invalid = true;
                None
            }
        }
    }
    fn boolean(&mut self, value: Option<&Value>) -> Option<bool> {
        let value = value.filter(|v| !v.is_null())?;
        let result = value.as_bool();
        self.invalid |= result.is_none();
        result
    }
    fn url(&mut self, value: Option<&Value>) -> Option<String> {
        let s = self.text(value, 2048)?;
        let valid = s
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
            && reqwest::Url::parse(&s).is_ok_and(|u| {
                u.scheme() == "https"
                    && u.host_str().is_some()
                    && u.username().is_empty()
                    && u.password().is_none()
            })
            && !s.contains('\\')
            && !s.chars().any(char::is_whitespace)
            && !s
                .split("//")
                .nth(1)
                .unwrap_or("")
                .split(['/', '?', '#'])
                .next()
                .unwrap_or("")
                .contains('@');
        if valid {
            Some(s)
        } else {
            self.invalid = true;
            None
        }
    }
    fn object<'a>(&mut self, value: Option<&'a Value>) -> Option<&'a Value> {
        let value = value.filter(|v| !v.is_null())?;
        if value.is_object() {
            Some(value)
        } else {
            self.invalid = true;
            None
        }
    }
    fn tier(&mut self, value: Option<&Value>) -> Option<AntigravitySubscriptionTier> {
        let v = self.object(value)?;
        let privacy_notice =
            self.object(v.get("privacyNotice"))
                .map(|v| AntigravityPrivacyNotice {
                    show_notice: self.boolean(v.get("showNotice")),
                    notice_text: self.text(v.get("noticeText"), 4096),
                });
        Some(AntigravitySubscriptionTier {
            id: self.text(v.get("id"), 128),
            name: self.text(v.get("name"), 128),
            description: self.text(v.get("description"), 4096),
            privacy_notice,
            is_default: self.boolean(v.get("isDefault")),
            upgrade_subscription_uri: self.url(v.get("upgradeSubscriptionUri")),
            upgrade_subscription_text: self.text(v.get("upgradeSubscriptionText"), 4096),
            upgrade_subscription_type: self.text(v.get("upgradeSubscriptionType"), 128),
            user_defined_cloudaicompanion_project: self
                .boolean(v.get("userDefinedCloudaicompanionProject")),
        })
    }
}

pub(super) fn parse(value: &Value) -> (Option<AntigravitySubscriptionInfo>, bool) {
    let mut p = Parser::default();
    let Some(v) = p.object(Some(value)) else {
        return (None, p.invalid);
    };
    let allowed_tiers = match v.get("allowedTiers").filter(|v| !v.is_null()) {
        Some(Value::Array(values)) => {
            p.invalid |= values.len() > 100;
            Some(
                values
                    .iter()
                    .take(100)
                    .filter_map(|v| p.tier(Some(v)))
                    .collect(),
            )
        }
        Some(_) => {
            p.invalid = true;
            None
        }
        None => None,
    };
    let project = v.get("cloudaicompanionProject");
    let info = AntigravitySubscriptionInfo {
        current_tier: p.tier(v.get("currentTier")),
        paid_tier: p.tier(v.get("paidTier")),
        allowed_tiers,
        cloudaicompanion_project: p.text(
            project.map(|v| {
                if v.is_object() {
                    v.get("id").unwrap_or(&Value::Null)
                } else {
                    v
                }
            }),
            1024,
        ),
        gcp_managed: p.boolean(v.get("gcpManaged")),
        upgrade_subscription_uri: p.url(v.get("upgradeSubscriptionUri")),
    };
    (
        (info != AntigravitySubscriptionInfo::default()).then_some(info),
        p.invalid,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn rich_fixture_roundtrips_all_fields() {
        let value: Value =
            serde_json::from_str(include_str!("fixtures/antigravity-subscription.json")).unwrap();
        let (info, invalid) = parse(&value);
        assert!(!invalid);
        let info = info.unwrap();
        assert_eq!(info.allowed_tiers.as_ref().unwrap().len(), 1);
        let tier = info.paid_tier.as_ref().unwrap();
        assert_eq!(
            tier.upgrade_subscription_type.as_deref(),
            Some("SUBSCRIPTION")
        );
        assert_eq!(
            tier.privacy_notice.as_ref().unwrap().show_notice,
            Some(false)
        );
        assert_eq!(tier.user_defined_cloudaicompanion_project, Some(true));
        let encoded = serde_json::to_value(&info).unwrap();
        let expected: Value = serde_json::from_str(include_str!(
            "fixtures/antigravity-subscription-expected.json"
        ))
        .unwrap();
        assert_eq!(encoded, expected);
        assert_eq!(
            serde_json::from_value::<AntigravitySubscriptionInfo>(encoded).unwrap(),
            info
        );
    }
    #[test]
    fn mixed_invalid_fields_preserve_siblings() {
        let (info, invalid) = parse(
            &json!({"paidTier":{"name":"Pro", "description":"bad\ntext", "privacyNotice":{"showNotice":true,"noticeText":42}, "upgradeSubscriptionUri":"javascript:alert(1)"}, "allowedTiers":[42, {"id":"free","name":"Free"}], "gcpManaged":"true", "cloudaicompanionProject":{"id":"project"}, "upgradeSubscriptionUri":"https://example.invalid/upgrade"}),
        );
        assert!(invalid);
        let info = info.unwrap();
        let tier = info.paid_tier.unwrap();
        assert_eq!(tier.name.as_deref(), Some("Pro"));
        assert!(tier.description.is_none());
        assert!(tier.upgrade_subscription_uri.is_none());
        let notice = tier.privacy_notice.unwrap();
        assert_eq!(notice.show_notice, Some(true));
        assert!(notice.notice_text.is_none());
        assert_eq!(info.allowed_tiers.unwrap()[0].id.as_deref(), Some("free"));
        assert_eq!(info.cloudaicompanion_project.as_deref(), Some("project"));
        assert!(info.gcp_managed.is_none());
        assert!(info.upgrade_subscription_uri.is_some());
    }
    #[test]
    fn rejects_unsafe_urls_and_bounds() {
        for url in [
            "http://example.invalid",
            "file:///tmp/test",
            "https://user:pass@example.invalid",
            "https://@example.invalid",
            "https://example.invalid/\n",
            "https://example.invalid\\evil",
            "data:text/plain,test",
        ] {
            let (info, invalid) =
                parse(&json!({"upgradeSubscriptionUri":url,"currentTier":{"name":"Free"}}));
            assert!(invalid, "{url}");
            assert!(info.unwrap().upgrade_subscription_uri.is_none());
        }
        for url in [
            "https://example.invalid/upgrade?source=quotio#plans",
            "https://example.invalid?email=demo@example.invalid",
            "https://example.invalid#demo@example.invalid",
            "HTTPS://example.invalid/upgrade",
        ] {
            let (info, invalid) = parse(&json!({"upgradeSubscriptionUri":url}));
            assert!(!invalid, "{url}");
            assert_eq!(info.unwrap().upgrade_subscription_uri.as_deref(), Some(url));
        }
        let (info, invalid) =
            parse(&json!({"paidTier":{"name":"x".repeat(129),"description":"x".repeat(4097)}}));
        assert!(invalid);
        assert!(info.unwrap().paid_tier.unwrap().name.is_none());
        assert_eq!(parse(&json!({})), (None, false));
    }
}
