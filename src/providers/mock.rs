use super::*;
use crate::domain::*;
use time::macros::datetime;
pub struct MockProvider;
impl ProviderAdapter for MockProvider {
    fn id(&self) -> ProviderId {
        ProviderId("mock".into())
    }
    fn idempotent(&self) -> bool {
        true
    }
    fn fetch<'a>(&'a self, _context: &'a ProviderContext) -> FetchFuture<'a> {
        Box::pin(async move {
            let fetched_at = datetime!(2026-01-01 0:00 UTC);
            Ok(ProviderUsage {
                account_ref: None,
                provider: self.id(),
                account: AccountIdentity {
                    plan: None,
                    id: "mock-account".into(),
                    label: "Demo account".into(),
                },
                windows: [
                    ("Session", Some(25.0)),
                    ("Weekly", Some(100.0)),
                    ("Monthly", None),
                ]
                .into_iter()
                .map(|(label, used)| QuotaWindow {
                    consumption: None,
                    reset_description: None,
                    amounts: None,
                    label: label.into(),
                    quota: Quota::from_used(used),
                    resets_at: used.map(|_| datetime!(2026-01-08 0:00 UTC)),
                    provenance: Provenance {
                        source: "mock_fixture".into(),
                        confidence: Confidence::Exact,
                    },
                    fetched_at,
                })
                .collect(),
            })
        })
    }
}
