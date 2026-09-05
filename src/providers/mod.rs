pub mod mock;
use crate::{
    domain::{ProviderId, ProviderUsage},
    error::ProviderError,
};
use std::{future::Future, pin::Pin, sync::Arc};
use time::OffsetDateTime;

pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}
// Credentials are intentionally not Debug or Serialize.
pub struct Secret(pub String);
pub trait CredentialStore: Send + Sync {
    fn get(&self, name: &str) -> Option<Secret>;
}
pub struct EnvironmentCredentials;
impl CredentialStore for EnvironmentCredentials {
    fn get(&self, name: &str) -> Option<Secret> {
        std::env::var(name).ok().map(Secret)
    }
}
#[derive(Clone)]
pub struct ProviderContext {
    pub http: reqwest::Client,
    pub clock: Arc<dyn Clock>,
    pub credentials: Arc<dyn CredentialStore>,
}
pub type FetchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ProviderUsage, ProviderError>> + Send + 'a>>;
/// Fetch must be cancellation-safe: dropping its future stops all work.
/// Never detach tasks or return raw server diagnostics. Only public account and
/// quota metadata belongs in ProviderUsage.
pub trait ProviderAdapter: Send + Sync {
    fn id(&self) -> ProviderId;
    fn idempotent(&self) -> bool {
        false
    }
    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> FetchFuture<'a>;
}
