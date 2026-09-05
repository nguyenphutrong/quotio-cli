pub mod amp;
pub mod antigravity;
pub(crate) mod antigravity_auth;
mod antigravity_local;
pub mod catalog;
pub mod codex;
pub mod codex_api;
pub mod factory;
pub(crate) mod http;
pub mod key_api;
pub mod mock;
pub(crate) mod process;
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
/// Dropping fetch must cancel network requests and child processes. Native OS reads
/// may finish after cancellation; keep those closures read-only and bound their
/// response size and caller wait. Never detach writes or return raw diagnostics.
/// Only public account and
/// quota metadata belongs in ProviderUsage.
pub trait ProviderAdapter: Send + Sync {
    fn id(&self) -> ProviderId;
    fn account_ref(&self) -> Option<crate::domain::AccountRef> {
        None
    }
    /// Opaque login/scope identity. None disables caching when identity cannot be verified.
    fn cache_identity<'a>(
        &'a self,
        context: &'a ProviderContext,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
        Box::pin(async move { crate::cache::environment_identity(&self.id().0, context) })
    }
    fn idempotent(&self) -> bool {
        false
    }
    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> FetchFuture<'a>;
}
