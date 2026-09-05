use quotio::{
    domain::*,
    error::ProviderError,
    fetch::*,
    providers::{mock::MockProvider, *},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use time::{OffsetDateTime, macros::datetime};
struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        datetime!(2026-01-01 0:00 UTC)
    }
}
struct NoCredentials;
impl CredentialStore for NoCredentials {
    fn get(&self, _: &str) -> Option<Secret> {
        None
    }
}
fn collector() -> Collector {
    Collector {
        context: ProviderContext {
            http: reqwest::Client::new(),
            clock: Arc::new(FixedClock),
            credentials: Arc::new(NoCredentials),
        },
    }
}
struct Fake {
    delay: Duration,
    error: ProviderError,
    calls: Arc<AtomicUsize>,
    retry: bool,
}
impl ProviderAdapter for Fake {
    fn id(&self) -> ProviderId {
        ProviderId("fake".into())
    }
    fn idempotent(&self) -> bool {
        self.retry
    }
    fn fetch<'a>(&'a self, _: &'a ProviderContext) -> FetchFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            Err(self.error)
        })
    }
}
fn request(providers: Vec<Arc<dyn ProviderAdapter>>) -> CollectRequest {
    CollectRequest {
        providers,
        timeout: Duration::from_secs(1),
        cancellation: Cancellation::default(),
    }
}
#[test]
fn normalize_and_preserve_unknown() {
    assert_eq!(Quota::from_used(None), Quota::Unknown);
    assert_eq!(Quota::from_used(Some(f64::NAN)), Quota::Unknown);
    assert_eq!(Quota::from_used(Some(f64::INFINITY)), Quota::Unknown);
    assert_eq!(Quota::from_used(Some(-5.0)), Quota::from_used(Some(0.0)));
    assert_eq!(Quota::from_used(Some(105.0)), Quota::from_used(Some(100.0)));
    assert_ne!(Quota::from_used(None), Quota::from_remaining(Some(0.0)));
    assert_eq!(
        Quota::from_remaining(Some(75.0)),
        Quota::from_used(Some(25.0))
    );
}
#[tokio::test(start_paused = true)]
async fn partial_failure_and_multiple_windows() {
    let bad = Fake {
        delay: Duration::ZERO,
        error: ProviderError::Authentication,
        calls: Arc::default(),
        retry: true,
    };
    let report = collector()
        .collect(request(vec![Arc::new(MockProvider), Arc::new(bad)]))
        .await;
    assert_eq!(report.exit_code(), 1);
    assert_eq!(report.providers[0].windows.len(), 3);
    assert_eq!(report.failures[0].code, ProviderError::Authentication);
    assert_eq!(report.generated_at, FixedClock.now());
}
#[tokio::test(start_paused = true)]
async fn deadline_and_cancellation() {
    let slow = || {
        Arc::new(Fake {
            delay: Duration::from_secs(10),
            error: ProviderError::Transient,
            calls: Arc::default(),
            retry: true,
        }) as Arc<dyn ProviderAdapter>
    };
    let report = collector().collect(request(vec![slow()])).await;
    assert_eq!(report.failures[0].code, ProviderError::Timeout);
    assert_eq!(report.exit_code(), 3);
    let req = request(vec![slow()]);
    req.cancellation.cancel();
    let report = collector().collect(req).await;
    assert_eq!(report.failures[0].code, ProviderError::Cancelled);
}
#[tokio::test(start_paused = true)]
async fn retry_is_bounded_and_only_idempotent_transient() {
    for (retry, error, expected) in [
        (true, ProviderError::Transient, 3),
        (false, ProviderError::Transient, 1),
        (true, ProviderError::Authentication, 1),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let fake = Fake {
            delay: Duration::ZERO,
            error,
            calls: calls.clone(),
            retry,
        };
        collector().collect(request(vec![Arc::new(fake)])).await;
        assert_eq!(calls.load(Ordering::SeqCst), expected);
    }
}
#[tokio::test(start_paused = true)]
async fn requests_run_concurrently() {
    let fake = || {
        Arc::new(Fake {
            delay: Duration::from_millis(700),
            error: ProviderError::Authentication,
            calls: Arc::default(),
            retry: false,
        }) as Arc<dyn ProviderAdapter>
    };
    let start = tokio::time::Instant::now();
    collector().collect(request(vec![fake(), fake()])).await;
    assert!(start.elapsed() < Duration::from_secs(1));
}
#[tokio::test]
async fn success_and_empty_exit_codes() {
    assert_eq!(
        collector()
            .collect(request(vec![Arc::new(MockProvider)]))
            .await
            .exit_code(),
        0
    );
    assert_eq!(collector().collect(request(vec![])).await.exit_code(), 3);
}

struct InvalidProvider;
impl ProviderAdapter for InvalidProvider {
    fn id(&self) -> ProviderId {
        ProviderId("mock".into())
    }
    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> FetchFuture<'a> {
        Box::pin(async move {
            let mut usage = MockProvider.fetch(context).await?;
            usage.windows[0].quota = Quota::Available {
                used_percent: f64::NAN,
                remaining_percent: 50.0,
            };
            Ok(usage)
        })
    }
}
#[tokio::test]
async fn invalid_adapter_data_is_a_provider_failure() {
    let report = collector()
        .collect(request(vec![Arc::new(InvalidProvider)]))
        .await;
    assert_eq!(report.exit_code(), 3);
    assert_eq!(report.failures[0].code, ProviderError::InvalidData);
    assert!(report.providers.is_empty());
    assert!(
        !Quota::Exhausted {
            used_percent: 10.0,
            remaining_percent: 90.0
        }
        .is_valid()
    );
    assert!(
        !Quota::Available {
            used_percent: 50.0,
            remaining_percent: 40.0
        }
        .is_valid()
    );
    let json = quotio::output::json::render(&report).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        value["failures"][0],
        serde_json::json!({"provider":"mock", "code":"invalid_data", "message":"provider returned invalid usage"})
    );
}
struct DropFlag(Arc<AtomicUsize>);
impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
struct PendingProvider(Arc<AtomicUsize>);
impl ProviderAdapter for PendingProvider {
    fn id(&self) -> ProviderId {
        ProviderId("pending".into())
    }
    fn fetch<'a>(&'a self, _: &'a ProviderContext) -> FetchFuture<'a> {
        Box::pin(async move {
            let _guard = DropFlag(self.0.clone());
            std::future::pending().await
        })
    }
}
#[tokio::test(start_paused = true)]
async fn cancellation_drops_inflight_work_and_keeps_success() {
    let drops = Arc::new(AtomicUsize::new(0));
    let req = request(vec![
        Arc::new(MockProvider),
        Arc::new(PendingProvider(drops.clone())),
    ]);
    let cancellation = req.cancellation.clone();
    let collect = collector();
    let (report, ()) = tokio::join!(collect.collect(req), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancellation.cancel();
    });
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(report.exit_code(), 1);
    assert_eq!(report.failures[0].code, ProviderError::Cancelled);
}
#[tokio::test(start_paused = true)]
async fn deadline_drops_inflight_work() {
    let drops = Arc::new(AtomicUsize::new(0));
    let report = collector()
        .collect(request(vec![Arc::new(PendingProvider(drops.clone()))]))
        .await;
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(report.failures[0].code, ProviderError::Timeout);
}
