//! Local read-only HTTP transport over the existing collector and report schema.
use crate::{
    cli::{Provider, ServeArgs},
    config::Config,
    domain::{ProviderFailure, ProviderId, UsageReport},
    error::ProviderError,
    fetch::{Cancellation, CollectRequest, Collector},
    providers::{EnvironmentCredentials, ProviderContext, SystemClock},
};
use axum::{
    Json, Router,
    extract::{Path, Request, State},
    http::{Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use clap::ValueEnum;
use ring::hmac;
use serde_json::{Value, json};
use std::{future::IntoFuture, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{RwLock, Semaphore, watch},
};

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("server requires a loopback listen address")]
    Listen,
    #[error("could not load server configuration")]
    Config,
    #[error("no providers enabled; use serve --provider or enabled_providers in config")]
    Providers,
    #[error("QUOTIO_SERVER_TOKEN must contain 32 to 4096 visible ASCII characters")]
    Token,
    #[error("could not bind server; check the listen address and port")]
    Bind,
    #[error("could not initialize the server")]
    Initialize,
}
impl ServerError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Listen | Self::Config | Self::Providers | Self::Token => 2,
            Self::Bind | Self::Initialize => 3,
        }
    }
}

#[derive(Default)]
struct Snapshot {
    report: Option<UsageReport>,
}
impl Snapshot {
    fn update(&mut self, mut next: UsageReport) {
        if let Some(previous) = self.report.take() {
            for usage in previous.providers {
                // Retain only accounts which failed this cycle. Accounts removed from
                // the vault disappear after a successful discovery/refresh cycle.
                let failed = next.failures.iter().any(|failure| {
                    failure.provider == usage.provider
                        && (failure.account_ref.is_none()
                            || failure.account_ref.as_ref().map(|a| &a.id)
                                == usage.account_ref.as_ref().map(|a| &a.id))
                });
                let replaced = next.providers.iter().any(|fresh| {
                    fresh.provider == usage.provider
                        && fresh.account_ref.as_ref().map(|a| &a.id)
                            == usage.account_ref.as_ref().map(|a| &a.id)
                });
                if failed && !replaced {
                    next.providers.push(usage);
                }
            }
        }
        self.report = Some(next);
    }
}

struct ApiState {
    snapshot: RwLock<Snapshot>,
    enabled: Vec<Provider>,
    address: std::net::SocketAddr,
    token: Option<hmac::Key>,
    requests: Semaphore,
}

fn token_key(token: Option<String>) -> Result<Option<hmac::Key>, ServerError> {
    token
        .map(|token| {
            if !(32..=4096).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(ServerError::Token);
            }
            Ok(hmac::Key::new(hmac::HMAC_SHA256, token.as_bytes()))
        })
        .transpose()
}

fn error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(json!({"error": code}))).into_response()
}

async fn guard(State(state): State<Arc<ApiState>>, request: Request, next: Next) -> Response {
    let mut response = if request.headers().contains_key(header::ORIGIN) {
        error(StatusCode::FORBIDDEN, "origin_not_allowed")
    } else if !valid_host(&request, state.address) {
        error(StatusCode::FORBIDDEN, "host_not_allowed")
    } else if !authorized(&request, state.token.as_ref()) {
        let mut response = error(StatusCode::UNAUTHORIZED, "unauthorized");
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
        response
    } else if request.method() != Method::GET && request.method() != Method::HEAD {
        let mut response = error(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
        response
            .headers_mut()
            .insert(header::ALLOW, "GET, HEAD".parse().unwrap());
        response
    } else if request.uri().query().is_some() {
        error(StatusCode::BAD_REQUEST, "unsupported_query")
    } else if let Ok(_permit) = state.requests.try_acquire() {
        next.run(request).await
    } else {
        error(StatusCode::SERVICE_UNAVAILABLE, "server_busy")
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    response
}

fn valid_host(request: &Request, address: std::net::SocketAddr) -> bool {
    let mut values = request.headers().get_all(header::HOST).iter();
    let Some(host) = values.next().and_then(|v| v.to_str().ok()) else {
        return false;
    };
    values.next().is_none()
        && [address.to_string(), format!("localhost:{}", address.port())]
            .iter()
            .any(|allowed| host.eq_ignore_ascii_case(allowed))
}

fn authorized(request: &Request, key: Option<&hmac::Key>) -> bool {
    let Some(key) = key else {
        return true;
    };
    let mut headers = request.headers().get_all(header::AUTHORIZATION).iter();
    let Some(token) = headers
        .next()
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
    else {
        return false;
    };
    if headers.next().is_some() || !(32..=4096).contains(&token.len()) {
        return false;
    }
    // Verify fixed-message tags with ring's constant-time comparison, without
    // storing or logging the original bearer token in server state.
    let candidate = hmac::Key::new(hmac::HMAC_SHA256, token.as_bytes());
    let tag = hmac::sign(&candidate, b"quotio-server-auth-v1");
    hmac::verify(key, b"quotio-server-auth-v1", tag.as_ref()).is_ok()
}

fn router(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/providers", get(providers))
        .route("/v1/usage", get(usage))
        .route("/v1/usage/{provider}", get(provider_usage))
        .fallback(|| async { error(StatusCode::NOT_FOUND, "not_found") })
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

async fn health(State(state): State<Arc<ApiState>>) -> Json<Value> {
    Json(json!({"status": "ok", "ready": state.snapshot.read().await.report.is_some()}))
}
async fn providers(State(state): State<Arc<ApiState>>) -> Json<Value> {
    Json(
        json!({"schema_version": 1, "providers": Provider::value_variants().iter().map(|p| {
        json!({"id": p.id(), "description": p.description(), "enabled": state.enabled.contains(p)})
    }).collect::<Vec<_>>()}),
    )
}
async fn usage(State(state): State<Arc<ApiState>>) -> Response {
    usage_response(&state, None).await
}
async fn provider_usage(State(state): State<Arc<ApiState>>, Path(id): Path<String>) -> Response {
    if !state.enabled.iter().any(|p| p.id() == id) {
        return error(StatusCode::NOT_FOUND, "provider_not_enabled");
    }
    usage_response(&state, Some(&id)).await
}
async fn usage_response(state: &ApiState, provider: Option<&str>) -> Response {
    let snapshot = state.snapshot.read().await;
    let Some(report) = &snapshot.report else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "not_ready");
    };
    let mut value = match serde_json::to_value(report) {
        Ok(value) => value,
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "encoding_failed"),
    };
    if let Some(id) = provider {
        for field in ["providers", "failures"] {
            value[field]
                .as_array_mut()
                .unwrap()
                .retain(|entry| entry["provider"] == id);
        }
    }
    Json(value).into_response()
}

async fn refresh(state: &ApiState, args: &ServeArgs, collector: &Collector) {
    let timeout = Duration::from_secs(args.timeout);
    let adapters = crate::accounts::service::adapters(
        state.enabled.clone(),
        !args.no_saved_accounts,
        timeout,
        None,
    )
    .await;
    let report = match adapters {
        Ok(providers) => {
            collector
                .collect(CollectRequest {
                    providers,
                    timeout,
                    cancellation: Cancellation::default(),
                })
                .await
        }
        Err(_) => UsageReport {
            schema_version: 1,
            generated_at: collector.context.clock.now(),
            providers: vec![],
            failures: state
                .enabled
                .iter()
                .map(|p| ProviderFailure {
                    provider: ProviderId(p.id().into()),
                    account_ref: None,
                    code: ProviderError::CredentialStorage,
                    message: ProviderError::CredentialStorage.to_string(),
                })
                .collect(),
        },
    };
    state.snapshot.write().await.update(report);
}

pub async fn run(args: ServeArgs) -> Result<(), ServerError> {
    if !args.listen.ip().is_loopback() {
        return Err(ServerError::Listen);
    }
    let config = Config::load(args.config.as_deref()).map_err(|_| ServerError::Config)?;
    let configured = config.providers().map_err(|_| ServerError::Config)?;
    let selected = if args.provider.is_empty() {
        configured
    } else {
        args.provider.clone()
    };
    let mut enabled = Vec::new();
    for provider in selected {
        if !enabled.contains(&provider) {
            enabled.push(provider);
        }
    }
    if enabled.is_empty() {
        return Err(ServerError::Providers);
    }
    let token = match std::env::var("QUOTIO_SERVER_TOKEN") {
        Ok(token) => token_key(Some(token))?,
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => return Err(ServerError::Token),
    };
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| ServerError::Initialize)?;
    let collector = Collector {
        context: ProviderContext {
            http,
            clock: Arc::new(SystemClock),
            credentials: Arc::new(EnvironmentCredentials),
        },
    };
    let listener = TcpListener::bind(args.listen)
        .await
        .map_err(|_| ServerError::Bind)?;
    let address = listener.local_addr().map_err(|_| ServerError::Bind)?;
    let state = Arc::new(ApiState {
        snapshot: RwLock::new(Snapshot::default()),
        enabled,
        address,
        token,
        requests: Semaphore::new(16),
    });
    let (stop, mut stopped) = watch::channel(false);
    let refresh_state = state.clone();
    let mut worker = tokio::spawn(async move {
        loop {
            refresh(&refresh_state, &args, &collector).await;
            tokio::time::sleep(Duration::from_secs(args.refresh_interval)).await;
        }
    });
    eprintln!("Quotio API listening on http://{address}");
    let server = axum::serve(listener, router(state))
        .with_graceful_shutdown(async move {
            let _ = stopped.wait_for(|stop| *stop).await;
        })
        .into_future();
    tokio::pin!(server);
    let result = tokio::select! {
        result = &mut server => result.map_err(|_| ServerError::Initialize),
        _ = &mut worker => {
            stop.send_replace(true);
            return Err(ServerError::Initialize);
        },
        _ = shutdown_signal() => {
            stop.send_replace(true);
            // Idle clients must not prevent the local process from stopping.
            match tokio::time::timeout(Duration::from_secs(2), &mut server).await {
                Ok(result) => result.map_err(|_| ServerError::Initialize),
                Err(_) => Ok(()),
            }
        }
    };
    worker.abort();
    let _ = worker.await;
    result
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = tokio::signal::ctrl_c() => (), _ = terminate.recv() => () }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AccountIdentity, AccountRef, ProviderUsage};

    fn report(accounts: &[&str], failed: &[Option<&str>]) -> UsageReport {
        UsageReport {
            schema_version: 1,
            generated_at: time::OffsetDateTime::UNIX_EPOCH,
            providers: accounts
                .iter()
                .map(|id| ProviderUsage {
                    provider: ProviderId("mock".into()),
                    account_ref: Some(AccountRef {
                        id: (*id).into(),
                        label: (*id).into(),
                    }),
                    account: AccountIdentity {
                        id: (*id).into(),
                        label: (*id).into(),
                        plan: None,
                    },
                    windows: vec![],
                })
                .collect(),
            failures: failed
                .iter()
                .map(|id| ProviderFailure {
                    provider: ProviderId("mock".into()),
                    account_ref: id.map(|id| AccountRef {
                        id: id.into(),
                        label: id.into(),
                    }),
                    code: ProviderError::Timeout,
                    message: ProviderError::Timeout.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn cache_keeps_failed_accounts_but_removes_deleted_accounts() {
        let mut snapshot = Snapshot::default();
        snapshot.update(report(&["local", "saved", "deleted"], &[]));
        snapshot.update(report(&["local"], &[Some("saved")]));
        let current = snapshot.report.as_ref().unwrap();
        assert_eq!(
            current
                .providers
                .iter()
                .map(|p| p.account.id.as_str())
                .collect::<Vec<_>>(),
            ["local", "saved"]
        );
        assert_eq!(current.failures.len(), 1);
        snapshot.update(report(&[], &[None]));
        assert_eq!(snapshot.report.as_ref().unwrap().providers.len(), 2);
        snapshot.update(report(&["saved"], &[]));
        assert_eq!(snapshot.report.as_ref().unwrap().providers.len(), 1);
        assert!(snapshot.report.as_ref().unwrap().failures.is_empty());
    }

    #[tokio::test]
    async fn usage_exposes_readiness_and_partial_failures_without_losing_accounts() {
        let state = ApiState {
            snapshot: RwLock::new(Snapshot::default()),
            enabled: vec![Provider::Mock],
            address: "127.0.0.1:8317".parse().unwrap(),
            token: None,
            requests: Semaphore::new(16),
        };
        assert_eq!(
            usage_response(&state, None).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        state
            .snapshot
            .write()
            .await
            .update(report(&["local", "saved"], &[]));
        state
            .snapshot
            .write()
            .await
            .update(report(&["local"], &[Some("saved")]));
        let response = usage_response(&state, Some("mock")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["providers"].as_array().unwrap().len(), 2);
        assert_eq!(json["failures"][0]["account_ref"]["id"], "saved");
        assert_eq!(json["failures"][0]["code"], "timeout");
    }

    #[test]
    fn bearer_and_host_validation_fail_closed() {
        let secret = "synthetic-local-api-token-1234567890";
        let key = token_key(Some(secret.into())).unwrap().unwrap();
        let request = Request::builder()
            .header(header::HOST, "127.0.0.2:8317")
            .header(header::AUTHORIZATION, format!("Bearer {secret}"))
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(authorized(&request, Some(&key)));
        assert!(valid_host(&request, "127.0.0.2:8317".parse().unwrap()));
        assert!(!valid_host(&request, "127.0.0.1:8317".parse().unwrap()));
        let wrong = token_key(Some("different-local-api-token-1234567890".into()))
            .unwrap()
            .unwrap();
        assert!(!authorized(&request, Some(&wrong)));
        assert!(token_key(Some("".into())).is_err());
        assert!(token_key(Some("x ".repeat(32))).is_err());
        let mut duplicate = request;
        duplicate.headers_mut().append(
            header::AUTHORIZATION,
            format!("Bearer {secret}").parse().unwrap(),
        );
        assert!(!authorized(&duplicate, Some(&key)));
        duplicate
            .headers_mut()
            .append(header::HOST, "localhost:8317".parse().unwrap());
        assert!(!valid_host(&duplicate, "127.0.0.2:8317".parse().unwrap()));
    }
}
