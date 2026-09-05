use axum::{
    Json,
    extract::Request,
    http::{Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use ring::hmac;
use serde_json::json;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Semaphore;

pub struct Policy {
    pub manage: bool,
    hosts: Vec<String>,
    origins: Vec<String>,
    token: Option<hmac::Key>,
    requests: Semaphore,
}
impl Policy {
    pub fn new(
        address: SocketAddr,
        manage: bool,
        public_url: Option<&str>,
        origins: &[String],
        token: Option<String>,
    ) -> Result<Self, &'static str> {
        if (manage || public_url.is_some()) && token.is_none() {
            return Err("server_token_required");
        }
        let token = token
            .map(|value| {
                if !(32..=4096).contains(&value.len())
                    || !value.bytes().all(|b| b.is_ascii_graphic())
                {
                    return Err("invalid_server_token");
                }
                Ok(hmac::Key::new(hmac::HMAC_SHA256, value.as_bytes()))
            })
            .transpose()?;
        let mut hosts = vec![address.to_string(), format!("localhost:{}", address.port())];
        if let Some(url) = public_url {
            let url = origin_url(url)?;
            if url.scheme() != "https" {
                return Err("invalid_public_url");
            }
            let origin = url.origin().ascii_serialization();
            let authority = origin
                .strip_prefix("https://")
                .ok_or("invalid_public_url")?;
            hosts.push(authority.into());
            if url.port().is_none() {
                hosts.push(format!("{authority}:443"));
            }
        }
        let origins = origins
            .iter()
            .map(|value| origin_url(value).map(|u| u.origin().ascii_serialization()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            manage,
            hosts,
            origins,
            token,
            requests: Semaphore::new(16),
        })
    }
}
// reqwest re-exports Url but not its Position enum. Authority uses the validated
// origin string so credentials, paths and queries can never become trusted hosts.
fn origin_url(value: &str) -> Result<reqwest::Url, &'static str> {
    let url = reqwest::Url::parse(value).map_err(|_| "invalid_origin")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("invalid_origin");
    }
    if url.scheme() == "http"
        && !matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
    {
        return Err("invalid_origin");
    }
    Ok(url)
}
fn one<'a>(headers: &'a axum::http::HeaderMap, key: &str) -> Option<&'a str> {
    let mut values = headers.get_all(key).iter();
    let v = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        None
    } else {
        Some(v)
    }
}
fn authorized(request: &Request, key: Option<&hmac::Key>) -> bool {
    let Some(key) = key else { return true };
    let Some(token) =
        one(request.headers(), "authorization").and_then(|v| v.strip_prefix("Bearer "))
    else {
        return false;
    };
    if !(32..=4096).contains(&token.len()) {
        return false;
    }
    let candidate = hmac::Key::new(hmac::HMAC_SHA256, token.as_bytes());
    let tag = hmac::sign(&candidate, b"quotio-server-auth-v1");
    hmac::verify(key, b"quotio-server-auth-v1", tag.as_ref()).is_ok()
}
pub fn error(status: StatusCode, code: &'static str) -> Response {
    let mut body = json!({"error":code});
    if code == "credential_storage_unavailable" {
        body["message"] = json!(
            "Allow Quotio access to its account vault on the Mac server, then retry. Remote requests cannot display Keychain authorization prompts."
        );
    }
    (status, Json(body)).into_response()
}
pub async fn guard(
    axum::extract::State(policy): axum::extract::State<Arc<Policy>>,
    request: Request,
    next: Next,
) -> Response {
    let origin = one(request.headers(), "origin")
        .filter(|origin| policy.origins.iter().any(|o| o == origin))
        .map(str::to_owned);
    let methods = if policy.manage {
        "GET, HEAD, POST, PATCH, DELETE, OPTIONS"
    } else {
        "GET, HEAD, OPTIONS"
    };
    let mut response = if !one(request.headers(), "host")
        .is_some_and(|host| policy.hosts.iter().any(|h| h.eq_ignore_ascii_case(host)))
    {
        error(StatusCode::FORBIDDEN, "host_not_allowed")
    } else if request.headers().contains_key(header::ORIGIN) && origin.is_none() {
        error(StatusCode::FORBIDDEN, "origin_not_allowed")
    } else if request.method() == Method::OPTIONS {
        if origin.is_none()
            || !one(request.headers(), "access-control-request-method")
                .is_some_and(|v| methods.split(", ").any(|m| m == v && m != "OPTIONS"))
            || one(request.headers(), "access-control-request-headers").is_some_and(|v| {
                v.split(',').any(|h| {
                    !matches!(
                        h.trim().to_ascii_lowercase().as_str(),
                        "authorization" | "content-type" | "idempotency-key"
                    )
                })
            })
        {
            error(StatusCode::FORBIDDEN, "preflight_not_allowed")
        } else {
            StatusCode::NO_CONTENT.into_response()
        }
    } else if !authorized(&request, policy.token.as_ref()) {
        let mut r = error(StatusCode::UNAUTHORIZED, "unauthorized");
        r.headers_mut()
            .insert(header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
        r
    } else if !matches!(*request.method(), Method::GET | Method::HEAD) && !policy.manage {
        error(StatusCode::METHOD_NOT_ALLOWED, "read_only")
    } else if request.uri().query().is_some() {
        error(StatusCode::BAD_REQUEST, "unsupported_query")
    } else if let Ok(_permit) = policy.requests.try_acquire() {
        next.run(request).await
    } else {
        error(StatusCode::SERVICE_UNAVAILABLE, "server_busy")
    };
    if (response.status().is_client_error() || response.status().is_server_error())
        && !response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|v| v.as_bytes().starts_with(b"application/json"))
    {
        response = error(
            response.status(),
            match response.status() {
                StatusCode::NOT_FOUND => "not_found",
                StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
                StatusCode::PAYLOAD_TOO_LARGE => "body_too_large",
                _ => "invalid_request",
            },
        );
    }
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::VARY, "Origin".parse().unwrap());
    if let Some(origin) = origin {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.parse().unwrap());
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            methods.parse().unwrap(),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            "Authorization, Content-Type, Idempotency-Key"
                .parse()
                .unwrap(),
        );
    }
    response
}
