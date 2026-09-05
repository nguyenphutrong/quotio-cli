use super::process::MAX_BYTES;
use crate::error::ProviderError;
use reqwest::{
    RequestBuilder,
    header::{HeaderValue, RETRY_AFTER},
};
use serde::de::DeserializeOwned;
use std::time::Duration;
use time::{OffsetDateTime, format_description::well_known::Rfc2822};

pub(crate) fn sensitive(value: &str) -> Result<HeaderValue, ProviderError> {
    let mut header = HeaderValue::from_str(value).map_err(|_| ProviderError::Authentication)?;
    header.set_sensitive(true);
    Ok(header)
}
pub(crate) async fn json<T: DeserializeOwned>(
    request: RequestBuilder,
    now: OffsetDateTime,
) -> Result<T, ProviderError> {
    let mut response = request.send().await.map_err(|error| {
        if error.is_timeout() {
            ProviderError::Timeout
        } else {
            ProviderError::Transient
        }
    })?;
    match response.status().as_u16() {
        200..=299 => (),
        401 | 403 => return Err(ProviderError::Authentication),
        429 => {
            // The outer provider deadline includes this wait. Never shorten Retry-After.
            let delay = response
                .headers()
                .get(RETRY_AFTER)
                .and_then(|h| h.to_str().ok())
                .and_then(|value| {
                    value
                        .parse::<u64>()
                        .ok()
                        .map(Duration::from_secs)
                        .or_else(|| {
                            OffsetDateTime::parse(value, &Rfc2822).ok().map(|at| {
                                Duration::from_secs((at - now).whole_seconds().max(0) as u64)
                            })
                        })
                });
            if let Some(delay) = delay {
                if delay > Duration::from_secs(3600) {
                    return Err(ProviderError::RateLimited);
                }
                tokio::time::sleep(delay).await;
                return Err(ProviderError::Transient);
            }
            return Err(ProviderError::RateLimited);
        }
        500..=599 => return Err(ProviderError::Transient),
        _ => return Err(ProviderError::Unavailable),
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BYTES as u64)
    {
        return Err(ProviderError::InvalidData);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ProviderError::Transient)?
    {
        if bytes.len() + chunk.len() > MAX_BYTES {
            return Err(ProviderError::InvalidData);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| ProviderError::InvalidData)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    async fn serve(response: String) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 8192];
            let length = socket.read(&mut request).await.unwrap();
            socket.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(request[..length].to_vec()).unwrap()
        });
        (format!("http://{address}/quota"), task)
    }
    #[tokio::test]
    async fn status_errors_and_body_limits_are_safe() {
        for (status, headers, expected) in [
            (401, "Content-Length: 0", ProviderError::Authentication),
            (403, "Content-Length: 0", ProviderError::Authentication),
            (429, "Content-Length: 0", ProviderError::RateLimited),
            (
                429,
                "Content-Length: 0\r\nRetry-After: 0",
                ProviderError::Transient,
            ),
            (
                429,
                "Content-Length: 0\r\nRetry-After: 18446744073709551615",
                ProviderError::RateLimited,
            ),
            (503, "Content-Length: 0", ProviderError::Transient),
            (200, "Content-Length: 1048577", ProviderError::InvalidData),
        ] {
            let (url, task) = serve(format!(
                "HTTP/1.1 {status} Test\r\n{headers}\r\nConnection: close\r\n\r\n"
            ))
            .await;
            let request = reqwest::Client::new()
                .get(url)
                .header("Authorization", sensitive("Bearer sentinel").unwrap());
            assert_eq!(
                json::<serde_json::Value>(request, OffsetDateTime::UNIX_EPOCH)
                    .await
                    .unwrap_err(),
                expected
            );
            assert!(task.await.unwrap().contains("Bearer sentinel"));
        }
    }
    #[tokio::test]
    async fn valid_invalid_json_and_redirect() {
        for (body, valid) in [("{\"remaining\":25}", true), ("secret-sentinel", false)] {
            let (url, task) = serve(format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ))
            .await;
            let result = json::<serde_json::Value>(
                reqwest::Client::new().get(url),
                OffsetDateTime::UNIX_EPOCH,
            )
            .await;
            assert_eq!(result.is_ok(), valid);
            task.await.unwrap();
        }
        let (url,task) = serve("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/secret\r\nContent-Length: 0\r\n\r\n".into()).await;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        assert_eq!(
            json::<serde_json::Value>(client.get(url), OffsetDateTime::UNIX_EPOCH)
                .await
                .unwrap_err(),
            ProviderError::Unavailable
        );
        task.await.unwrap();
    }
}
