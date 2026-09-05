use super::{FetchFuture, ProviderAdapter, ProviderContext, Secret, http, process};
use crate::{domain::*, error::ProviderError};
use serde::Deserialize;
use std::{path::Path, time::Duration};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const BINARY: &str = "/Applications/Antigravity.app/Contents/Resources/bin/language_server";
const METHOD: &str = "/exa.language_server_pb.LanguageServerService/GetUserStatus";
/// This client is exclusively for the process-owned 127.0.0.1 service.
pub struct AntigravityProvider {
    local_http: reqwest::Client,
}
impl AntigravityProvider {
    pub fn new() -> Result<Self, ProviderError> {
        let local_http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|_| ProviderError::Unavailable)?;
        Ok(Self { local_http })
    }
}
struct Service {
    pid: u32,
    csrf: Secret,
}
fn discover(input: &str, uid: &str) -> Result<Service, ProviderError> {
    let mut services = Vec::new();
    for line in input.lines() {
        let mut fields = line.split_whitespace();
        let Some(pid) = fields.next().and_then(|v| v.parse::<u32>().ok()) else {
            continue;
        };
        if fields.next() != Some(uid) {
            continue;
        }
        // Match the executable itself, not a shell command containing its name.
        if fields.next() != Some(BINARY) {
            continue;
        }
        let args: Vec<_> = fields.collect();
        let csrf = args
            .iter()
            .enumerate()
            .find_map(|(i, arg)| {
                arg.strip_prefix("--csrf_token=").or_else(|| {
                    if *arg == "--csrf_token" {
                        args.get(i + 1).copied()
                    } else {
                        None
                    }
                })
            })
            .filter(|s| !s.is_empty())
            .ok_or(ProviderError::Authentication)?;
        services.push(Service {
            pid,
            csrf: Secret(csrf.to_owned()),
        });
    }
    if services.len() != 1 {
        return Err(ProviderError::Unavailable);
    }
    Ok(services.remove(0))
}
fn ports(input: &str) -> Vec<u16> {
    let mut ports: Vec<_> = input
        .lines()
        .filter_map(|line| line.strip_prefix('n'))
        .filter_map(|line| line.rsplit_once(':')?.1.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Response {
    user_status: Status,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    email: String,
    cascade_model_config_data: Models,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Models {
    client_model_configs: Vec<Model>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Model {
    label: String,
    quota_info: Option<ModelQuota>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ModelQuota {
    remaining_fraction: Option<f64>,
    reset_time: Option<String>,
}
fn parse(response: Response, now: OffsetDateTime) -> Result<ProviderUsage, ProviderError> {
    let status = response.user_status;
    if status.email.trim().is_empty()
        || status
            .cascade_model_config_data
            .client_model_configs
            .is_empty()
    {
        return Err(ProviderError::InvalidData);
    }
    let windows = status
        .cascade_model_config_data
        .client_model_configs
        .into_iter()
        .map(|model| {
            if model.label.trim().is_empty() {
                return Err(ProviderError::InvalidData);
            }
            let remaining = model.quota_info.as_ref().and_then(|q| q.remaining_fraction);
            if remaining.is_some_and(|n| !n.is_finite() || !(0.0..=1.0).contains(&n)) {
                return Err(ProviderError::InvalidData);
            }
            let resets_at = model
                .quota_info
                .and_then(|q| q.reset_time)
                .map(|s| OffsetDateTime::parse(&s, &Rfc3339))
                .transpose()
                .map_err(|_| ProviderError::InvalidData)?;
            let quota = Quota::from_remaining(remaining.map(|v| v * 100.0));
            let confidence = if remaining.is_some() {
                Confidence::Exact
            } else {
                Confidence::Unknown
            };
            Ok(QuotaWindow {
                label: model.label,
                quota,
                amounts: None,
                resets_at,
                fetched_at: now,
                provenance: Provenance {
                    source: "antigravity_local_service".into(),
                    confidence,
                },
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ProviderUsage {
        provider: ProviderId("antigravity".into()),
        account: AccountIdentity {
            id: status.email.clone(),
            label: status.email,
        },
        windows,
    })
}
impl ProviderAdapter for AntigravityProvider {
    fn id(&self) -> ProviderId {
        ProviderId("antigravity".into())
    }
    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> FetchFuture<'a> {
        Box::pin(async move {
            if !cfg!(target_os = "macos") {
                return Err(ProviderError::Unavailable);
            }
            let uid = process::output(Path::new("/usr/bin/id"), &["-u"]).await?;
            let uid = std::str::from_utf8(&uid)
                .map_err(|_| ProviderError::InvalidData)?
                .trim();
            let processes =
                process::output(Path::new("/bin/ps"), &["-axo", "pid=,uid=,args="]).await?;
            let service = discover(
                std::str::from_utf8(&processes).map_err(|_| ProviderError::InvalidData)?,
                uid,
            )?;
            let pid = service.pid.to_string();
            let listeners = process::output(
                Path::new("/usr/sbin/lsof"),
                &["-nP", "-a", "-p", &pid, "-iTCP", "-sTCP:LISTEN", "-Fn"],
            )
            .await?;
            let listeners =
                ports(std::str::from_utf8(&listeners).map_err(|_| ProviderError::InvalidData)?);
            let mut last_error = ProviderError::Unavailable;
            for port in listeners {
                let request = self.local_http.post(format!("https://127.0.0.1:{port}{METHOD}"))
                    .header("X-Codeium-Csrf-Token", http::sensitive(&service.csrf.0)?)
                    .json(&serde_json::json!({"metadata":{"ideName":"antigravity","extensionName":"antigravity","locale":"en"}}));
                match tokio::time::timeout(
                    Duration::from_secs(2),
                    http::json::<Response>(request, context.clock.now()),
                )
                .await
                {
                    Ok(Ok(response)) => return parse(response, context.clock.now()),
                    Ok(Err(error)) => last_error = error,
                    Err(_) => last_error = ProviderError::Timeout,
                }
            }
            Err(last_error)
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_is_owned_exact_and_unambiguous() {
        let row = format!("12 501 {BINARY} --csrf_token synthetic\n");
        assert_eq!(discover(&row, "501").unwrap().pid, 12);
        assert!(discover(&row, "502").is_err());
        assert!(discover(&format!("{row}{row}"), "501").is_err());
        assert!(
            discover(
                &format!("12 501 sh -c {BINARY} --csrf_token synthetic"),
                "501"
            )
            .is_err()
        );
        assert_eq!(ports("p12\nn127.0.0.1:1234\nn*:1234\nn*:0\n"), vec![1234]);
    }
    #[test]
    fn fractions_resets_and_absent_quota() {
        let response = serde_json::from_value(serde_json::json!({"userStatus":{"email":"demo@example.com","cascadeModelConfigData":{"clientModelConfigs":[{"label":"Model A","quotaInfo":{"remainingFraction":0.5,"resetTime":"2026-09-05T10:00:00+07:00"}},{"label":"Model B"},{"label":"Model C","quotaInfo":{"remainingFraction":0}}]}}})).unwrap();
        let usage = parse(response, OffsetDateTime::UNIX_EPOCH).unwrap();
        assert_eq!(usage.windows.len(), 3);
        assert_eq!(usage.windows[0].quota, Quota::from_used(Some(50.0)));
        assert_eq!(usage.windows[1].quota, Quota::Unknown);
        assert_eq!(usage.windows[2].quota, Quota::from_used(Some(100.0)));
    }
}
