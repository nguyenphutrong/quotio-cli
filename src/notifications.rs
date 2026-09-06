//! Notification business policy. Native clients only ask permission and render deliveries.
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Preferences {
    pub suppressed_update_version: Option<String>,
    pub enabled: bool,
    pub quota_threshold: f64,
    pub quota_low: bool,
    pub cooling: bool,
    pub proxy_crash: bool,
    pub proxy_update: bool,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            suppressed_update_version: None,
            enabled: true,
            quota_threshold: 20.0,
            quota_low: true,
            cooling: true,
            proxy_crash: true,
            proxy_update: true,
        }
    }
}
impl Preferences {
    pub fn valid(&self) -> bool {
        self.quota_threshold.is_finite() && (0.0..=100.0).contains(&self.quota_threshold)
    }
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Submit,
    ObserveQuota,
    ObserveCooling,
    Clear,
    Suppress,
    ClearAll,
}
#[derive(Clone, Copy, Deserialize, Serialize, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    QuotaLow,
    AccountCooling,
    ProxyCrashed,
    ProxyStarted,
    ProxyUpdateAvailable,
    ProxyUpdateSucceeded,
    ProxyUpdateFailed,
    ProxyRolledBack,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub status: Option<String>,
    pub action: Action,
    pub event: Event,
    pub scope: Vec<String>,
    #[serde(default)]
    pub remaining: Vec<Option<f64>>,
    pub authorized: bool,
}
#[derive(Serialize, Debug, PartialEq)]
pub struct Decision {
    pub deliver: bool,
    pub remaining_percent: Option<f64>,
}
impl Decision {
    fn skip() -> Self {
        Self {
            deliver: false,
            remaining_percent: None,
        }
    }
}
#[derive(Default, Serialize, Deserialize)]
pub struct Policy {
    sent: HashSet<String>,
}
impl Policy {
    pub fn evaluate(
        &mut self,
        preferences: &Preferences,
        request: Request,
    ) -> Result<Decision, &'static str> {
        if !preferences.valid()
            || request.scope.len() > 2
            || request
                .scope
                .iter()
                .any(|s| s.is_empty() || s.len() > 512 || s.chars().any(char::is_control))
            || request.remaining.len() > 4096
        {
            return Err("invalid_notification");
        }
        let scope_count = match request.event {
            Event::QuotaLow | Event::AccountCooling => 2,
            Event::ProxyUpdateAvailable
            | Event::ProxyUpdateSucceeded
            | Event::ProxyUpdateFailed
            | Event::ProxyRolledBack => 1,
            _ => 0,
        };
        if request.scope.len() != scope_count {
            return Err("invalid_notification");
        }
        let key = tracking_key(request.event, &request.scope);
        let tracked = matches!(
            request.event,
            Event::QuotaLow | Event::AccountCooling | Event::ProxyUpdateAvailable
        );
        match request.action {
            Action::ClearAll => {
                self.sent.clear();
                return Ok(Decision::skip());
            }
            Action::Clear => {
                self.sent.remove(&key);
                return Ok(Decision::skip());
            }
            Action::Suppress => {
                if self.sent.len() >= 4096 {
                    return Err("notification_capacity");
                }
                self.sent.insert(key);
                return Ok(Decision::skip());
            }
            Action::ObserveCooling => {
                if request.event != Event::AccountCooling {
                    return Err("invalid_notification");
                }
                match request.status.as_deref() {
                    Some("ready") => {
                        self.sent.remove(&key);
                        return Ok(Decision::skip());
                    }
                    Some("cooling") => (),
                    _ => return Ok(Decision::skip()),
                }
            }
            Action::ObserveQuota if request.event != Event::QuotaLow => {
                return Err("invalid_notification");
            }
            _ => (),
        }
        let remaining = request
            .remaining
            .into_iter()
            .flatten()
            .filter(|v| v.is_finite() && *v >= 0.0)
            .reduce(f64::min);
        if request.event == Event::QuotaLow {
            let Some(remaining) = remaining else {
                return Ok(Decision::skip());
            };
            if remaining > preferences.quota_threshold {
                if matches!(request.action, Action::ObserveQuota) {
                    self.sent.remove(&key);
                }
                return Ok(Decision::skip());
            }
        }
        let enabled = match request.event {
            Event::QuotaLow => preferences.quota_low,
            Event::AccountCooling => preferences.cooling,
            Event::ProxyCrashed => preferences.proxy_crash,
            Event::ProxyUpdateAvailable => preferences.proxy_update,
            _ => true,
        };
        if !preferences.enabled || !enabled || !request.authorized {
            return Ok(Decision::skip());
        }
        if tracked {
            if self.sent.contains(&key) {
                return Ok(Decision::skip());
            }
            if self.sent.len() >= 4096 {
                return Err("notification_capacity");
            }
            self.sent.insert(key);
        }
        Ok(Decision {
            deliver: true,
            remaining_percent: if request.event == Event::QuotaLow {
                remaining
            } else {
                None
            },
        })
    }
}

fn tracking_key(event: Event, scope: &[String]) -> String {
    crate::cache::fingerprint(&[&serde_json::to_string(&(event, scope)).expect("serializable key")])
}

#[derive(Clone)]
pub struct Store(pub std::path::PathBuf);
impl Store {
    #[cfg(not(unix))]
    pub fn evaluate(&self, _: &Preferences, _: Request) -> Result<Decision, &'static str> {
        Err("notification_platform_unsupported")
    }

    #[cfg(unix)]
    pub fn evaluate(
        &self,
        preferences: &Preferences,
        request: Request,
    ) -> Result<Decision, &'static str> {
        use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
        use std::{
            fs::{self, File, OpenOptions},
            io::{Read, Write},
        };
        let parent = self.0.parent().ok_or("notification_storage_unavailable")?;
        fs::create_dir_all(parent).map_err(|_| "notification_storage_unavailable")?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(self.0.with_extension("lock"))
            .map_err(|_| "notification_storage_unavailable")?;
        if !lock
            .metadata()
            .map_err(|_| "notification_storage_unavailable")?
            .is_file()
        {
            return Err("notification_storage_unavailable");
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("notification_busy");
        }
        let mut policy = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&self.0)
        {
            Ok(file) => {
                if !file
                    .metadata()
                    .map_err(|_| "notification_storage_unavailable")?
                    .is_file()
                {
                    return Err("notification_storage_unavailable");
                }
                let mut bytes = Vec::new();
                file.take(1_048_577)
                    .read_to_end(&mut bytes)
                    .map_err(|_| "notification_storage_unavailable")?;
                if bytes.len() > 1_048_576 {
                    return Err("notification_storage_unavailable");
                }
                serde_json::from_slice::<Policy>(&bytes)
                    .map_err(|_| "notification_storage_unavailable")?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut policy = Policy::default();
                if let Some(version) = &preferences.suppressed_update_version {
                    policy.sent.insert(tracking_key(
                        Event::ProxyUpdateAvailable,
                        std::slice::from_ref(version),
                    ));
                }
                policy
            }
            Err(_) => return Err("notification_storage_unavailable"),
        };
        if policy.sent.len() > 4096
            || policy
                .sent
                .iter()
                .any(|key| key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("notification_storage_unavailable");
        }
        let previous = policy.sent.clone();
        let decision = policy.evaluate(preferences, request)?;
        if previous == policy.sent {
            return Ok(decision);
        }
        let bytes = serde_json::to_vec(&policy).map_err(|_| "notification_storage_unavailable")?;
        let temporary = parent.join(format!(
            ".notification-{}.tmp",
            crate::accounts::random_string().map_err(|_| "notification_storage_unavailable")?
        ));
        let result = (|| -> std::io::Result<()> {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            output.write_all(&bytes)?;
            output.sync_all()?;
            fs::rename(&temporary, &self.0)?;
            File::open(parent)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
            return Err("notification_storage_unavailable");
        }
        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn quota(values: &[Option<f64>], authorized: bool) -> Request {
        Request {
            status: None,
            action: Action::ObserveQuota,
            event: Event::QuotaLow,
            scope: vec!["codex".into(), "account".into()],
            remaining: values.to_vec(),
            authorized,
        }
    }
    #[test]
    fn unknown_is_not_exhausted_and_recovery_rearms_threshold() {
        let mut policy = Policy::default();
        let prefs = Preferences::default();
        assert!(
            !policy
                .evaluate(&prefs, quota(&[None, Some(-1.0)], true))
                .unwrap()
                .deliver
        );
        assert!(
            policy
                .evaluate(&prefs, quota(&[Some(20.0), Some(50.0)], true))
                .unwrap()
                .deliver
        );
        assert!(
            !policy
                .evaluate(&prefs, quota(&[Some(0.0)], true))
                .unwrap()
                .deliver
        );
        assert!(
            !policy
                .evaluate(&prefs, quota(&[Some(21.0)], true))
                .unwrap()
                .deliver
        );
        assert_eq!(
            policy.evaluate(&prefs, quota(&[Some(0.0)], true)).unwrap(),
            Decision {
                deliver: true,
                remaining_percent: Some(0.0)
            }
        );
    }
    #[test]
    fn denied_permission_does_not_consume_notification() {
        let mut policy = Policy::default();
        let prefs = Preferences::default();
        assert!(
            !policy
                .evaluate(&prefs, quota(&[Some(0.0)], false))
                .unwrap()
                .deliver
        );
        assert!(
            policy
                .evaluate(&prefs, quota(&[Some(0.0)], true))
                .unwrap()
                .deliver
        );
    }
    #[test]
    fn category_switches_and_update_suppression_are_backend_decisions() {
        let mut policy = Policy::default();
        let prefs = Preferences {
            proxy_crash: false,
            ..Default::default()
        };
        let event = |action, event, scope: Vec<String>| Request {
            status: None,
            action,
            event,
            scope,
            remaining: vec![],
            authorized: true,
        };
        assert!(
            !policy
                .evaluate(&prefs, event(Action::Submit, Event::ProxyCrashed, vec![]))
                .unwrap()
                .deliver
        );
        assert!(
            policy
                .evaluate(&prefs, event(Action::Submit, Event::ProxyStarted, vec![]))
                .unwrap()
                .deliver
        );
        policy
            .evaluate(
                &prefs,
                event(
                    Action::Suppress,
                    Event::ProxyUpdateAvailable,
                    vec!["2.0".into()],
                ),
            )
            .unwrap();
        assert!(
            !policy
                .evaluate(
                    &prefs,
                    event(
                        Action::Submit,
                        Event::ProxyUpdateAvailable,
                        vec!["2.0".into()]
                    )
                )
                .unwrap()
                .deliver
        );
        policy
            .evaluate(
                &prefs,
                event(
                    Action::Clear,
                    Event::ProxyUpdateAvailable,
                    vec!["2.0".into()],
                ),
            )
            .unwrap();
        assert!(
            policy
                .evaluate(
                    &prefs,
                    event(
                        Action::Submit,
                        Event::ProxyUpdateAvailable,
                        vec!["2.0".into()]
                    )
                )
                .unwrap()
                .deliver
        );
    }
    #[cfg(unix)]
    #[test]
    fn persisted_dedup_rearms_after_restart_and_rejects_symlinks() {
        let directory = std::env::temp_dir().join(format!(
            "quotio-notification-{}",
            crate::accounts::random_string().unwrap()
        ));
        std::fs::create_dir(&directory).unwrap();
        let store = Store(directory.join("state.json"));
        let preferences = Preferences::default();
        assert!(
            store
                .evaluate(&preferences, quota(&[Some(5.0)], true))
                .unwrap()
                .deliver
        );
        assert!(
            !Store(store.0.clone())
                .evaluate(&preferences, quota(&[Some(5.0)], true))
                .unwrap()
                .deliver
        );
        let contents = std::fs::read_to_string(&store.0).unwrap();
        assert!(!contents.contains("account"));
        assert!(!contents.contains("codex"));
        store
            .evaluate(&preferences, quota(&[Some(80.0)], true))
            .unwrap();
        assert!(
            store
                .evaluate(&preferences, quota(&[Some(5.0)], true))
                .unwrap()
                .deliver
        );
        let link = directory.join("link.json");
        std::os::unix::fs::symlink(&store.0, &link).unwrap();
        assert!(
            Store(link)
                .evaluate(&preferences, quota(&[Some(5.0)], true))
                .is_err()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn cooling_observations_rearm_without_client_transition_tracking() {
        let mut policy = Policy::default();
        let prefs = Preferences::default();
        let request = |status: &str| Request {
            action: Action::ObserveCooling,
            event: Event::AccountCooling,
            scope: vec!["claude".into(), "work".into()],
            remaining: vec![],
            authorized: true,
            status: Some(status.into()),
        };
        assert!(policy.evaluate(&prefs, request("cooling")).unwrap().deliver);
        assert!(!policy.evaluate(&prefs, request("cooling")).unwrap().deliver);
        assert!(!policy.evaluate(&prefs, request("ready")).unwrap().deliver);
        assert!(policy.evaluate(&prefs, request("cooling")).unwrap().deliver);
    }
}
