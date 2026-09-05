use crate::{domain::*, error::ProviderError, providers::*};
use std::{sync::Arc, time::Duration};
use tokio::{sync::watch, task::JoinSet};

#[derive(Clone)]
pub struct Cancellation(watch::Sender<bool>);
impl Default for Cancellation {
    fn default() -> Self {
        Self(watch::channel(false).0)
    }
}
impl Cancellation {
    pub fn cancel(&self) {
        self.0.send_replace(true);
    }
    async fn cancelled(&self) {
        let mut receiver = self.0.subscribe();
        let _ = receiver.wait_for(|value| *value).await;
    }
}
pub struct CollectRequest {
    pub providers: Vec<Arc<dyn ProviderAdapter>>,
    /// Total budget per provider, including retries and backoff.
    pub timeout: Duration,
    pub cancellation: Cancellation,
}
pub struct Collector {
    pub context: ProviderContext,
}
impl Collector {
    pub async fn collect(&self, request: CollectRequest) -> UsageReport {
        let mut tasks = JoinSet::new();
        let mut ids = Vec::new();
        let mut accounts = Vec::new();
        let mut task_order = std::collections::HashMap::new();
        for (index, adapter) in request.providers.into_iter().enumerate() {
            ids.push(adapter.id());
            accounts.push(adapter.account_ref());
            let context = self.context.clone();
            let cancellation = request.cancellation.clone();
            let timeout = request.timeout;
            let handle = tasks.spawn(async move {
                let work = async {
                    for attempt in 0..3 {
                        match adapter.fetch(&context).await {
                            Err(ProviderError::Transient) if adapter.idempotent() && attempt < 2 => {
                                tracing::debug!(attempt, "retry temporary provider failure");
                                tokio::time::sleep(Duration::from_millis(100 * (attempt + 1))).await;
                            }
                            result => return result,
                        }
                    }
                    unreachable!()
                };
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => Err(ProviderError::Cancelled),
                    result = tokio::time::timeout(timeout, work) => result.unwrap_or(Err(ProviderError::Timeout)),
                }
            });
            // Preserve request order and associate even a panicking task with its provider.
            task_order.insert(handle.id(), index);
        }
        let mut results = Vec::new();
        while let Some(result) = tasks.join_next_with_id().await {
            let (task_id, value) = match result {
                Ok((id, value)) => (id, value),
                Err(error) => (error.id(), Err(ProviderError::Internal)),
            };
            results.push((task_order[&task_id], value));
        }
        results.sort_by_key(|(index, _)| *index);
        let mut report = UsageReport {
            schema_version: 1,
            generated_at: self.context.clock.now(),
            providers: vec![],
            failures: vec![],
        };
        for (index, result) in results {
            let result = result.and_then(|usage| {
                if usage.provider != ids[index]
                    || usage.windows.is_empty()
                    || usage.windows.iter().any(|window| {
                        !window.quota.is_valid()
                            || window.consumption.as_ref().is_some_and(|c| {
                                !c.used.is_finite() || c.used < 0.0 || c.unit.trim().is_empty()
                            })
                    })
                {
                    Err(ProviderError::InvalidData)
                } else {
                    Ok(usage)
                }
            });
            match result {
                Ok(mut usage) => {
                    usage.account_ref = accounts[index].clone();
                    report.providers.push(usage);
                }
                Err(code) => report.failures.push(ProviderFailure {
                    account_ref: accounts[index].clone(),
                    provider: ids[index].clone(),
                    code,
                    message: code.to_string(),
                }),
            }
        }
        reconcile_accounts(&mut report.providers);
        report
    }
}

// Prefer a managed snapshot only when it identifies the same account. Email-only
// local identity is sufficient for a unique personal account, never a workspace.
fn reconcile_accounts(providers: &mut Vec<ProviderUsage>) {
    let personal = |usage: &ProviderUsage| {
        matches!(
            usage.account.plan.as_deref(),
            Some("free" | "plus" | "pro" | "go")
        )
    };
    let mut remove = Vec::new();
    for (index, local) in providers.iter().enumerate() {
        if !matches!(
            local.provider.0.as_str(),
            "codex" | "amp" | "synthetic" | "openrouter" | "zai" | "minimax"
        ) || local.account_ref.as_ref().is_none_or(|a| a.id != "local")
        {
            continue;
        }
        let managed: Vec<_> = providers
            .iter()
            .filter(|p| {
                p.provider == local.provider
                    && p.account_ref.as_ref().is_some_and(|a| a.id != "local")
            })
            .collect();
        if !matches!(local.provider.0.as_str(), "codex" | "amp") {
            if !local.account.id.is_empty()
                && managed
                    .iter()
                    .any(|saved| saved.account.id == local.account.id)
            {
                remove.push(index);
            }
            continue;
        }
        if local.provider.0 == "amp" {
            let duplicate = managed.iter().any(|saved| {
                !local.account.id.is_empty()
                    && local.account.id.eq_ignore_ascii_case(&saved.account.id)
                    && local.windows.len() == saved.windows.len()
                    && local.windows.iter().zip(&saved.windows).all(|(a, b)| {
                        a.label == b.label
                            && a.quota == b.quota
                            && a.amounts == b.amounts
                            && a.consumption == b.consumption
                            && a.resets_at == b.resets_at
                            && a.reset_description == b.reset_description
                    })
            });
            if duplicate {
                remove.push(index);
            }
            continue;
        }
        let exact = managed
            .iter()
            .any(|p| !local.account.id.is_empty() && p.account.id == local.account.id);
        let email_matches: Vec<_> = managed
            .iter()
            .filter(|p| p.account.label.eq_ignore_ascii_case(&local.account.label))
            .collect();
        let same_personal = personal(local)
            && local.account.label.contains('@')
            && email_matches.len() == 1
            && personal(email_matches[0]);
        if exact || same_personal {
            remove.push(index);
        }
    }
    let mut index = 0;
    providers.retain(|_| {
        let keep = !remove.contains(&index);
        index += 1;
        keep
    });
}
