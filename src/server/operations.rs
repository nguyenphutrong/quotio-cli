use serde::Serialize;
use serde_json::Value;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

#[derive(Clone, Serialize)]
pub struct Operation {
    pub id: String,
    pub kind: String,
    pub status: &'static str,
    pub result: Option<Value>,
    pub error: Option<&'static str>,
    pub message: Option<&'static str>,
}
struct Entry {
    operation: Operation,
    finished: Option<Instant>,
    key: Option<String>,
    fingerprint: String,
}
#[derive(Default)]
pub struct Operations {
    entries: HashMap<String, Entry>,
}
impl Operations {
    fn prune(&mut self) {
        // Account writes retain their retry keys for this server's lifetime.
        self.entries.retain(|_, e| {
            e.key.is_some()
                || e.finished
                    .is_none_or(|t| t.elapsed() < Duration::from_secs(900))
        });
        let mut completed: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, e)| e.key.is_none() && e.finished.is_some())
            .map(|(id, e)| (id.clone(), e.finished.unwrap()))
            .collect();
        completed.sort_by_key(|(_, at)| *at);
        let excess = completed.len().saturating_sub(128);
        for (id, _) in completed.into_iter().take(excess) {
            self.entries.remove(&id);
        }
    }
    pub fn start(
        &mut self,
        kind: &str,
        key: Option<String>,
        fingerprint: String,
    ) -> Result<(Operation, bool), &'static str> {
        self.prune();
        if let Some(key) = &key {
            if key.is_empty() || key.len() > 128 || !key.bytes().all(|c| c.is_ascii_graphic()) {
                return Err("invalid_idempotency_key");
            }
            if let Some(e) = self.entries.values().find(|e| e.key.as_ref() == Some(key)) {
                return if e.operation.kind == kind && e.fingerprint == fingerprint {
                    Ok((e.operation.clone(), false))
                } else {
                    Err("idempotency_conflict")
                };
            }
        }
        if key.is_some() && self.entries.values().filter(|e| e.key.is_some()).count() >= 4096 {
            return Err("idempotency_full");
        }
        if self
            .entries
            .values()
            .filter(|e| e.finished.is_none())
            .count()
            >= 128
        {
            return Err("operations_full");
        }
        let id = crate::accounts::random_string().map_err(|_| "internal_error")?;
        let operation = Operation {
            id: id.clone(),
            kind: kind.into(),
            status: "running",
            result: None,
            error: None,
            message: None,
        };
        self.entries.insert(
            id,
            Entry {
                operation: operation.clone(),
                finished: None,
                key,
                fingerprint,
            },
        );
        Ok((operation, true))
    }
    pub fn finish(&mut self, id: &str, result: Result<Value, &'static str>) {
        if let Some(e) = self.entries.get_mut(id) {
            e.finished = Some(Instant::now());
            e.operation.status = if result.is_ok() {
                "completed"
            } else {
                "failed"
            };
            tracing::info!(operation_id = %id, kind = %e.operation.kind, status = e.operation.status,
                code = result.as_ref().err().copied().unwrap_or("ok"), "operation finished");
            match result {
                Ok(value) => e.operation.result = Some(value),
                Err(code) => {
                    e.operation.error = Some(code);
                    if code == "credential_storage_unavailable" {
                        e.operation.message = Some(
                            "Allow Quotio access to its account vault on the Mac server, then retry. Remote requests cannot display Keychain authorization prompts.",
                        );
                    }
                }
            }
        }
    }
    pub fn get(&mut self, id: &str) -> Option<Operation> {
        self.prune();
        self.entries.get(id).map(|e| e.operation.clone())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retry_conflict_capacity_and_expiry() {
        let mut ops = Operations::default();
        let (op, new) = ops
            .start("create", Some("request-1".into()), "a".into())
            .unwrap();
        assert!(new);
        assert!(
            !ops.start("create", Some("request-1".into()), "a".into())
                .unwrap()
                .1
        );
        assert!(matches!(
            ops.start("create", Some("request-1".into()), "b".into()),
            Err("idempotency_conflict")
        ));
        ops.finish(&op.id, Ok(serde_json::json!({"account_id":"test"})));
        assert_eq!(ops.get(&op.id).unwrap().status, "completed");
        ops.entries.get_mut(&op.id).unwrap().finished =
            Some(Instant::now() - Duration::from_secs(901));
        assert!(ops.get(&op.id).is_some());
        assert!(
            !ops.start("create", Some("request-1".into()), "a".into())
                .unwrap()
                .1
        );
        for _ in 0..128 {
            ops.start("refresh", None, String::new()).unwrap();
        }
        assert!(matches!(
            ops.start("refresh", None, String::new()),
            Err("operations_full")
        ));
    }
    #[test]
    fn completed_refreshes_do_not_block_new_work() {
        let mut ops = Operations::default();
        let mut first = String::new();
        for n in 0..300 {
            let (op, _) = ops.start("refresh", None, n.to_string()).unwrap();
            if n == 0 {
                first = op.id.clone();
            }
            ops.finish(&op.id, Ok(serde_json::json!({"providers":1,"failures":0})));
        }
        assert!(ops.get(&first).is_none());
        assert_eq!(ops.entries.len(), 128);
        assert!(
            ops.start("account_update", Some("new-key".into()), "body".into())
                .is_ok()
        );
    }
    #[test]
    fn retry_ledger_is_bounded_without_blocking_refreshes() {
        let mut ops = Operations::default();
        for n in 0..4096 {
            let (op, _) = ops
                .start("account_update", Some(n.to_string()), "body".into())
                .unwrap();
            ops.finish(&op.id, Ok(serde_json::json!({"account_id":"fake"})));
        }
        assert!(matches!(
            ops.start("account_update", Some("overflow".into()), "body".into()),
            Err("idempotency_full")
        ));
        assert!(
            !ops.start("account_update", Some("0".into()), "body".into())
                .unwrap()
                .1
        );
        assert!(ops.start("refresh", None, "scope".into()).is_ok());
    }
}
