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
        self.entries.retain(|_, e| {
            e.finished
                .is_none_or(|t| t.elapsed() < Duration::from_secs(900))
        });
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
        if self.entries.len() >= 128 {
            return Err("operations_full");
        }
        let id = crate::accounts::random_string().map_err(|_| "internal_error")?;
        let operation = Operation {
            id: id.clone(),
            kind: kind.into(),
            status: "running",
            result: None,
            error: None,
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
            match result {
                Ok(value) => e.operation.result = Some(value),
                Err(code) => e.operation.error = Some(code),
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
        assert!(ops.get(&op.id).is_none());
        for _ in 0..128 {
            ops.start("refresh", None, String::new()).unwrap();
        }
        assert!(matches!(
            ops.start("refresh", None, String::new()),
            Err("operations_full")
        ));
    }
}
