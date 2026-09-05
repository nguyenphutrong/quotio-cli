use super::{AccountError, Document};
use std::{
    fs::{File, OpenOptions},
    path::PathBuf,
    sync::Arc,
};

pub trait Backend: Send + Sync {
    fn read(&self) -> Result<Option<Vec<u8>>, AccountError>;
    /// Atomically replace this application's document; leave old data on failure.
    fn write(&self, bytes: &[u8]) -> Result<(), AccountError>;
}
pub struct Keychain;
impl Backend for Keychain {
    fn read(&self) -> Result<Option<Vec<u8>>, AccountError> {
        #[cfg(target_os = "macos")]
        {
            match security_framework::passwords::get_generic_password(
                "app.quotio.cli.accounts.v1",
                "vault",
            ) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(e) if e.code() == -25300 => Ok(None),
                Err(_) => Err(AccountError::Storage),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(AccountError::Unsupported)
        }
    }
    fn write(&self, bytes: &[u8]) -> Result<(), AccountError> {
        #[cfg(target_os = "macos")]
        {
            security_framework::passwords::set_generic_password(
                "app.quotio.cli.accounts.v1",
                "vault",
                bytes,
            )
            .map_err(|_| AccountError::Storage)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = bytes;
            Err(AccountError::Unsupported)
        }
    }
}
#[derive(Clone)]
pub struct Vault {
    backend: Arc<dyn Backend>,
    lock_path: PathBuf,
}
pub struct Transaction {
    backend: Arc<dyn Backend>,
    _lock: File,
    pub document: Document,
}
impl Vault {
    pub fn system() -> Result<Self, AccountError> {
        let dirs = directories::ProjectDirs::from("", "", "quotio").ok_or(AccountError::Storage)?;
        Ok(Self::new(
            Arc::new(Keychain),
            dirs.data_local_dir().join("accounts.lock"),
        ))
    }
    pub fn new(backend: Arc<dyn Backend>, lock_path: PathBuf) -> Self {
        Self { backend, lock_path }
    }
    pub fn begin(&self) -> Result<Transaction, AccountError> {
        let parent = self.lock_path.parent().ok_or(AccountError::Storage)?;
        std::fs::create_dir_all(parent).map_err(|_| AccountError::Storage)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let lock = options
            .open(&self.lock_path)
            .map_err(|_| AccountError::Storage)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // The descriptor remains alive for the full transaction, including refresh.
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(AccountError::Busy);
            }
        }
        #[cfg(not(unix))]
        {
            return Err(AccountError::Unsupported);
        }
        let document = match self.backend.read()? {
            None => Document::empty(),
            Some(bytes) => {
                if bytes.len() > 1024 * 1024 {
                    return Err(AccountError::Corrupt);
                }
                let doc: Document =
                    serde_json::from_slice(&bytes).map_err(|_| AccountError::Corrupt)?;
                if doc.version != 1 {
                    return Err(AccountError::Corrupt);
                }
                doc
            }
        };
        Ok(Transaction {
            backend: self.backend.clone(),
            _lock: lock,
            document,
        })
    }
}
impl Transaction {
    pub fn commit(self) -> Result<(), AccountError> {
        let bytes = serde_json::to_vec(&self.document).map_err(|_| AccountError::Corrupt)?;
        if bytes.len() > 1024 * 1024 {
            return Err(AccountError::Input);
        }
        self.backend.write(&bytes)
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        accounts::{Credential, random_string},
        cli::Provider,
    };
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };
    #[derive(Default)]
    pub struct Memory {
        bytes: Mutex<Option<Vec<u8>>>,
        pub fail: AtomicBool,
    }
    impl Backend for Memory {
        fn read(&self) -> Result<Option<Vec<u8>>, AccountError> {
            Ok(self.bytes.lock().unwrap().clone())
        }
        fn write(&self, b: &[u8]) -> Result<(), AccountError> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(AccountError::Storage);
            }
            *self.bytes.lock().unwrap() = Some(b.to_vec());
            Ok(())
        }
    }
    fn credential() -> Credential {
        Credential::ApiKey {
            token: "secret-sentinel".into(),
            region: None,
            organization: None,
        }
    }
    #[test]
    fn transactions_select_remove_and_rollback() {
        let memory = Arc::new(Memory::default());
        let dir = std::env::temp_dir().join(random_string().unwrap());
        let vault = Vault::new(memory.clone(), dir.join("lock"));
        let mut tx = vault.begin().unwrap();
        let a = tx
            .document
            .add(Provider::Amp, "first", "id1".into(), credential())
            .unwrap();
        assert!(matches!(vault.begin(), Err(AccountError::Busy)));
        assert!(
            tx.document
                .add(Provider::Amp, "first", "id2".into(), credential())
                .is_err()
        );
        let b = tx
            .document
            .add(Provider::Amp, "second", "id2".into(), credential())
            .unwrap();
        tx.commit().unwrap();
        let mut tx = vault.begin().unwrap();
        tx.document.select(&b).unwrap();
        tx.commit().unwrap();
        let mut tx = vault.begin().unwrap();
        assert!(
            tx.document
                .accounts
                .iter()
                .find(|a| a.id == b)
                .unwrap()
                .active
        );
        let visible = serde_json::to_string(
            &tx.document
                .accounts
                .iter()
                .map(|a| a.info())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(!visible.contains("secret-sentinel"));
        tx.document.remove(&b).unwrap();
        memory.fail.store(true, Ordering::SeqCst);
        assert!(tx.commit().is_err());
        memory.fail.store(false, Ordering::SeqCst);
        let mut tx = vault.begin().unwrap();
        assert_eq!(tx.document.accounts.len(), 2);
        tx.document.remove(&b).unwrap();
        tx.commit().unwrap();
        let tx = vault.begin().unwrap();
        assert_eq!(tx.document.accounts[0].id, a);
        assert!(tx.document.accounts[0].active);
        drop(tx);
        std::fs::remove_file(dir.join("lock")).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
