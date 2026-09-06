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
pub struct Keychain {
    #[cfg(target_os = "macos")]
    interactive: bool,
}
#[cfg(target_os = "macos")]
impl Keychain {
    fn options(&self) -> security_framework::passwords::PasswordOptions {
        let mut options = security_framework::passwords::PasswordOptions::new_generic_password(
            "app.quotio.cli.accounts.v1",
            "vault",
        );
        if !self.interactive {
            use core_foundation::{base::TCFType, string::CFString};
            use security_framework_sys::item::kSecUseAuthenticationUI;
            // This public Security.framework constant is absent from the pinned sys bindings.
            unsafe extern "C" {
                static kSecUseAuthenticationUIFail: core_foundation::string::CFStringRef;
            }
            // The pinned wrapper exposes no setter for this per-query native option.
            #[allow(deprecated)]
            unsafe {
                options.query.push((
                    CFString::wrap_under_get_rule(kSecUseAuthenticationUI),
                    CFString::wrap_under_get_rule(kSecUseAuthenticationUIFail).into_CFType(),
                ));
            }
        }
        options
    }
}
impl Backend for Keychain {
    fn read(&self) -> Result<Option<Vec<u8>>, AccountError> {
        #[cfg(target_os = "macos")]
        {
            match security_framework::passwords::generic_password(self.options()) {
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
            security_framework::passwords::set_generic_password_options(bytes, self.options())
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
        Self::system_with_interaction(true)
    }
    pub fn for_usage() -> Result<Self, AccountError> {
        Self::system_with_interaction(false)
    }
    fn system_with_interaction(_interactive: bool) -> Result<Self, AccountError> {
        let dirs = directories::ProjectDirs::from("", "", "quotio").ok_or(AccountError::Storage)?;
        Ok(Self::new(
            Arc::new(Keychain {
                #[cfg(target_os = "macos")]
                interactive: _interactive,
            }),
            dirs.data_local_dir().join("accounts.lock"),
        ))
    }
    pub fn new(backend: Arc<dyn Backend>, lock_path: PathBuf) -> Self {
        Self { backend, lock_path }
    }
    pub fn refresh_lock(&self, id: &str) -> Result<File, AccountError> {
        if id.is_empty()
            || id.len() > 80
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(AccountError::Corrupt);
        }
        acquire(&self.lock_path.with_file_name(format!("refresh-{id}.lock")))
    }
    pub fn begin(&self) -> Result<Transaction, AccountError> {
        let lock = acquire(&self.lock_path)?;
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
fn acquire(path: &std::path::Path) -> Result<File, AccountError> {
    let parent = path.parent().ok_or(AccountError::Storage)?;
    std::fs::create_dir_all(parent).map_err(|_| AccountError::Storage)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let lock = options.open(path).map_err(|_| AccountError::Storage)?;
    if !lock
        .metadata()
        .map_err(|_| AccountError::Storage)?
        .is_file()
    {
        return Err(AccountError::Storage);
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // Keep the descriptor alive until the protected operation completes.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(AccountError::Busy);
        }
    }
    #[cfg(not(unix))]
    {
        return Err(AccountError::Unsupported);
    }
    Ok(lock)
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
    #[cfg(target_os = "macos")]
    #[test]
    fn usage_keychain_queries_fail_instead_of_prompting() {
        use core_foundation::{base::TCFType, string::CFString};
        use security_framework_sys::item::kSecUseAuthenticationUI;
        unsafe extern "C" {
            static kSecUseAuthenticationUIFail: core_foundation::string::CFStringRef;
        }
        let key = unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationUI) };
        let fail =
            unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationUIFail).into_CFType() };
        #[allow(deprecated)]
        let noninteractive = Keychain { interactive: false }.options().query;
        #[allow(deprecated)]
        let interactive = Keychain { interactive: true }.options().query;
        assert!(noninteractive.iter().any(|(k, v)| k == &key && v == &fail));
        assert!(!interactive.iter().any(|(k, _)| k == &key));
    }
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "explicit native Keychain smoke; synthetic isolated item only"]
    fn native_keychain_round_trip() {
        use security_framework::passwords::{
            delete_generic_password, get_generic_password, set_generic_password,
        };
        let service = format!("app.quotio.cli.verification.{}", random_string().unwrap());
        assert!(get_generic_password(&service, "test").is_err());
        set_generic_password(&service, "test", b"synthetic-first").unwrap();
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = delete_generic_password(&self.0, "test");
            }
        }
        let _cleanup = Cleanup(service.clone());
        assert_eq!(
            get_generic_password(&service, "test").unwrap(),
            b"synthetic-first"
        );
        set_generic_password(&service, "test", b"synthetic-updated").unwrap();
        assert_eq!(
            get_generic_password(&service, "test").unwrap(),
            b"synthetic-updated"
        );
        delete_generic_password(&service, "test").unwrap();
        assert!(get_generic_password(&service, "test").is_err());
    }
}
