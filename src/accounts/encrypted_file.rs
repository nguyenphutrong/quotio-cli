//! Headless account storage. The master key is supplied separately from ciphertext.
use super::{AccountError, vault::Backend};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const HEADER: &[u8] = b"quotio-vault\0\x01";
const MAX_DOCUMENT: usize = 1024 * 1024;

pub struct EncryptedFile {
    path: PathBuf,
    key: aead::LessSafeKey,
}

fn private_file(path: &Path) -> Result<File, AccountError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| AccountError::Storage)?;
    let meta = file.metadata().map_err(|_| AccountError::Storage)?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.permissions().mode() & 0o077 != 0
        || meta.nlink() != 1
    {
        return Err(AccountError::Storage);
    }
    Ok(file)
}

fn read_key(file: File) -> Result<[u8; 32], AccountError> {
    let mut bytes = Vec::new();
    file.take(33)
        .read_to_end(&mut bytes)
        .map_err(|_| AccountError::Storage)?;
    bytes.try_into().map_err(|_| AccountError::Storage)
}

#[cfg(any(target_os = "linux", test))]
fn read_descriptor(file: File, timeout: std::time::Duration) -> Result<[u8; 32], AccountError> {
    use std::os::fd::AsRawFd;
    let deadline = std::time::Instant::now() + timeout;
    let mut bytes = [0u8; 33];
    let mut count = 0;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(AccountError::Storage);
        }
        let mut poll = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe {
            libc::poll(
                &mut poll,
                1,
                remaining.as_millis().min(i32::MAX as u128) as i32,
            )
        } <= 0
        {
            return Err(AccountError::Storage);
        }
        let read = unsafe {
            libc::read(
                file.as_raw_fd(),
                bytes[count..].as_mut_ptr().cast(),
                bytes.len() - count,
            )
        };
        if read < 0 {
            return Err(AccountError::Storage);
        }
        if read == 0 {
            return bytes[..count].try_into().map_err(|_| AccountError::Storage);
        }
        count += read as usize;
        if count == bytes.len() {
            return Err(AccountError::Storage);
        }
    }
}

impl EncryptedFile {
    pub fn from_key_file(path: PathBuf, key_path: &Path) -> Result<Self, AccountError> {
        let parent = path.parent().ok_or(AccountError::Storage)?;
        // Resolve the directory before comparison so alternate spellings cannot
        // place the master key alongside its ciphertext.
        let parent = std::fs::canonicalize(parent).map_err(|_| AccountError::Storage)?;
        let canonical_key = std::fs::canonicalize(key_path).map_err(|_| AccountError::Storage)?;
        if canonical_key.starts_with(&parent) {
            return Err(AccountError::Storage);
        }
        Self::new(path, read_key(private_file(key_path)?)?)
    }

    fn new(path: PathBuf, key: [u8; 32]) -> Result<Self, AccountError> {
        let key =
            aead::UnboundKey::new(&aead::AES_256_GCM, &key).map_err(|_| AccountError::Storage)?;
        Ok(Self {
            path,
            key: aead::LessSafeKey::new(key),
        })
    }

    #[cfg(target_os = "linux")]
    pub fn from_environment(directory: &Path) -> Result<Self, AccountError> {
        use std::os::fd::FromRawFd;
        let key_file = std::env::var_os("QUOTIO_VAULT_KEY_FILE");
        let key_fd = std::env::var_os("QUOTIO_VAULT_KEY_FD");
        if key_file.is_some() == key_fd.is_some() {
            return Err(AccountError::Storage);
        }
        let mut builder = std::fs::DirBuilder::new();
        use std::os::unix::fs::DirBuilderExt;
        builder
            .recursive(true)
            .mode(0o700)
            .create(directory)
            .map_err(|_| AccountError::Storage)?;
        let meta = std::fs::symlink_metadata(directory).map_err(|_| AccountError::Storage)?;
        if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err(AccountError::Storage);
        }
        let path = directory.join("accounts.enc");
        if let Some(key_file) = key_file {
            return Self::from_key_file(path, Path::new(&key_file));
        }
        let fd: i32 = key_fd
            .and_then(|s| s.into_string().ok())
            .and_then(|s| s.parse().ok())
            .filter(|fd| *fd >= 3)
            .ok_or(AccountError::Storage)?;
        // Consume an inherited descriptor once. Subsequent vault instances share
        // the same key, including when the descriptor was a pipe.
        static KEY: std::sync::OnceLock<Result<(i32, [u8; 32]), ()>> = std::sync::OnceLock::new();
        let (original_fd, key) = KEY
            .get_or_init(|| {
                if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                    return Err(());
                }
                let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
                if duplicate < 0 {
                    return Err(());
                }
                let file = unsafe { File::from_raw_fd(duplicate) };
                let meta = file.metadata().map_err(|_| ())?;
                use std::os::unix::fs::FileTypeExt;
                if meta.is_file() {
                    if meta.uid() != unsafe { libc::geteuid() }
                        || meta.mode() & 0o077 != 0
                        || meta.nlink() != 1
                    {
                        return Err(());
                    }
                    let source =
                        std::fs::read_link(format!("/proc/self/fd/{duplicate}")).map_err(|_| ())?;
                    let directory = std::fs::canonicalize(directory).map_err(|_| ())?;
                    if source.starts_with(directory) {
                        return Err(());
                    }
                } else if !meta.file_type().is_fifo() {
                    return Err(());
                }
                read_descriptor(file, std::time::Duration::from_secs(5))
                    .map(|key| (fd, key))
                    .map_err(|_| ())
            })
            .as_ref()
            .map_err(|_| AccountError::Storage)?;
        if *original_fd != fd {
            return Err(AccountError::Storage);
        }
        Self::new(path, *key)
    }
}

impl Backend for EncryptedFile {
    fn read(&self) -> Result<Option<Vec<u8>>, AccountError> {
        match std::fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(AccountError::Storage),
            Ok(_) => {}
        }
        let mut bytes = Vec::new();
        private_file(&self.path)?
            .take((MAX_DOCUMENT + 128) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| AccountError::Storage)?;
        if bytes.len() < HEADER.len() + 12 + aead::AES_256_GCM.tag_len()
            || bytes.len() > MAX_DOCUMENT + HEADER.len() + 12 + aead::AES_256_GCM.tag_len()
            || !bytes.starts_with(HEADER)
        {
            return Err(AccountError::Corrupt);
        }
        let nonce: [u8; 12] = bytes[HEADER.len()..HEADER.len() + 12].try_into().unwrap();
        let plaintext = self
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(HEADER),
                &mut bytes[HEADER.len() + 12..],
            )
            .map_err(|_| AccountError::Corrupt)?;
        Ok(Some(plaintext.to_vec()))
    }

    fn write(&self, bytes: &[u8]) -> Result<(), AccountError> {
        if bytes.len() > MAX_DOCUMENT {
            return Err(AccountError::Input);
        }
        // A wrong key or corrupt existing vault must never be overwritten.
        self.read()?;
        let mut nonce = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| AccountError::Storage)?;
        let mut ciphertext = bytes.to_vec();
        self.key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(HEADER),
                &mut ciphertext,
            )
            .map_err(|_| AccountError::Storage)?;
        let temp = self
            .path
            .with_extension(format!("{}.tmp", super::random_string()?));
        let result: std::io::Result<()> = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temp)?;
            file.write_all(HEADER)?;
            file.write_all(&nonce)?;
            file.write_all(&ciphertext)?;
            file.sync_all()?;
            std::fs::rename(&temp, &self.path)?;
            File::open(self.path.parent().unwrap())?.sync_all()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temp);
        }
        result.map_err(|_| AccountError::Storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "quotio-encrypted-{}",
                super::super::random_string().unwrap()
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
        fn vault(&self, key: u8) -> EncryptedFile {
            EncryptedFile::new(self.0.join("accounts.enc"), [key; 32]).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn inherited_pipe_requires_exact_key_and_eof_within_deadline() {
        use std::os::fd::FromRawFd;
        for length in [0, 31, 32, 33] {
            let mut fds = [0; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            let reader = unsafe { File::from_raw_fd(fds[0]) };
            let mut writer = unsafe { File::from_raw_fd(fds[1]) };
            writer.write_all(&vec![1; length]).unwrap();
            drop(writer);
            assert_eq!(
                read_descriptor(reader, std::time::Duration::from_millis(100)).is_ok(),
                length == 32
            );
        }
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let reader = unsafe { File::from_raw_fd(fds[0]) };
        let mut writer = unsafe { File::from_raw_fd(fds[1]) };
        writer.write_all(&[1]).unwrap();
        assert!(read_descriptor(reader, std::time::Duration::from_millis(30)).is_err());
    }
    #[test]
    fn vault_transactions_preserve_accounts_and_exclude_concurrent_writer() {
        use super::super::{Credential, vault::Vault};
        use std::sync::Arc;
        let f = Fixture::new();
        let vault = Vault::new(Arc::new(f.vault(1)), f.0.join("accounts.lock"));
        let mut transaction = vault.begin().unwrap();
        assert!(matches!(vault.begin(), Err(AccountError::Busy)));
        let id = transaction
            .document
            .add(
                crate::cli::Provider::Amp,
                "fixture",
                "identity".into(),
                Credential::ApiKey {
                    token: "fixture-only".into(),
                    region: None,
                    organization: None,
                },
            )
            .unwrap();
        transaction.commit().unwrap();
        let restarted = Vault::new(Arc::new(f.vault(1)), f.0.join("accounts.lock"));
        assert_eq!(restarted.begin().unwrap().document.accounts[0].id, id);
    }
    #[test]
    fn roundtrip_restart_and_fresh_nonce() {
        let f = Fixture::new();
        let vault = f.vault(1);
        assert!(vault.read().unwrap().is_none());
        vault.write(b"private fixture").unwrap();
        let first = std::fs::read(&vault.path).unwrap();
        assert!(!first.windows(15).any(|w| w == b"private fixture"));
        assert_eq!(f.vault(1).read().unwrap().unwrap(), b"private fixture");
        vault.write(b"private fixture").unwrap();
        assert_ne!(first, std::fs::read(&vault.path).unwrap());
    }
    #[test]
    fn wrong_key_and_tamper_preserve_existing_file() {
        let f = Fixture::new();
        let vault = f.vault(1);
        vault.write(b"fixture").unwrap();
        let original = std::fs::read(&vault.path).unwrap();
        assert!(f.vault(2).read().is_err());
        assert!(f.vault(2).write(b"replacement").is_err());
        assert_eq!(original, std::fs::read(&vault.path).unwrap());
        let mut damaged = original;
        *damaged.last_mut().unwrap() ^= 1;
        std::fs::write(&vault.path, &damaged).unwrap();
        assert!(vault.read().is_err());
        assert!(vault.write(b"replacement").is_err());
        assert_eq!(damaged, std::fs::read(&vault.path).unwrap());
    }
    #[test]
    fn rejects_public_files_and_symlinks() {
        let f = Fixture::new();
        let vault = f.vault(1);
        vault.write(b"fixture").unwrap();
        std::fs::set_permissions(&vault.path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(vault.read().is_err());
        let target = f.0.join("target");
        std::fs::rename(&vault.path, &target).unwrap();
        std::os::unix::fs::symlink(&target, &vault.path).unwrap();
        assert!(vault.read().is_err());
        assert!(vault.write(b"replacement").is_err());
    }
    #[test]
    fn master_key_must_be_private_and_outside_vault_directory() {
        let f = Fixture::new();
        let key_path = f.0.join("key");
        std::fs::write(&key_path, [1; 32]).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(EncryptedFile::from_key_file(f.0.join("accounts.enc"), &key_path).is_err());
        let storage = f.0.join("storage");
        std::fs::create_dir(&storage).unwrap();
        assert!(EncryptedFile::from_key_file(storage.join("accounts.enc"), &key_path).is_ok());
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(EncryptedFile::from_key_file(storage.join("accounts.enc"), &key_path).is_err());
    }
}
