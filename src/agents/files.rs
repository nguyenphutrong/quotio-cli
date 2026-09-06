//! Agent-owned files only. Backups are exclusive and failed multi-file writes roll back.
use super::AgentError;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub struct WriteRequest {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub permissions: Option<u32>,
}
#[derive(Clone)]
pub struct Files {
    pub home: PathBuf,
}
impl Files {
    pub fn path(&self, relative: &str) -> PathBuf {
        self.home.join(relative)
    }
    pub fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, AgentError> {
        self.check(path)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let file = match options.open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(AgentError::Storage),
        };
        if !file.metadata().map_err(|_| AgentError::Storage)?.is_file() {
            return Err(AgentError::UnsafePath);
        }
        let mut bytes = Vec::new();
        file.take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AgentError::Storage)?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(AgentError::TooLarge);
        }
        Ok(Some(bytes))
    }
    fn check(&self, path: &Path) -> Result<(), AgentError> {
        let relative = path
            .strip_prefix(&self.home)
            .map_err(|_| AgentError::UnsafePath)?;
        if relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(AgentError::UnsafePath);
        }
        let mut current = self.home.clone();
        for part in relative.components() {
            current.push(part);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(AgentError::UnsafePath);
                }
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(AgentError::Storage);
                }
                _ => (),
            }
        }
        Ok(())
    }
    fn replace(
        &self,
        path: &Path,
        bytes: &[u8],
        permissions: Option<u32>,
    ) -> Result<(), AgentError> {
        self.check(path)?;
        let parent = path.parent().ok_or(AgentError::UnsafePath)?;
        fs::create_dir_all(parent).map_err(|_| AgentError::Storage)?;
        let temporary = parent.join(format!(
            ".quotio-{}.tmp",
            crate::accounts::random_string().map_err(|_| AgentError::Storage)?
        ));
        let result = (|| -> Result<(), AgentError> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary).map_err(|_| AgentError::Storage)?;
            file.write_all(bytes).map_err(|_| AgentError::Storage)?;
            #[cfg(unix)]
            if let Some(mode) = permissions {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(mode))
                    .map_err(|_| AgentError::Storage)?;
            }
            #[cfg(not(unix))]
            let _ = permissions;
            file.sync_all().map_err(|_| AgentError::Storage)?;
            self.check(path)?;
            fs::rename(&temporary, path).map_err(|_| AgentError::Storage)?;
            File::open(parent)
                .and_then(|d| d.sync_all())
                .map_err(|_| AgentError::Storage)
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
    pub fn apply(&self, writes: &[WriteRequest]) -> Result<Vec<PathBuf>, AgentError> {
        self.apply_with(writes, |_| Ok(()))
    }
    fn apply_with(
        &self,
        writes: &[WriteRequest],
        before: impl Fn(usize) -> Result<(), AgentError>,
    ) -> Result<Vec<PathBuf>, AgentError> {
        let mut originals = Vec::new();
        let mut modes = Vec::new();
        let mut backups = Vec::new();
        let mut unique = std::collections::HashSet::new();
        for write in writes {
            if !unique.insert(&write.path) {
                return Err(AgentError::UnsafePath);
            }
            let original = self.read(&write.path)?;
            if let Some(bytes) = &original {
                backups.push(self.backup(&write.path, bytes)?);
            }
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                fs::metadata(&write.path)
                    .ok()
                    .map(|m| m.permissions().mode())
            };
            #[cfg(not(unix))]
            let mode = None;
            modes.push(mode);
            originals.push(original);
        }
        for (index, write) in writes.iter().enumerate() {
            if let Err(error) = before(index).and_then(|()| {
                self.replace(
                    &write.path,
                    &write.bytes,
                    write.permissions.or(modes[index]),
                )
            }) {
                let mut failed = false;
                for prior_index in (0..=index).rev() {
                    let prior = &writes[prior_index];
                    let result = match &originals[prior_index] {
                        Some(bytes) => self.replace(&prior.path, bytes, modes[prior_index]),
                        None => self.check(&prior.path).and_then(|()| {
                            if prior.path.exists() {
                                fs::remove_file(&prior.path).map_err(|_| AgentError::Rollback)?;
                            }
                            Ok(())
                        }),
                    };
                    failed |= result.is_err();
                }
                if failed {
                    return Err(AgentError::Rollback);
                }
                return Err(error);
            }
        }
        Ok(backups)
    }
    fn backup(&self, path: &Path, bytes: &[u8]) -> Result<PathBuf, AgentError> {
        let mut timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
        loop {
            let backup = PathBuf::from(format!("{}.backup.{timestamp}", path.display()));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            }
            match options.open(&backup) {
                Ok(mut file) => {
                    file.write_all(bytes).map_err(|_| AgentError::Storage)?;
                    file.sync_all().map_err(|_| AgentError::Storage)?;
                    return Ok(backup);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    timestamp += 1;
                }
                Err(_) => return Err(AgentError::Storage),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn files() -> Files {
        let home = std::env::temp_dir().join(format!(
            "quotio-agent-{}",
            crate::accounts::random_string().unwrap()
        ));
        fs::create_dir(&home).unwrap();
        Files { home }
    }
    #[test]
    fn failure_rolls_back_and_same_second_backups_never_overwrite() {
        let files = files();
        let a = files.path("a.json");
        let b = files.path("b.json");
        fs::write(&a, b"original").unwrap();
        let writes = [
            WriteRequest {
                path: a.clone(),
                bytes: b"changed".to_vec(),
                permissions: None,
            },
            WriteRequest {
                path: b.clone(),
                bytes: b"new".to_vec(),
                permissions: None,
            },
        ];
        assert!(
            files
                .apply_with(&writes, |index| if index == 1 {
                    Err(AgentError::Storage)
                } else {
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(fs::read(&a).unwrap(), b"original");
        assert!(!b.exists());
        let first = files.apply(&writes).unwrap();
        let second = files.apply(&writes).unwrap();
        assert_ne!(first[0], second[0]);
        assert_eq!(fs::read(&first[0]).unwrap(), b"original");
        fs::remove_dir_all(files.home).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn refuses_symlink_parents_and_traversal() {
        let other = files();
        let files = files();
        std::os::unix::fs::symlink(&other.home, files.path("linked")).unwrap();
        assert!(files.read(&files.path("linked/file")).is_err());
        assert!(files.read(&files.path("../outside")).is_err());
        assert!(
            files
                .apply(&[WriteRequest {
                    path: files.path("linked/file"),
                    bytes: vec![],
                    permissions: None,
                }])
                .is_err()
        );
        fs::remove_dir_all(files.home).unwrap();
        fs::remove_dir_all(other.home).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn preserves_existing_permissions_and_can_require_private_credentials() {
        use std::os::unix::fs::PermissionsExt;
        let files = files();
        let path = files.path("settings.json");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        files
            .apply(&[WriteRequest {
                path: path.clone(),
                bytes: b"next".to_vec(),
                permissions: None,
            }])
            .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        files
            .apply(&[WriteRequest {
                path: path.clone(),
                bytes: b"secret".to_vec(),
                permissions: Some(0o600),
            }])
            .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(files.home).unwrap();
    }
}
