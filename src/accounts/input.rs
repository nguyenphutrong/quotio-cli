use super::AccountError;
#[cfg(unix)]
struct Input {
    file: std::fs::File,
    flags: libc::c_int,
}
#[cfg(unix)]
impl Input {
    fn new(fd: std::os::fd::RawFd) -> Result<Self, AccountError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let copy = unsafe { libc::dup(fd) };
        if copy < 0 {
            return Err(AccountError::Input);
        }
        let file = unsafe { std::fs::File::from_raw_fd(copy) };
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(AccountError::Input);
        }
        Ok(Self { file, flags })
    }
    async fn read(mut self) -> Result<String, AccountError> {
        use std::io::Read;
        let mut bytes = Vec::new();
        let mut chunk = [0; 1024];
        loop {
            match self.file.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    bytes.extend_from_slice(&chunk[..n]);
                    if bytes.len() > 16384 {
                        return Err(AccountError::Input);
                    }
                    if let Some(end) = bytes.iter().position(|b| *b == b'\n') {
                        bytes.truncate(end);
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(AccountError::Input),
            }
        }
        String::from_utf8(bytes).map_err(|_| AccountError::Input)
    }
}
#[cfg(unix)]
impl Drop for Input {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_SETFL, self.flags) };
    }
}
pub async fn read_stdin() -> Result<String, AccountError> {
    #[cfg(unix)]
    {
        Input::new(libc::STDIN_FILENO)?.read().await
    }
    #[cfg(not(unix))]
    {
        Err(AccountError::Unsupported)
    }
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd};
    #[tokio::test]
    async fn stalled_pipe_is_cancellable_and_flags_are_restored() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read = unsafe { std::fs::File::from_raw_fd(fds[0]) };
        let _write = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        let before = unsafe { libc::fcntl(read.as_raw_fd(), libc::F_GETFL) };
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(40),
            Input::new(read.as_raw_fd()).unwrap().read(),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(
            unsafe { libc::fcntl(read.as_raw_fd(), libc::F_GETFL) },
            before
        );
    }
}
