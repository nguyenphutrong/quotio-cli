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
#[cfg(unix)]
struct HiddenEcho {
    file: std::fs::File,
    original: libc::termios,
}
#[cfg(unix)]
impl HiddenEcho {
    fn new(file: &std::fs::File) -> Result<Self, AccountError> {
        use std::os::fd::AsRawFd;
        let file = file.try_clone().map_err(|_| AccountError::Input)?;
        let fd = file.as_raw_fd();
        let mut original = std::mem::MaybeUninit::uninit();
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return Err(AccountError::Input);
        }
        let original = unsafe { original.assume_init() };
        let mut hidden = original;
        hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
        // Keep Ctrl-C active, but prevent job-control suspension from leaving
        // the user's terminal with echo disabled while this prompt is paused.
        hidden.c_cc[libc::VSUSP] = libc::_POSIX_VDISABLE as libc::cc_t;
        hidden.c_cc[libc::VQUIT] = libc::_POSIX_VDISABLE as libc::cc_t;
        #[cfg(target_os = "macos")]
        {
            hidden.c_cc[libc::VDSUSP] = libc::_POSIX_VDISABLE as libc::cc_t;
        }
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &hidden) } != 0 {
            return Err(AccountError::Input);
        }
        Ok(Self { file, original })
    }
}
#[cfg(unix)]
impl Drop for HiddenEcho {
    fn drop(&mut self) {
        use std::{io::Write, os::fd::AsRawFd};
        // Flush unread pasted input before returning control to the shell.
        unsafe { libc::tcsetattr(self.file.as_raw_fd(), libc::TCSAFLUSH, &self.original) };
        let _ = writeln!(std::io::stderr());
    }
}
#[cfg(unix)]
async fn read_hidden(fd: std::os::fd::RawFd, provider: &str) -> Result<String, AccountError> {
    use std::io::Write;
    let input = Input::new(fd)?;
    let _echo = HiddenEcho::new(&input.file)?;
    let mut stderr = std::io::stderr();
    write!(stderr, "{provider} API key (hidden): ")
        .and_then(|_| stderr.flush())
        .map_err(|_| AccountError::Input)?;
    input.read().await
}

pub async fn read_api_key(provider: &str, token_stdin: bool) -> Result<String, AccountError> {
    use std::io::IsTerminal;
    match (token_stdin, std::io::stdin().is_terminal()) {
        (true, false) => read_stdin().await,
        (false, true) => {
            #[cfg(unix)]
            {
                read_hidden(libc::STDIN_FILENO, provider).await
            }
            #[cfg(not(unix))]
            {
                let _ = provider;
                Err(AccountError::Unsupported)
            }
        }
        _ => Err(AccountError::InputMode),
    }
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd};
    #[tokio::test]
    async fn hidden_prompt_timeout_restores_terminal_state() {
        let mut fds = [-1; 2];
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut fds[0],
                    &mut fds[1],
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let _master = unsafe { std::fs::File::from_raw_fd(fds[0]) };
        let slave = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        for fd in fds {
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
                0
            );
        }
        let mut before = std::mem::MaybeUninit::uninit();
        assert_eq!(
            unsafe { libc::tcgetattr(slave.as_raw_fd(), before.as_mut_ptr()) },
            0
        );
        let before = unsafe { before.assume_init() };
        let flags = unsafe { libc::fcntl(slave.as_raw_fd(), libc::F_GETFL) };
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(40),
                read_hidden(slave.as_raw_fd(), "Test")
            )
            .await
            .is_err()
        );
        let mut after = std::mem::MaybeUninit::uninit();
        assert_eq!(
            unsafe { libc::tcgetattr(slave.as_raw_fd(), after.as_mut_ptr()) },
            0
        );
        let after = unsafe { after.assume_init() };
        assert_eq!(before.c_lflag, after.c_lflag);
        assert_eq!(before.c_cc, after.c_cc);
        assert_eq!(
            unsafe { libc::fcntl(slave.as_raw_fd(), libc::F_GETFL) },
            flags
        );
    }
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
