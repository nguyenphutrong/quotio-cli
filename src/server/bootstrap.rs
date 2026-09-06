//! Private inherited-pipe protocol for a native parent, independent of CLI text.
use super::ServerError;
use std::{io::Write, net::SocketAddr, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt};

pub struct Parent {
    token: String,
    #[cfg(unix)]
    input: tokio::net::unix::pipe::Receiver,
}
impl Parent {
    pub async fn open() -> Result<Self, ServerError> {
        // Do not silently select between two credentials.
        if std::env::var_os("QUOTIO_SERVER_TOKEN").is_some() {
            return Err(ServerError::Security);
        }
        #[cfg(unix)]
        {
            use std::os::fd::{FromRawFd, OwnedFd};
            // Own only a duplicate; never close the application's original stdin.
            let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                return Err(ServerError::Initialize);
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let mut input = tokio::net::unix::pipe::Receiver::from_owned_fd(fd)
                .map_err(|_| ServerError::Initialize)?;
            let token = tokio::time::timeout(Duration::from_secs(5), read_token(&mut input))
                .await
                .map_err(|_| ServerError::Security)??;
            Ok(Self { token, input })
        }
        #[cfg(not(unix))]
        Err(ServerError::Initialize)
    }
    pub fn take_token(&mut self) -> String {
        std::mem::take(&mut self.token)
    }
    pub async fn closed(&mut self) {
        #[cfg(unix)]
        {
            // EOF, read failure, or unexpected extra input ends the parent session.
            let _ = self.input.read_u8().await;
        }
    }
}
async fn read_token(input: &mut (impl AsyncRead + Unpin)) -> Result<String, ServerError> {
    let mut bytes = Vec::with_capacity(64);
    loop {
        let byte = input.read_u8().await.map_err(|_| ServerError::Security)?;
        if byte == b'\n' {
            if bytes.len() < 32 {
                return Err(ServerError::Security);
            }
            return String::from_utf8(bytes).map_err(|_| ServerError::Security);
        }
        if !byte.is_ascii_graphic() || bytes.len() == 4096 {
            return Err(ServerError::Security);
        }
        bytes.push(byte);
    }
}
pub fn announce(address: SocketAddr) -> Result<(), ServerError> {
    let record = serde_json::json!({
        "bootstrap_version": 1,
        "api_version": 1,
        "server_version": env!("CARGO_PKG_VERSION"),
        "pid": std::process::id(),
        "host": address.ip().to_string(),
        "port": address.port(),
    });
    let mut output = std::io::stdout().lock();
    writeln!(output, "{record}").map_err(|_| ServerError::Initialize)?;
    output.flush().map_err(|_| ServerError::Initialize)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn token_is_bounded_and_requires_a_complete_visible_ascii_line() {
        for value in [
            "short\n".to_string(),
            "x".repeat(4097) + "\n",
            "x".repeat(32) + "\r\n",
            "x".repeat(32),
            "x".repeat(32) + " \n",
        ] {
            assert!(read_token(&mut value.as_bytes()).await.is_err());
        }
        let value = "x".repeat(4096) + "\n";
        assert_eq!(read_token(&mut value.as_bytes()).await.unwrap().len(), 4096);
    }
}
