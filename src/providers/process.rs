use crate::error::ProviderError;
use std::{path::Path, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::{Child, Command},
};
pub(crate) const MAX_BYTES: usize = 1024 * 1024;

pub(crate) fn spawn(program: &Path, args: &[&str]) -> Result<Child, ProviderError> {
    Command::new(program)
        .args(args)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| ProviderError::Unavailable)
}
pub(crate) async fn line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, ProviderError> {
    let mut buffer = Vec::new();
    reader
        .take((MAX_BYTES + 1) as u64)
        .read_until(b'\n', &mut buffer)
        .await
        .map_err(|_| ProviderError::InvalidData)?;
    if buffer.is_empty() || buffer.len() > MAX_BYTES {
        return Err(ProviderError::InvalidData);
    }
    Ok(buffer)
}
pub(crate) async fn output(program: &Path, args: &[&str]) -> Result<Vec<u8>, ProviderError> {
    let mut child = spawn(program, args)?;
    drop(child.stdin.take());
    let stdout = child.stdout.take().ok_or(ProviderError::Internal)?;
    let mut bytes = Vec::new();
    BufReader::new(stdout)
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| ProviderError::InvalidData)?;
    if bytes.len() > MAX_BYTES {
        return Err(ProviderError::InvalidData);
    }
    if !child
        .wait()
        .await
        .map_err(|_| ProviderError::Unavailable)?
        .success()
    {
        return Err(ProviderError::Unavailable);
    }
    Ok(bytes)
}
