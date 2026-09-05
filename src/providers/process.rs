use crate::error::ProviderError;
use std::{path::Path, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt},
    process::{Child, Command},
};
pub(crate) const MAX_BYTES: usize = 1024 * 1024;

pub(crate) fn spawn(program: &Path, args: &[&str]) -> Result<Child, ProviderError> {
    Command::new(program)
        .args(args)
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
