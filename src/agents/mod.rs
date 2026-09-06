pub mod codex;
pub mod files;
pub mod jsonc;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AgentError {
    #[error("agent configuration storage is unavailable")]
    Storage,
    #[error("unsafe agent configuration path")]
    UnsafePath,
    #[error("agent configuration is too large")]
    TooLarge,
    #[error("agent configuration rollback failed; recover using the retained backup")]
    Rollback,
    #[error("invalid agent configuration")]
    Invalid,
}
