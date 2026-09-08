// Frozen document model from ca61f34^ and vault validation from a5af655.
// Keep the old reader independent of the current Document and version bounds.
use crate::accounts::{Account, AccountError, Credential, MutationReceipt};
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize)]
pub struct Document {
    pub version: u8,
    pub accounts: Vec<Account>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub mutation_receipts: std::collections::BTreeMap<String, MutationReceipt>,
}

pub fn read(bytes: &[u8]) -> Result<Document, AccountError> {
    let doc: Document = serde_json::from_slice(bytes).map_err(|_| AccountError::Corrupt)?;
    if !matches!(doc.version, 1..=4)
        || (doc.version == 1 && !doc.mutation_receipts.is_empty())
        || (doc.version < 3
            && doc.accounts.iter().any(|a| {
                matches!(
                    a.credential,
                    Credential::QuotioCustomProvider { .. }
                        | Credential::AmpNative { .. }
                        | Credential::CodexNative { .. }
                        | Credential::ClaudeNative { .. }
                        | Credential::CopilotNative { .. }
                        | Credential::CursorNative { .. }
                        | Credential::GrokNative { .. }
                        | Credential::DevinDesktopNative { .. }
                        | Credential::FactoryNative { .. }
                )
            }))
        || (doc.version < 4 && doc.accounts.iter().any(|a| !a.enabled))
        || doc.mutation_receipts.len() > 4096
    {
        return Err(AccountError::Corrupt);
    }
    Ok(doc)
}
