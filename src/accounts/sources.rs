//! Explicit references to Quotio's proxy configuration. No discovery or writes.
use super::{AccountError, Credential};
use serde::{Deserialize, Serialize};

fn enabled_default() -> bool {
    true
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AmpNativeReference {
    pub path: std::path::PathBuf,
    #[serde(default = "enabled_default")]
    pub enabled: bool,
}
impl AmpNativeReference {
    pub fn system() -> Result<Self, AccountError> {
        let path = crate::providers::amp::AmpProvider::default()
            .credential_path
            .ok_or(AccountError::Unsupported)?;
        Ok(Self {
            path,
            enabled: true,
        })
    }
    pub fn identity(&self) -> Result<String, AccountError> {
        if !self.path.is_absolute() {
            return Err(AccountError::Input);
        }
        Ok(crate::cache::fingerprint(&[
            "amp_native",
            self.path.to_str().ok_or(AccountError::Input)?,
        ]))
    }
    pub async fn resolve(&self) -> Result<Resolved, AccountError> {
        self.identity()?;
        if !self.enabled {
            return Err(AccountError::SourceDisabled);
        }
        let path = self.path.clone();
        let token = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::task::spawn_blocking(move || crate::providers::amp::local_key(&path)),
        )
        .await
        .map_err(|_| AccountError::Busy)?
        .map_err(|_| AccountError::Storage)??
        .ok_or(AccountError::NotFound)?;
        Ok(Resolved {
            label: "Local Amp account".into(),
            credential: Credential::ApiKey {
                token,
                region: None,
                organization: None,
            },
        })
    }
}
impl Credential {
    pub async fn resolve_reference(
        &self,
        provider: crate::cli::Provider,
    ) -> Result<Option<Resolved>, AccountError> {
        match self {
            Self::QuotioCustomProvider { source }
                if provider == crate::cli::Provider::Catalog("clinepass") =>
            {
                source.resolve().await.map(Some)
            }
            Self::AmpNative { source } if provider == crate::cli::Provider::Amp => {
                source.resolve().await.map(Some)
            }
            Self::QuotioCustomProvider { .. } | Self::AmpNative { .. } => {
                Err(AccountError::Unsupported)
            }
            _ => Ok(None),
        }
    }
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QuotioDomain {
    Production,
    Development,
}
impl QuotioDomain {
    fn identifier(self) -> &'static str {
        match self {
            Self::Production => "app.bytrong.quotio",
            Self::Development => "app.bytrong.quotio.dev",
        }
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustomProviderReference {
    pub domain: QuotioDomain,
    pub record_id: String,
}
pub struct Resolved {
    pub label: String,
    pub credential: Credential,
}
#[derive(Deserialize)]
struct Record {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "is-enabled")]
    enabled: Option<bool>,
    #[serde(rename = "api-keys")]
    keys: Option<Vec<Key>>,
}
#[derive(Deserialize)]
struct Key {
    #[serde(rename = "api-key")]
    token: String,
}
impl CustomProviderReference {
    pub fn identity(&self) -> Result<String, AccountError> {
        let id = &self.record_id;
        if id.len() != 36
            || !id.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
        {
            return Err(AccountError::Input);
        }
        Ok(crate::cache::fingerprint(&[
            "quotio_custom_provider",
            self.domain.identifier(),
            &id.to_ascii_lowercase(),
        ]))
    }
    fn parse(&self, bytes: &[u8]) -> Result<Resolved, AccountError> {
        self.identity()?;
        if bytes.len() > 1024 * 1024 {
            return Err(AccountError::Corrupt);
        }
        let records: Vec<Record> =
            serde_json::from_slice(bytes).map_err(|_| AccountError::Corrupt)?;
        let mut matching = records
            .iter()
            .filter(|r| r.id.eq_ignore_ascii_case(&self.record_id));
        let record = matching.next().ok_or(AccountError::NotFound)?;
        if matching.next().is_some() {
            return Err(AccountError::Corrupt);
        }
        // Extend only when that provider's source and quota contracts are tested.
        if record.kind != "clinepass" {
            return Err(AccountError::Unsupported);
        }
        if record.enabled == Some(false) {
            return Err(AccountError::SourceDisabled);
        }
        let token = record
            .keys
            .as_deref()
            .unwrap_or_default()
            .first()
            .ok_or(AccountError::Input)?
            .token
            .trim();
        if token.is_empty() || token.len() > 16_384 || token.chars().any(char::is_control) {
            return Err(AccountError::Input);
        }
        Ok(Resolved {
            label: super::validate_label(&record.name)?,
            credential: Credential::CatalogKey {
                token: token.into(),
                settings: Default::default(),
            },
        })
    }
    pub async fn resolve(&self) -> Result<Resolved, AccountError> {
        self.identity()?;
        let source = self.clone();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::task::spawn_blocking(move || source.parse(&read_preferences(source.domain)?)),
        )
        .await
        .map_err(|_| AccountError::Busy)?
        .map_err(|_| AccountError::Storage)?
    }
}
#[cfg(target_os = "macos")]
fn read_preferences(domain: QuotioDomain) -> Result<Vec<u8>, AccountError> {
    read_preferences_domain(domain.identifier())
}
#[cfg(target_os = "macos")]
fn read_preferences_domain(identifier: &str) -> Result<Vec<u8>, AccountError> {
    use core_foundation::{
        base::{CFType, CFTypeRef, TCFType},
        data::CFData,
        string::{CFString, CFStringRef},
    };
    unsafe extern "C" {
        fn CFPreferencesCopyAppValue(key: CFStringRef, application_id: CFStringRef) -> CFTypeRef;
    }
    let key = CFString::new("customProviders");
    let domain = CFString::new(identifier);
    let value = unsafe {
        CFPreferencesCopyAppValue(key.as_concrete_TypeRef(), domain.as_concrete_TypeRef())
    };
    if value.is_null() {
        return Err(AccountError::NotFound);
    }
    let value = unsafe { CFType::wrap_under_create_rule(value) };
    let data = value.downcast::<CFData>().ok_or(AccountError::Corrupt)?;
    if data.len() > 1024 * 1024 {
        return Err(AccountError::Corrupt);
    }
    Ok(data.bytes().to_vec())
}
#[cfg(not(target_os = "macos"))]
fn read_preferences(_: QuotioDomain) -> Result<Vec<u8>, AccountError> {
    Err(AccountError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source() -> CustomProviderReference {
        CustomProviderReference {
            domain: QuotioDomain::Production,
            record_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        }
    }
    fn records() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/quotio-clinepass-custom-providers.json"
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn amp_reference_observes_rotation_disable_and_removal_without_copying_credentials() {
        use crate::accounts::{
            service::{MutationIntent, commit_once, mutation_receipt},
            vault::{Vault, tests::Memory},
        };
        use std::sync::Arc;
        let dir = std::env::temp_dir().join(super::super::random_string().unwrap());
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("secrets.json");
        let mut source = AmpNativeReference {
            path: path.clone(),
            enabled: true,
        };
        std::fs::write(&path, br#"{"apiKey@https://ampcode.com/":"fixture-first"}"#).unwrap();
        let first = source.resolve().await.unwrap().credential;
        let identity = source.identity().unwrap();
        let vault = Vault::new(Arc::new(Memory::default()), dir.join("lock"));
        let intent = MutationIntent::new("native-fixture", identity.clone()).unwrap();
        let copy = source.clone();
        let id = commit_once(vault.clone(), intent.clone(), move |doc| {
            doc.add(
                crate::cli::Provider::Amp,
                "Local Amp",
                identity,
                Credential::AmpNative { source: copy },
            )
        })
        .await
        .unwrap();
        assert_eq!(
            mutation_receipt(vault.clone(), &intent).await.unwrap(),
            Some(id.clone())
        );
        let tx = vault.begin().unwrap();
        assert_eq!(
            tx.document.accounts[0].origin(),
            crate::domain::AccountOrigin::BorrowedNative
        );
        assert!(
            !serde_json::to_string(&tx.document)
                .unwrap()
                .contains("fixture-first")
        );
        drop(tx);
        std::fs::write(
            &path,
            br#"{"apiKey@https://ampcode.com/":"fixture-second"}"#,
        )
        .unwrap();
        assert!(source.resolve().await.unwrap().credential != first);
        let bytes = std::fs::read(&path).unwrap();
        let mut tx = vault.begin().unwrap();
        tx.document.patch(&id, None, None, Some(false)).unwrap();
        tx.commit().unwrap();
        assert!(!vault.begin().unwrap().document.accounts[0].enabled());
        source.enabled = false;
        assert!(matches!(
            source.resolve().await,
            Err(AccountError::SourceDisabled)
        ));
        source.enabled = true;
        assert!(source.resolve().await.is_ok());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        std::fs::remove_file(&path).unwrap();
        assert!(source.resolve().await.is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn amp_registration_cannot_supply_a_path_or_credential() {
        assert!(
            serde_json::from_str::<crate::accounts::api::SourceInput>(r#"{"kind":"amp_native"}"#)
                .is_ok()
        );
        for field in ["path", "token", "owned", "source"] {
            let value = serde_json::json!({"kind":"amp_native",field:"fixture"});
            assert!(serde_json::from_value::<crate::accounts::api::SourceInput>(value).is_err());
        }
    }
    #[test]
    fn reference_preserves_group_identity_and_selects_first_key() {
        let source = source();
        let bytes = serde_json::to_vec(&records()).unwrap();
        let resolved = source.parse(&bytes).unwrap();
        assert_eq!(resolved.label, "Cline group");
        assert!(
            matches!(resolved.credential, Credential::CatalogKey{token,..} if token == "fixture-first")
        );
        assert!(
            !serde_json::to_string(&source)
                .unwrap()
                .contains("fixture-first")
        );
        let mut alias = source.clone();
        alias.record_id = alias.record_id.to_uppercase();
        assert_eq!(source.identity().unwrap(), alias.identity().unwrap());
        alias.domain = QuotioDomain::Development;
        assert_ne!(source.identity().unwrap(), alias.identity().unwrap());
    }
    #[test]
    fn disabled_duplicate_missing_and_wrong_provider_are_rejected() {
        let source = source();
        let mut value = records();
        value[0]["is-enabled"] = false.into();
        assert!(matches!(
            source.parse(&serde_json::to_vec(&value).unwrap()),
            Err(AccountError::SourceDisabled)
        ));
        let row = records()[0].clone();
        assert!(matches!(
            source.parse(&serde_json::to_vec(&vec![&row, &row]).unwrap()),
            Err(AccountError::Corrupt)
        ));
        assert!(matches!(source.parse(b"[]"), Err(AccountError::NotFound)));
        let mut value = records();
        value[0]["type"] = "openai-compatibility".into();
        assert!(matches!(
            source.parse(&serde_json::to_vec(&value).unwrap()),
            Err(AccountError::Unsupported)
        ));
    }
    #[tokio::test]
    async fn reference_receipt_survives_restart_without_downgrading_document() {
        use crate::accounts::{
            service::{MutationIntent, commit_once, mutation_receipt},
            vault::{Backend, Vault, tests::Memory},
        };
        use std::sync::Arc;
        let backend = Arc::new(Memory::default());
        let dir = std::env::temp_dir().join(super::super::random_string().unwrap());
        let vault = Vault::new(backend.clone(), dir.join("lock"));
        let source = source();
        let identity = source.identity().unwrap();
        let intent = MutationIntent::new("source-registration-fixture", identity.clone()).unwrap();
        let id = commit_once(vault.clone(), intent.clone(), move |doc| {
            doc.add(
                crate::cli::Provider::Catalog("clinepass"),
                "Cline group",
                identity,
                Credential::QuotioCustomProvider { source },
            )
        })
        .await
        .unwrap();
        let reopened = Vault::new(backend.clone(), dir.join("lock"));
        assert_eq!(
            mutation_receipt(reopened.clone(), &intent).await.unwrap(),
            Some(id)
        );
        let tx = reopened.begin().unwrap();
        assert_eq!(tx.document.version, 3);
        assert!(matches!(
            tx.document.accounts[0].origin(),
            super::super::AccountOrigin::BorrowedProxy
        ));
        let public = serde_json::to_string(&crate::accounts::api::AccountDto::from(
            &tx.document.accounts[0],
        ))
        .unwrap();
        assert!(!public.contains("credential"));
        drop(tx);
        let bytes = backend.read().unwrap().unwrap();
        let mut old: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        old["version"] = 2.into();
        backend.write(&serde_json::to_vec(&old).unwrap()).unwrap();
        assert!(matches!(reopened.begin(), Err(AccountError::Corrupt)));
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn registration_cannot_supply_credentials_paths_or_ownership() {
        let base = serde_json::json!({"kind":"quotio_custom_provider", "source":{"domain":"production","record_id":source().record_id}});
        assert!(serde_json::from_value::<crate::accounts::api::SourceInput>(base.clone()).is_ok());
        for name in ["credential", "api_key", "path", "owned", "origin"] {
            let mut value = base.clone();
            value[name] = "fixture".into();
            assert!(serde_json::from_value::<crate::accounts::api::SourceInput>(value).is_err());
        }
        let mut value = base;
        value["source"]["domain"] = "com.other.application".into();
        assert!(serde_json::from_value::<crate::accounts::api::SourceInput>(value).is_err());
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn preference_fixture_writer() {
        use core_foundation::{
            base::TCFType,
            data::CFData,
            string::{CFString, CFStringRef},
        };
        unsafe extern "C" {
            fn CFPreferencesSetAppValue(
                key: CFStringRef,
                value: core_foundation::base::CFTypeRef,
                application: CFStringRef,
            );
            fn CFPreferencesAppSynchronize(application: CFStringRef) -> u8;
        }
        let Ok(domain) = std::env::var("QUOTIO_TEST_PREFERENCE_DOMAIN") else {
            return;
        };
        assert!(domain.starts_with("app.quotio.cli.fixture."));
        assert!(
            domain
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
        );
        let mode = std::env::var("QUOTIO_TEST_PREFERENCE_VALUE").unwrap();
        let value = CFData::from_buffer(mode.as_bytes());
        let domain = CFString::new(&domain);
        let key = CFString::new("customProviders");
        unsafe {
            CFPreferencesSetAppValue(
                key.as_concrete_TypeRef(),
                if mode == "clear" {
                    std::ptr::null()
                } else {
                    value.as_CFTypeRef()
                },
                domain.as_concrete_TypeRef(),
            );
            assert_ne!(CFPreferencesAppSynchronize(domain.as_concrete_TypeRef()), 0);
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn native_preferences_observe_changes_from_another_process() {
        let domain = format!(
            "app.quotio.cli.fixture.{}",
            super::super::random_string().unwrap()
        );
        let write = |mode| {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "accounts::sources::tests::preference_fixture_writer",
                ])
                .env("QUOTIO_TEST_PREFERENCE_DOMAIN", &domain)
                .env("QUOTIO_TEST_PREFERENCE_VALUE", mode)
                .output()
                .unwrap();
            assert!(result.status.success());
        };
        write("first-fixture");
        let first = read_preferences_domain(&domain);
        write("second-fixture");
        let second = read_preferences_domain(&domain);
        write("clear");
        assert_eq!(first.unwrap(), b"first-fixture");
        assert_eq!(second.unwrap(), b"second-fixture");
    }
}
