use clap::Parser;
use quotio::{
    cli::{Cli, Command as CliCommand},
    config::Config,
};
use std::{
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct ConfigFile(PathBuf);
impl ConfigFile {
    fn new(contents: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "quotio-test-{}-{}.toml",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).unwrap();
        Self(path)
    }
}
impl Drop for ConfigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn run(args: &[&str], config: &ConfigFile) -> Output {
    Command::new(env!("CARGO_BIN_EXE_quotio"))
        .args(args)
        .arg("--no-saved-accounts")
        .arg("--config")
        .arg(&config.0)
        .output()
        .unwrap()
}
#[test]
fn argument_contract() {
    let parsed = Cli::try_parse_from([
        "quotio",
        "usage",
        "--provider",
        "mock",
        "--provider",
        "mock",
        "--format",
        "json",
        "--timeout",
        "1",
        "--no-color",
        "--verbose",
    ])
    .unwrap();
    let CliCommand::Usage(args) = parsed.command else {
        panic!()
    };
    assert_eq!(args.provider.len(), 2);
    for value in ["0", "3601", "NaN", "-1"] {
        assert!(Cli::try_parse_from(["quotio", "usage", "--timeout", value]).is_err());
    }
    assert!(Cli::try_parse_from(["quotio", "usage", "--provider", "unknown"]).is_err());
}
#[test]
fn json_contract_and_deduplication() {
    let config = ConfigFile::new("enabled_providers = []");
    let result = run(
        &[
            "usage",
            "--provider",
            "mock",
            "--provider",
            "mock",
            "--format",
            "json",
            "--verbose",
        ],
        &config,
    );
    assert_eq!(result.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 4);
    assert_eq!(value["schema_version"], 1);
    time::OffsetDateTime::parse(
        value["generated_at"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert_eq!(value["providers"].as_array().unwrap().len(), 1);
    let provider = &value["providers"][0];
    assert_eq!(provider["provider"], "mock");
    assert_eq!(
        provider["account"],
        serde_json::json!({"id":"mock-account", "label":"Demo account"})
    );
    let windows = &provider["windows"];
    assert_eq!(windows.as_array().unwrap().len(), 3);
    assert_eq!(
        windows[0]["quota"],
        serde_json::json!({"state":"available", "used_percent":25.0, "remaining_percent":75.0})
    );
    assert_eq!(windows[1]["quota"]["state"], "exhausted");
    assert_eq!(windows[2]["quota"], serde_json::json!({"state":"unknown"}));
    assert!(windows[2]["resets_at"].is_null());
    assert_eq!(windows[0]["provenance"]["source"], "mock_fixture");
    assert_eq!(windows[0]["fetched_at"], "2026-01-01T00:00:00Z");
    assert!(value["failures"].as_array().unwrap().is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("collecting provider usage"));
}
#[test]
fn text_and_config_selection() {
    let config = ConfigFile::new("enabled_providers = [\"mock\"]");
    let result = run(&["usage", "--no-color"], &config);
    assert_eq!(result.status.code(), Some(0));
    assert!(result.stderr.is_empty());
    let text = String::from_utf8(result.stdout).unwrap();
    for expected in [
        "mock | Demo account",
        "remaining 75.0%",
        "exhausted",
        "usage unknown",
        "reset",
        "mock_fixture",
        "fetched",
    ] {
        assert!(text.contains(expected), "{expected}");
    }
    assert!(!text.contains('\x1b'));
}
#[test]
fn empty_and_invalid_config_exit_codes_and_redaction() {
    let empty = ConfigFile::new("enabled_providers = []");
    let result = run(&["usage", "--format", "json"], &empty);
    assert_eq!(result.status.code(), Some(3));
    assert!(serde_json::from_slice::<serde_json::Value>(&result.stdout).is_ok());
    for input in [
        "token = 'secret-sentinel'",
        "enabled_providers = ['secret-sentinel']",
        "enabled_providers = secret-sentinel",
    ] {
        let config = ConfigFile::new(input);
        let result = run(&["usage"], &config);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("secret-sentinel"));
    }
    let result = run(&["usage", "--provider", "secret-sentinel"], &empty);
    assert_eq!(result.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("secret-sentinel"));
}
#[test]
fn missing_config_and_help() {
    assert!(
        Config::load(Some(std::path::Path::new(
            "/nonexistent/quotio/config.toml"
        )))
        .is_err()
    );
    for args in [vec!["--help"], vec!["usage", "--help"], vec!["providers"]] {
        let result = Command::new(env!("CARGO_BIN_EXE_quotio"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(0));
        assert!(!result.stdout.is_empty());
        assert!(result.stderr.is_empty());
    }
}

#[test]
fn real_provider_selection_and_mixed_missing_auth() {
    use quotio::cli::Provider;
    let configured =
        Config::parse("enabled_providers = ['codex','amp','antigravity','droid','factory']")
            .unwrap()
            .providers()
            .unwrap();
    assert_eq!(
        configured,
        vec![
            Provider::Codex,
            Provider::Amp,
            Provider::Antigravity,
            Provider::Factory
        ]
    );
    let config = ConfigFile::new("enabled_providers = []");
    let output = Command::new(env!("CARGO_BIN_EXE_quotio"))
        .args([
            "usage",
            "--provider",
            "mock",
            "--provider",
            "factory",
            "--no-saved-accounts",
            "--format",
            "json",
            "--verbose",
            "--config",
        ])
        .arg(&config.0)
        .env_remove("FACTORY_API_KEY")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["providers"][0]["provider"], "mock");
    assert_eq!(value["failures"][0]["provider"], "factory");
    assert_eq!(value["failures"][0]["code"], "authentication");
}

#[test]
fn account_commands_are_explicit_and_help_exposes_no_secret_argument() {
    for args in [
        vec![
            "quotio",
            "accounts",
            "add",
            "--provider",
            "codex",
            "--label",
            "Personal",
        ],
        vec![
            "quotio",
            "accounts",
            "add",
            "--provider",
            "amp",
            "--label",
            "Work",
            "--token-stdin",
        ],
        vec!["quotio", "accounts", "list", "--format", "json"],
        vec!["quotio", "accounts", "use", "id"],
        vec!["quotio", "accounts", "remove", "id"],
    ] {
        assert!(Cli::try_parse_from(args).is_ok());
    }
    assert!(
        Cli::try_parse_from([
            "quotio",
            "accounts",
            "add",
            "--provider",
            "amp",
            "--label",
            "Work",
            "--token",
            "secret"
        ])
        .is_err()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_quotio"))
        .args(["accounts", "add", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
}
