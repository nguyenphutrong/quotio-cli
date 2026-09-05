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
        vec!["quotio", "accounts", "add", "--provider", "codex"],
        vec![
            "quotio",
            "accounts",
            "add",
            "--provider",
            "amp",
            "--token-stdin",
        ],
        vec![
            "quotio",
            "accounts",
            "add",
            "--provider",
            "factory",
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

#[test]
fn account_selector_requires_one_provider_and_conflicts_with_skip_vault() {
    assert!(
        Cli::try_parse_from([
            "quotio",
            "usage",
            "--provider",
            "codex",
            "--account",
            "local"
        ])
        .is_ok()
    );
    assert!(Cli::try_parse_from(["quotio", "usage", "--account", "id"]).is_err());
    assert!(
        Cli::try_parse_from([
            "quotio",
            "usage",
            "--provider",
            "codex",
            "--account",
            "id",
            "--no-saved-accounts"
        ])
        .is_err()
    );
    let config = ConfigFile::new("enabled_providers = []");
    let output = Command::new(env!("CARGO_BIN_EXE_quotio"))
        .args([
            "usage",
            "--provider",
            "codex",
            "--provider",
            "amp",
            "--account",
            "id",
            "--config",
        ])
        .arg(&config.0)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn authorize_help_is_available_without_accessing_keychain() {
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_quotio"))
        .args(["accounts", "authorize", "--help"])
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(
        String::from_utf8(result.stdout)
            .unwrap()
            .contains("--provider")
    );
}

#[cfg(target_os = "macos")]
#[test]
fn api_key_prompt_hides_input_and_restores_terminal_on_error_or_ctrl_c() {
    use std::{
        io::{Read, Write},
        os::fd::{AsRawFd, FromRawFd},
        process::Stdio,
        time::{Duration, Instant},
    };
    struct Terminal {
        child: std::process::Child,
        master: std::fs::File,
        slave: std::fs::File,
    }
    impl Drop for Terminal {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
    fn attributes(file: &std::fs::File) -> libc::termios {
        let mut value = std::mem::MaybeUninit::uninit();
        assert_eq!(
            unsafe { libc::tcgetattr(file.as_raw_fd(), value.as_mut_ptr()) },
            0
        );
        unsafe { value.assume_init() }
    }
    for (provider, cancel) in [("amp", false), ("amp", true), ("factory", false)] {
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
        let master = unsafe { std::fs::File::from_raw_fd(fds[0]) };
        let slave = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        for fd in fds {
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
                0
            );
        }
        assert_eq!(
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let before = attributes(&slave);
        let flags = unsafe { libc::fcntl(slave.as_raw_fd(), libc::F_GETFL) };
        let child = Command::new(env!("CARGO_BIN_EXE_quotio"))
            .args(["accounts", "add", "--provider", provider])
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()))
            .spawn()
            .unwrap();
        let mut terminal = Terminal {
            child,
            master,
            slave,
        };
        let mut output = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut buffer = [0; 1024];
            match terminal.master.read(&mut buffer) {
                Ok(n) => output.extend_from_slice(&buffer[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                result => panic!("PTY read failed: {result:?}"),
            }
            if String::from_utf8_lossy(&output).contains("API key (hidden):") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "prompt missing: {}",
                String::from_utf8_lossy(&output)
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let during_flags = unsafe { libc::fcntl(terminal.slave.as_raw_fd(), libc::F_GETFL) };
        let during = attributes(&terminal.slave);
        assert_eq!(during.c_lflag & (libc::ECHO | libc::ECHONL), 0);
        assert_eq!(
            during.c_cc[libc::VQUIT],
            libc::_POSIX_VDISABLE as libc::cc_t
        );
        assert_eq!(
            during.c_cc[libc::VSUSP],
            libc::_POSIX_VDISABLE as libc::cc_t
        );
        if cancel {
            terminal.master.write_all(b"synthetic-hidden").unwrap();
            assert_eq!(
                unsafe { libc::kill(terminal.child.id() as i32, libc::SIGINT) },
                0
            );
        } else {
            // Internal tab makes this synthetic key invalid before network/Keychain.
            terminal
                .master
                .write_all(b"synthetic-hidden\tkey\n")
                .unwrap();
        }
        let exit = loop {
            if let Some(status) = terminal.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "command did not finish");
            std::thread::sleep(Duration::from_millis(10));
        };
        loop {
            let mut buffer = [0; 1024];
            match terminal.master.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => output.extend_from_slice(&buffer[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                result => panic!("PTY read failed: {result:?}"),
            }
        }
        assert_eq!(exit.code(), Some(2));
        let after = attributes(&terminal.slave);
        assert_eq!(after.c_lflag, before.c_lflag);
        assert_eq!(after.c_cc, before.c_cc);
        assert_eq!(
            unsafe { libc::fcntl(terminal.slave.as_raw_fd(), libc::F_GETFL) },
            // Process startup can add unrelated flags before the prompt begins.
            (during_flags & !libc::O_NONBLOCK) | (flags & libc::O_NONBLOCK)
        );
        let text = String::from_utf8_lossy(&output);
        assert!(!text.contains("synthetic-hidden"));
        assert!(
            text.contains(if cancel {
                "cancelled"
            } else {
                "credential input"
            }),
            "{text}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn api_key_pipe_requires_flag_and_preserves_validation() {
    use std::{io::Write, process::Stdio};
    for token_stdin in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_quotio"));
        command.args(["accounts", "add", "--provider", "amp"]);
        if token_stdin {
            command.arg("--token-stdin");
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = child
            .stdin
            .take()
            .unwrap()
            .write_all(b"synthetic-hidden\tkey\n");
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let message = String::from_utf8(output.stderr).unwrap();
        assert!(!message.contains("synthetic-hidden"));
        assert!(message.contains(if token_stdin {
            "credential input"
        } else {
            "--token-stdin"
        }));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn new_key_providers_reach_key_validation_without_network() {
    use std::{io::Write, process::Stdio};
    for provider in ["synthetic", "openrouter", "zai", "minimax"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_quotio"));
        command.args(["accounts", "add", "--provider", provider, "--token-stdin"]);
        if matches!(provider, "zai" | "minimax") {
            command.args(["--region", "cn"]);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"invalid\tkey\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("credential input")
        );
        assert!(output.stdout.is_empty());
    }
}
