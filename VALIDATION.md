# Validation

Verified 2026-09-05 on macOS, Rust 1.92.0 / Cargo 1.92.0.

All final commands used `CARGO_TARGET_DIR=target CARGO_NET_OFFLINE=true`.
The host default target path was invalid; no host config was modified.
Initial offline resolution lacked crates, so one dependency download was needed.
All tests and final validation ran offline without credentials or endpoints.

| Command | Result |
| --- | --- |
| `cargo fmt --check` | PASS (0) |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS (0) |
| `cargo test` | PASS (0) |
| `cargo run -- --help` | PASS (0) |
| `cargo run -- providers` | PASS (0) |
| `cargo run -- usage --provider mock --format text` | PASS (0) |
| `cargo run -- usage --provider mock --format json` | PASS (0) |

Tests: 14 passed, 0 failed. Five binary/argument tests and nine collection/domain tests.
Coverage includes normalization, unknown versus exhausted, multiple windows, partial
failure, concurrency, timeout, cancellation cleanup, bounded retry, invalid adapter
data, JSON fields/failures, exit codes, config selection and diagnostic redaction.

Exit 1 is verified through a mixed-adapter report; the shipped mock always succeeds.
No live provider, authentication flow or TUI has been verified.

## Text smoke output

```text
Usage as of 2026-09-05T06:37:37.515325Z
mock | Demo account (mock-account)
  Session: used 25.0%; remaining 75.0%; reset 2026-01-08T00:00:00Z; source mock_fixture (Exact); fetched 2026-01-01T00:00:00Z
  Weekly: exhausted; used 100.0%; remaining 0.0%; reset 2026-01-08T00:00:00Z; source mock_fixture (Exact); fetched 2026-01-01T00:00:00Z
  Monthly: usage unknown; remaining unknown; reset unknown; source mock_fixture (Exact); fetched 2026-01-01T00:00:00Z
```
