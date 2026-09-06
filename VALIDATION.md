# Backend verification

Verified on 2026-09-06, macOS ARM64, at code revision `2c5cfbb`.
Local default Rust: 1.92.0. Minimum supported Rust checked separately: 1.88.0.
The default toolchain was not changed.

Release binary: `target/release/quotio`.
SHA-256: `9539a7a2de6a6b4131bdccd3a3483365b0c5d7880ad593df79b1475674aa7d79`.
This checksum identifies this signed artifact; a new timestamp/signature changes it.

## Automated results

| Check | Observed result |
| --- | --- |
| `cargo fmt --check` | PASS |
| `cargo clippy --offline --locked --all-targets --all-features -- -D warnings` | PASS |
| `cargo test --offline --locked --all-features --quiet` | PASS: 222 passed, 1 ignored |
| `cargo +1.88.0 clippy --offline --locked --all-targets --all-features -- -D warnings` | PASS |
| `cargo +1.88.0 test --offline --locked --all-features --quiet` | PASS: 222 passed, 1 ignored |
| `actionlint .github/workflows/rust.yml` | PASS |
| `shellcheck scripts/build-signed.sh scripts/sign-macos.sh` | PASS |
| `python3 scripts/test-check-advisories.py` | PASS: 3 tests |
| `python3 scripts/check-advisories.py` | PASS: 212 locked packages, no OSV findings returned |
| `python3 scripts/test-third-party-notices.py` | PASS: 1 test |
| Notice generation for `aarch64-apple-darwin` | PASS: 162 normal/build dependencies, no missing license texts |
| `scripts/build-signed.sh --release --offline --locked --distribution` | PASS |
| `codesign --verify --strict target/release/quotio` | PASS; Developer ID authority and secure timestamp also checked |

The ignored test is the existing explicit native Keychain round trip. The Rust
suites cover domain, provider fixtures, account services, cache, CLI, HTTP and
OpenAPI serialization. They do not require live provider credentials.
OSV results are a point-in-time dependency check, not proof of no vulnerabilities.
GitHub's macOS/Linux matrix is configured but has not run remotely in this phase;
no push was performed. The Linux matrix is not evidence of Linux vault support.

## Regressions covered

- Vault contention stops before mutation and recovers after release. Waiting on
  the shared mutation lock has a deadline; usage/settings return bounded errors.
- Native writes retain their actual completion semantics. No whole-write timeout
  was added that could falsely report failure after a successful OS write.
- Completed refreshes do not consume the 128 running-operation slots. A binary
  integration test completes 140 sequential refreshes.
- Account write retry keys survive refresh history pruning and the 15-minute
  refresh retention window. The 4096-key limit preserves replay for existing keys
  and does not block refresh.
- Manual refresh preserves the scheduler deadline. Timer expiry and configuration
  wakeups clear and replace the advertised next refresh time.
- Binary integration checks observe operation/refresh events without request
  body sentinels, bearer tokens or idempotency keys in captured logs.
- Existing shared-cache, identity, OAuth callback/session, partial-failure and
  secret-free DTO tests still pass.

## Signed release smoke

The signed release ran with an isolated empty-of-secrets config, mock provider,
private temporary cache and synthetic server token. Saved accounts were disabled.
Observed results:

- 140 sequential refresh requests completed, with no `operations_full` failure.
- Manual refreshes preserved `next_refresh_at`; usage remained schema v1.
- A configured public Host and allowed Origin succeeded. Rejected Origin returned
  403; invalid bearer returned 401; OpenAPI returned version 3.1.0.
- Captured logs did not contain the synthetic token. SIGTERM returned exit 0 and
  emitted the server-stop event. Temporary files and process were cleaned up.

The public Host/Origin checks used loopback HTTP with synthetic headers. They do
not prove that an actual HTTPS proxy or tunnel is configured correctly.

## Acceptance still required

This phase made no live OAuth login, real account mutation, notarization upload
or public deployment. Current live evidence must be recorded separately for:

1. OAuth relay/loopback, token renewal and saved-account access on the signed server.
2. Keychain grant/denial/lock behavior and interruption during a native write.
3. Provider quota comparisons against real dashboards and account entitlements.
4. HTTPS proxy/tunnel integration and sustained operation across sleep/restart.
5. Accepted notarization and clean-machine distribution/upgrade checks.

Use [backend operations](docs/operations.md) and [release preparation](docs/releasing.md)
for the procedure. Completion of the automated checks does not close these gates.
