# Account onboarding verification

Code revision: 2321257. macOS, Rust/Cargo 1.92.0. This supplements the historical
provider-only VALIDATION.md; that older binary digest is not the current artifact.

## Completed implementation

- API-key Add account for Amp/Factory; validate quota before persisting.
- Codex standalone PKCE login, direct quota reads, safe refresh and token rotation.
- List/use/remove accounts; one active account per provider; no foreign CLI logout.
- Native Keychain vault with one atomic document and process locking.
- No cookie extraction or dependency on Codex/Amp binaries for saved accounts.
- Explicit --no-saved-accounts preserves the prior environment/CLI routes.

## Evidence

| Check | Result |
| --- | --- |
| cargo fmt --check | PASS |
| cargo clippy --offline --all-targets --all-features -- -D warnings | PASS |
| cargo test --offline | PASS: 50 tests, one opt-in native test skipped |
| cargo test --offline native_keychain_round_trip -- --ignored | PASS: synthetic create/read/update/delete in native Keychain; item cleaned up |
| cargo build --offline | PASS |
| --help, accounts --help, accounts add --help, providers | PASS, exit 0 |
| usage --provider mock --no-saved-accounts --format json | PASS, exit 0 |
| Built CLI Add account with pipe held open, then SIGINT | PASS: exit 2 promptly, stdout empty; no credential submitted/account saved |

All commands used CARGO_TARGET_DIR=target. Initial native dependencies needed one
Cargo download; subsequent tests ran offline. Ordinary tests use in-memory vaults,
synthetic credentials, local fixture servers and local subprocesses. The native
Keychain test uses a unique verification namespace, not personal credentials.

## Independent review

A separate read-only reviewer checked vault, OAuth, CLI and service orchestration.
Findings were fixed and covered:

- Ordinary Codex quota reads release the vault lock, so concurrent Amp can complete.
- Busy discovery is bounded and cancellable before collection; refresh contention
  waits asynchronously within the caller budget.
- Stalled API-key pipe input yields to timeout/Ctrl-C and restores descriptor flags.
- A rotating refresh operation is not marked idempotent and is attempted only once
  after uncertain network failure.
- Rotated tokens reach storage before quota retry; failed save fails closed and
  leaves prior data. A failed quota retry does not discard persisted rotation.

OAuth tests include the RFC PKCE challenge example, callback state mismatch and
duplicates, nonce and expiry, actual loopback callback IO, account identity changes
on refresh, and protected request metadata. Provider tests preserve sparse windows.

One parallel test run hit transient lock contention during immediate test read-back.
The test now uses the same bounded async acquisition as the application; the full
suite subsequently passed. No thresholds or product behavior were weakened.

## Remaining acceptance

No personal API key was submitted and no interactive Codex sign-in was initiated
in this development run. Thus the new end-to-end live login/key-validation flow is
not claimed to have passed. The user can exercise it via README commands.

Keychain storage is currently macOS-only. Browser PKCE uses the same Codex client
and internal quota route as the Swift Monitor reference; provider-side changes can
require updates. The CLI retains prior fallback routes for users without a saved
account. Antigravity OAuth onboarding, new providers and TUI are separate next slices.

Built binary SHA-256: `7e85f675fbb59808d041481d2263af93a4b2660a8fba5124b7f8e7531e2b773f`.
