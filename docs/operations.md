# Operate a Quotio backend

Run one server as the OS user who owns the provider accounts. The server must
stay on loopback. An independently managed HTTPS proxy or tunnel handles remote
connections. macOS stores accounts in Keychain. Linux uses its encrypted vault
and requires `QUOTIO_VAULT_KEY_FILE` or `QUOTIO_VAULT_KEY_FD` at startup.

## First startup

1. On macOS, build with `scripts/build-signed.sh --release --locked` and keep the
   same signing identity for upgrades. This is a local build, not a notarized
   distribution. On Linux, use a published release artifact or build with
   `cargo build --release --locked`; macOS signing scripts do not run on Linux.
2. Run the binary's `accounts list` command in a terminal. On macOS, grant access
   to Quotio's vault if prompted. On Linux, first supply one protected master-key
   source as documented in the README. Add accounts through the CLI or management API.
3. Put the server token in the launcher's secret storage. Supply it as the
   `QUOTIO_SERVER_TOKEN` environment variable, never a command-line argument or URL.
4. Start the server with an explicit absolute config path:

   ```sh
   /absolute/path/to/quotio serve --manage --config /absolute/path/to/config.toml
   ```

   The config must exist when explicitly supplied; an empty file supports initial
   setup. Omit provider, timeout and refresh interval flags to manage those fields
   through settings API calls.
5. Read `/v1/status`, `/v1/settings`, `/v1/providers` and `/v1/usage` using bearer
   authentication. A ready snapshot can contain provider failures: inspect the
   `failures` array and each account's `fetched_at`, not readiness alone.

For remote access add `--public-url https://quota.example.com` and the exact client
origin, for example `--allow-origin https://dashboard.example.com`. Configure the
proxy to preserve that Host, forward Authorization, redact it from logs, and
limit connections, request sizes and idle time. Do not expose the loopback HTTP
port directly. Quotio does not trust forwarded headers as authority.

## Run in the background

On macOS, use a per-user LaunchAgent or a Swift app-owned child process. On Linux,
use a per-user service manager and pass the protected vault key source from its
secret storage. Keep the binary at an absolute, stable path, run it as the account
owner, and configure restart on unexpected exit with a delay between restarts. Do
not run a system-wide root daemon against a user's Keychain or encrypted vault.

The launcher must pass the token without putting it into a checked-in plist.
Keep any local wrapper or secret file private to its owner (mode 0600), and keep
logs private because operational metadata still describes the user's activity.
On macOS, a LaunchAgent runs only within the user's login session; locking the
Keychain, logging out, sleeping or restarting the Mac can interrupt provider
access. On Linux, verify the user service can read its key source after logout or
restart without copying the key into the unit file or process arguments.

Quotio emits lifecycle, refresh counts and operation outcome events to stderr.
It does not log request bodies, callbacks, authorization headers, labels or
provider response bodies. Rotate the stderr file in the supervisor.

## Recover from an interruption

- Poll running operations before an intentional upgrade. Stop accepting new client
  writes, then send SIGTERM. HTTP draining is limited to two seconds; native writes
  cannot be rolled back by cancelling their Rust future.
- After restart, read the account list and settings before retrying a write whose
  outcome was unknown. Operations, OAuth sessions and idempotency keys are in
  memory only. Never assume a missing operation means the write did not happen.
- A blocked native write stays running until the OS returns. Other requests stop
  waiting on its lock after 10 seconds. Resolve Keychain access on the Mac; do not
  repeatedly submit new idempotency keys for the same intent.
- On `idempotency_full`, let pending writes finish, reconcile account state and
  restart. The server retains at most 4096 account write keys per lifetime.
- On provider failures, check credentials and account entitlements locally. A
  forced refresh bypasses freshness checks; repeated force calls do not fix an
  authentication error and can trigger provider rate limits.

Retain the previous release binary and a private copy of the config before an
upgrade. On macOS, keep its signing identity stable. Use the same config and vault
identity for rollback. Credentials remain
in Keychain on macOS or in the encrypted vault on Linux. Keep the Linux master key
separate from the vault, and never export either into diagnostics or Git. The usage
cache is rebuildable and does not contain provider tokens.

## Release acceptance

Record the revision, OS, binary checksum, signing verification and result for each
check below. Use sanitized outcomes, not tokens, email addresses or raw responses.

- Add, relabel, select and remove a disposable account through the release server.
  On macOS, use the actual signed binary and check both granted and denied Keychain
  access without remote prompts. On Linux, test missing, invalid and correct vault
  keys plus a restart using the same encrypted vault.
- Complete Codex OAuth in loopback and relay modes. Check expiry, token rotation,
  duplicate identity and callback replay against the real provider.
- Verify usage for every provider advertised as live-supported against its own
  dashboard. A parser fixture proves only the fixture contract.
- Interrupt a write, restart and reconcile the stored account list. On macOS,
  repeat with the Keychain locked and the Mac asleep. On Linux, repeat with the
  vault key temporarily unavailable. Test network loss on both platforms.
- Through the actual HTTPS proxy, verify bearer enforcement, allowed and rejected
  origins, Host validation, body limits and recovery after proxy restart.
- Run the release binary long enough to cover token renewal and multiple refresh
  periods. Check that memory, child processes and open connections remain bounded.

These checks require the deployment environment and suitable accounts. Offline
fixtures and CI do not replace this acceptance.
