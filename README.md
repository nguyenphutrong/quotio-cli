# Quotio CLI

A standalone Rust CLI for provider quota reports. The CLI supports `mock`, `codex`,
`amp`, `antigravity`, and `factory` (aliases `droid`, `factory-droid`). No TUI yet.

| Provider | Data source | Current verification |
| --- | --- | --- |
| Codex / ChatGPT | Saved OAuth + direct API; installed CLI fallback | OAuth/direct API tested offline; CLI live read previously passed |
| Amp | Saved API key + direct API; installed CLI fallback | API tested offline; CLI live read previously passed |
| Antigravity | Direct Google quota API, following the main Quotio project | Offline tests passed; live token use awaiting approval |
| Factory Droid | Saved API key or environment key + direct API | Offline tests passed; user key validation needed |
| Mock | Fixed fixture | Offline tests passed |

Antigravity does not use the app's local service or require the app to be running.
See [provider contracts](plans/20260905-first-live-provider/) for source evidence.

## Run

Use Rust stable with edition 2024 support. The package declares Rust 1.88 or newer;
this revision was verified with Rust 1.92.0. `Cargo.lock` pins dependencies.

```sh
cargo run -- --help
cargo run -- providers
cargo run -- usage --provider mock --format text
cargo run -- usage --provider mock --format json
cargo run -- usage --provider mock --provider mock --timeout 5 --no-color --verbose
cargo run -- usage --config ./config.toml
cargo run -- usage --provider codex --provider amp --timeout 30
cargo run -- usage --provider antigravity --provider factory --format json
```

Repeated provider IDs are deduplicated, keeping the first occurrence. Timeout is
an integer from 1 to 3600 seconds, default 10, applied separately to each provider.
Text output is always plain, so `--no-color` is accepted without changing it.
`--verbose` sends logs to stderr. Reports go to stdout.

## Config

```toml
# config.toml
enabled_providers = ["mock"]
```

`--config` chooses an explicit file. Otherwise `directories::ProjectDirs` locates
`quotio/config.toml` under the platform config directory. Typical locations are:

- macOS: `~/Library/Application Support/quotio/config.toml`
- Linux: `$XDG_CONFIG_HOME/quotio/config.toml`, or `~/.config/quotio/config.toml`
- Windows: the application config directory returned by `ProjectDirs`.

Without `--provider`, selection comes from `enabled_providers`. Explicit providers
override selection, but any loaded config must still be valid. Missing default
config means no enabled providers, with exit code 3. A missing explicit config,
invalid TOML, unknown fields or unsupported provider is a config error, code 2.
The CLI does not create config or cache directories.

Do not put credentials in config. Unknown fields, including token fields, are
rejected. Parse errors show a line and column without echoing input. Argument
errors also omit input values; use `quotio usage --help` for valid syntax.
`CredentialStore` reads environment variables, but mock never requests a secret.
Credentials are persisted only by explicit account commands in Keychain; they are
never printed or logged.

## Add and manage accounts on macOS

```sh
# Codex opens the official sign-in page. No Codex CLI is required.
cargo run -- accounts add --provider codex

# Keys come from your existing secret-manager environment, never command arguments.
printenv AMP_API_KEY | cargo run -- accounts add --provider amp --token-stdin
printenv FACTORY_API_KEY | cargo run -- accounts add --provider factory --token-stdin

cargo run -- accounts list
cargo run -- accounts list --format json
cargo run -- accounts use <account-id>
cargo run -- accounts remove <account-id>
cargo run -- usage --provider codex --provider amp --provider factory
```

`--label` is optional. Codex defaults to the authenticated email. API-key accounts
default to `API key ****ABCD`, showing only the last four ASCII characters of keys
longer than eight characters; shorter or non-ASCII keys are fully masked. An explicit
label takes precedence. If a label already exists, supply a different `--label`.

For Codex, `--no-browser` prints the login URL without opening it. Callback binds to
`localhost:1455/auth/callback`; close another login process if that port is busy.
Login uses PKCE, state and nonce validation, then reads quota before saving. It has
a 180-second budget and supports Ctrl-C. No browser cookies are read.

For Factory, `--region global|eu` and `--organization <id>` may be supplied during
Add account. Amp/Factory accept one key line from a pipe, not an interactive visible
prompt. A failed validation or save does not create an account.

The first saved account for each provider becomes active. Additional accounts are
saved without changing the selection; use `accounts use` to select them. Removing
an active account selects the next account for that provider. Removal affects only
Quotio's saved record; it does not revoke remote tokens or log other apps out.

All account metadata and tokens live in one protected Keychain item:
service `app.quotio.cli.accounts.v1`, account `vault`. No plaintext credential files
are created. A local empty lock file coordinates processes. Failed atomic writes
preserve the previous document. Listing prints metadata only.

Saved active accounts take precedence over environment/local CLI sources. Use
`usage --no-saved-accounts` to explicitly skip the vault. A locked/denied vault
returns a provider failure rather than silently selecting another account.
Managed storage currently supports macOS only; other platforms retain the previous
environment/CLI usage routes. There is no plaintext storage fallback.

Saved Codex accounts use `source: codex_api`. Refresh occurs near expiry or after
authentication failure, and all rotated tokens are saved before a quota retry.
Refresh is serialized and never automatically replayed after an uncertain failure.
Saved Amp accounts use `source: amp_api` and require no Amp binary. Factory uses
`source: factory_billing_limits` with account/organization validation.

Without saved accounts, Codex and Amp retain their installed-CLI routes. Quotio
submits no prompts and never starts login/logout through those fallback CLIs.
Those CLIs may perform their usual internal auth maintenance or update checks.
Missing executables or unsupported output become per-provider failures.

## Other credential sources

Antigravity reads `ANTIGRAVITY_ACCESS_TOKEN`, or the `access_token` field in the JSON
file selected by `ANTIGRAVITY_AUTH_FILE`. Without either, it selects exactly one
`antigravity-*.json` in `~/.cli-proxy-api`, as used by the main Quotio app. Multiple
files require explicit selection. It obtains identity from Google userinfo and
calls Google quota APIs with the same token. File contents are never rewritten.
This version does not refresh tokens, scrape native SQLite/keychain stores or start
a login flow. Refresh an expired token through its existing login owner.

Without a saved account, Factory uses `FACTORY_API_KEY`. Optional `FACTORY_REGION` is `global`
or `eu`; `FACTORY_ORG_ID` selects the organization. The adapter validates user and
organization with Factory before and after reading quota. Local encrypted Droid
auth reuse is not implemented pending the requested explicit authorization.
The internal billing endpoint is verified from first-party code, but API-key
acceptance has not yet been validated live.

Set credentials through your existing environment/secret manager. Do not put them
in TOML, shell command arguments, fixture files or bug reports. See the contract
notes for the exact authenticated destinations. Remote HTTP uses normal TLS and
disables redirects; no self-signed local-service client remains.

## Output contract

JSON has `schema_version: 1`, RFC 3339 `generated_at`, `providers`, and `failures`.
Arrays preserve request order within successes and failures. Each provider contains
`provider`, `account` with `id` and `label`, and an arbitrary number of `windows`.

Each window contains `label`, `quota`, nullable `resets_at`, `provenance` with
`source` and `confidence`, and RFC 3339 `fetched_at`. Timestamps include an offset.
Optional `amounts` records a balance as `remaining`, nullable `limit`, and `unit`.
USD credit balances with no limit retain unknown percentage, including a zero
balance. Amp subscription dollar/hour allowances are separate windows.

The mock's fixed observation date is January 1, 2026. It is demo data, not fresh
account usage. The report generation time uses the injected clock.

Quota examples:

```json
{"state":"available","used_percent":25.0,"remaining_percent":75.0}
{"state":"exhausted","used_percent":100.0,"remaining_percent":0.0}
{"state":"unknown"}
```

Missing or non-finite input becomes unknown. Finite input is clamped to 0–100.
Unknown usage has no numeric percentage fields and never means exhausted.
Collector rejects inconsistent numeric quota values returned by an adapter.
Confidence is `exact`, `estimated` or `unknown`. Consumers can calculate observation
age from `fetched_at`; this milestone has no cache or automatic stale threshold.

A failure contains `provider`, a fixed `code`, and a safe `message`. Codes are
`timeout`, `cancelled`, `transient`, `authentication`, `invalid_data`, `internal`,
`unavailable`, and `rate_limited`.
A failed provider does not remove successful results. Failures are included in
reports and summarized on stderr. Consumers should allow future additive fields;
incompatible changes require a new schema version.

| Exit | Meaning |
| --- | --- |
| 0 | Every selected provider returned valid data |
| 1 | Some providers succeeded and some failed |
| 2 | Invalid arguments or config |
| 3 | No provider returned data, no providers selected, or output/runtime setup failed |

Ctrl-C cancels pending providers and emits a report with completed results. It uses
the same success/partial/empty exit rules. Output write errors use code 3.

## Code and extension points

- `src/domain.rs`: renderer-independent identity, quota, provenance and report types.
- `src/providers/mod.rs`: `ProviderAdapter`, injected HTTP client, clock and credential store.
- `src/providers/mock.rs`: fixed fixture, with available, exhausted and unknown windows.
- `src/providers/{codex,amp,antigravity,factory}.rs`: independent provider adapters.
- `src/providers/http.rs`, `src/providers/process.rs`: bounded transport and child lifecycle.
- `src/fetch.rs`: `Collector::collect(CollectRequest) -> UsageReport`.
- `src/cli.rs`, `src/config.rs`, `src/main.rs`: arguments, config and executable wiring.
- `src/output/`: independent text and JSON renderers.
- `tests/`: offline collection and binary contract tests.
- `plans/plan.md`, `VALIDATION.md`: implementation plan and verification evidence.

The collector runs adapters concurrently with Tokio. Each provider gets a deadline
covering fetches and retry delays. Only an idempotent adapter returning `Transient`
is retried, up to three total attempts, with 100 ms then 200 ms backoff. Cancellation
and timeout drop the adapter future. Dropping collection aborts its owned tasks.
HTTP 429 honors Retry-After within the deadline. Missing/invalid delays or delays
over one hour return rate_limited without rapid retries.

Adapters must remain async and cancellation-safe, and must not detach work or block
the runtime. Completed results are ordered before rendering.

The HTTP client uses reqwest JSON and rustls TLS. Redirects are disabled in the
executable. Tokio supplies concurrency, deadlines, cancellation channels and signals;
no extra async trait or cancellation dependency is needed. Serde, JSON and TOML
handle data/config; time handles timestamp offsets; thiserror provides fixed typed
errors; tracing sends diagnostics; clap parses arguments; directories resolves the
config location. Account onboarding additionally uses ring for secure randomness and PKCE hashing,
base64 for protocol encoding, libc for native file locking and cancellable input,
and security-framework on macOS for Keychain access.

To add a live provider:

1. Choose the provider and confirm its documented endpoint and authentication flow.
2. Implement `ProviderAdapter` using the injected client, clock and credential store.
3. Normalize missing data explicitly. Return public account metadata and source names
   only; never copy raw response bodies, headers or credentials into errors or logs.
4. Add sanitized fixtures and offline tests for authentication, malformed responses,
   rate limits, account identity and retries. Add the provider to CLI/config selection.
5. Verify live behavior separately with authorized credentials. Mock tests cannot
   establish that live authentication or quota fetching works.

Antigravity tries quota summary with a project, then without a project when needed,
then model quota. Optional project discovery failures do not block this fallback;
authentication and rate-limit failures stop it. Every window records its source.

A future TUI can own `Collector`, call `collect`, display the domain report and use
`Cancellation` on refresh or exit. It must not parse the CLI text or require changes
to provider fetch logic. No UI framework is needed in this milestone.

## Verification

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

After dependencies are downloaded, use `CARGO_NET_OFFLINE=true` to enforce offline
Cargo resolution. Tests need no credentials and call no endpoints. If the host's
shared Cargo target path is invalid, set `CARGO_TARGET_DIR=target` for local builds.
See `VALIDATION.md` for the exact checked commands and results.

CodexBar was inspected read-only for modeling and test ideas. Relevant files were
`UsageFetcher.swift`, `ProviderIdentitySnapshot.swift`, `ProviderFetchPlan.swift`,
`UsageFormatter.swift`, and `CopilotUsageModelsTests.swift`. No implementation was
copied. This project contains no CodexBar imports, path dependencies, binaries,
symlinks or submodules. Build and runtime do not need the reference checkout.


## Limits of this milestone

- Prior live evidence covers the Codex/Amp CLI routes on this macOS installation.
  The new OAuth/direct-key onboarding needs user sign-in/key acceptance testing.
- Antigravity direct API and Factory live verification await credential approval.
  Offline tests do not establish provider availability or account entitlements.
- Antigravity/Factory internal endpoints and Amp text output can change. Unknown
  formats fail explicitly instead of fabricating usage.
- Codex token refresh is implemented for saved accounts. Antigravity refresh,
  multi-account fan-out, cache, automatic polling and TUI remain future work.
- Dates without a timezone in Amp output have no invented reset instant.
- Factory windows whose end is in the past remain unknown until replaced by fresh data.
- The main Quotio repository was consulted read-only for Antigravity API behavior.
  The CLI builds without that repository and without CodexBar.
