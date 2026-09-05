# Quotio CLI

A standalone Rust CLI for provider quota reports. This milestone includes only
`mock`, a deterministic fixture with three quota windows. It does not check any
live account. No TUI is included yet.

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
`CredentialStore` can read environment variables, but mock never requests a secret.
No credentials are persisted, printed or logged by this implementation.

## Output contract

JSON has `schema_version: 1`, RFC 3339 `generated_at`, `providers`, and `failures`.
Arrays preserve request order within successes and failures. Each provider contains
`provider`, `account` with `id` and `label`, and an arbitrary number of `windows`.

Each window contains `label`, `quota`, nullable `resets_at`, `provenance` with
`source` and `confidence`, and RFC 3339 `fetched_at`. Timestamps include an offset.
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
`timeout`, `cancelled`, `transient`, `authentication`, `invalid_data`, and `internal`.
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
- `src/fetch.rs`: `Collector::collect(CollectRequest) -> UsageReport`.
- `src/cli.rs`, `src/config.rs`, `src/main.rs`: arguments, config and executable wiring.
- `src/output/`: independent text and JSON renderers.
- `tests/`: offline collection and binary contract tests.
- `plans/plan.md`, `VALIDATION.md`: implementation plan and verification evidence.

The collector runs adapters concurrently with Tokio. Each provider gets a deadline
covering fetches and retry delays. Only an idempotent adapter returning `Transient`
is retried, up to three total attempts, with 100 ms then 200 ms backoff. Cancellation
and timeout drop the adapter future. Dropping collection aborts its owned tasks.
Adapters must remain async and cancellation-safe, and must not detach work or block
the runtime. Completed results are ordered before rendering.

The HTTP client uses reqwest JSON and rustls TLS. Redirects are disabled in the
executable. Tokio supplies concurrency, deadlines, cancellation channels and signals;
no extra async trait or cancellation dependency is needed. Serde, JSON and TOML
handle data/config; time handles timestamp offsets; thiserror provides fixed typed
errors; tracing sends diagnostics; clap parses arguments; directories resolves the
config location. These are the dependencies requested for this milestone.

To add a live provider:

1. Choose the provider and confirm its documented endpoint and authentication flow.
2. Implement `ProviderAdapter` using the injected client, clock and credential store.
3. Normalize missing data explicitly. Return public account metadata and source names
   only; never copy raw response bodies, headers or credentials into errors or logs.
4. Add sanitized fixtures and offline tests for authentication, malformed responses,
   rate limits, account identity and retries. Add the provider to CLI/config selection.
5. Verify live behavior separately with authorized credentials. Mock tests cannot
   establish that live authentication or quota fetching works.

An adapter can try documented fallback sources internally under the same deadline.
It must preserve account identity and report the source actually used. No fallback
source or live endpoint is implemented here.

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
