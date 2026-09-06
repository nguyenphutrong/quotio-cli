# Local REST API

Start a read-only API for applications running on the same machine:

```sh
cargo run -- serve --provider codex --provider amp
```

For a fixture-only run with no account discovery or provider requests:

```sh
cargo run -- serve --provider mock --no-saved-accounts
curl http://127.0.0.1:8317/health
curl http://127.0.0.1:8317/v1/providers
curl http://127.0.0.1:8317/v1/usage
curl http://127.0.0.1:8317/v1/usage/mock
```

The listening address is printed to stderr. The process stays in the foreground;
Ctrl-C or SIGTERM on Unix stops it. An occupied port is a startup error, rather
than silently disabling the API. Use `--listen 127.0.0.1:0` to choose an available
port, or `--listen '[::1]:8317'` for IPv6 loopback.

## Configuration

| Option | Default | Meaning |
| --- | --- | --- |
| `--listen` | `127.0.0.1:8317` | Loopback IP address and port; non-loopback addresses are rejected |
| `--provider` | Config selection | Repeat to enable multiple providers; duplicates are removed |
| `--config` | Platform config path | Read `enabled_providers` and `cache_ttl_seconds` from this TOML file |
| `--refresh-interval` | Config, then `60` | Seconds to wait after each completed refresh, from 1 to 86400 |
| `--timeout` | Config, then `10` | Per-provider collection deadline, including retries, from 1 to 3600 seconds |
| `--no-saved-accounts` | Off | Skip the Quotio account vault and use environment/local sources |
| `--manage` | Off | Enable account, OAuth, settings, and refresh writes; requires `QUOTIO_SERVER_TOKEN` |
| `--public-url` | None | External HTTPS origin supplied by a reverse proxy or tunnel; requires the server token |
| `--allow-origin` | None | Exact browser origin allowed for CORS preflight and responses; repeat for multiple origins |

Without `--provider`, the server uses `enabled_providers` from the existing CLI configuration. An empty selection is allowed and serves an empty report until providers are enabled. Startup loads the configuration, while `GET /v1/settings` rechecks the file and applies external changes safely; effective changes invalidate the usage snapshot. Saved accounts are discovered again each cycle.

The same adapters and collector used by `quotio usage` fetch data. Existing provider
credential refresh behavior still applies, including managed OAuth token rotation.
The read-only default has no account or settings writes. `--manage` adds the managed API described in [openapi.json](openapi.json): account mutations, Codex OAuth session relay/loopback callbacks, settings updates, and asynchronous refresh. Codex OAuth sessions can create a managed Codex account through the session and callback routes; other native provider logins still happen in the supported provider CLI or application.

## Routes

| Request | Response |
| --- | --- |
| `GET /health` | `{"status":"ok","ready":true}`; `ready` means the first refresh has completed, even if providers failed |
| `GET /v1/providers` | `schema_version: 1` and a `providers` array with `id`, `description`, `enabled`, and `capabilities` |
| `GET /v1/usage` | Latest report for all enabled providers and their accounts |
| `GET /v1/usage/{provider}` | The same report shape filtered to one enabled, canonical provider ID |
| `GET /openapi.json` | OpenAPI 3.1 contract for all routes |
| `GET /v1/status` | Refresh state and current settings revision |
| `GET /v1/accounts` and `/v1/accounts/{id}` | Managed account metadata; available in read-only mode when account storage is enabled |
| `POST/PATCH/DELETE /v1/accounts...` | Asynchronous managed account mutations; require `Idempotency-Key` (1–128 visible ASCII characters) |
| `POST /v1/auth/sessions` and callback routes | Codex OAuth relay or loopback session lifecycle (requires `--manage`) |
| `GET /v1/settings` | Current settings and revision; available in read-only mode |
| `PATCH /v1/settings` | Optimistic revision patch; requires `--manage` |
| `POST /v1/refresh` | Asynchronous refresh request (requires `--manage`) |
| `GET /v1/operations/{id}` | Operation status; recent refresh results expire after 15 minutes; account write results persist until restart |

Usage responses use Quotio's existing `schema_version: 1` JSON contract, matching
`quotio usage --format json`: `generated_at`, `providers`, and `failures`. Each usage
entry includes its provider, account identity, optional account reference, and quota
windows. Each window retains its own `fetched_at`, reset time, and provenance.
Unknown usage stays unknown; it is never replaced with zero.

A provider route returns all accounts for that provider, including local and saved
accounts after the collector's normal deduplication. Disabled and unknown providers
return 404. Route IDs are canonical IDs from `/v1/providers`; CLI aliases are not
accepted in HTTP paths. Query parameters are not supported.

`HEAD` is supported with no response body. `OPTIONS` returns 204 for an allowed CORS preflight when `--allow-origin` matches; unsupported methods return 405. Read routes remain available without `--manage`; write routes are rejected as read-only unless management mode is enabled.

## Managed request examples

Create an API-key account with a synthetic credential and poll the returned operation:

```sh
curl -X POST http://127.0.0.1:8317/v1/accounts \
  -H "Authorization: Bearer $QUOTIO_SERVER_TOKEN" \
  -H "Idempotency-Key: demo-account-1" -H 'Content-Type: application/json' \
  -d '{"provider":"synthetic","api_key":"synthetic-example-key","settings":{},"region":null,"organization":null}'
curl -H "Authorization: Bearer $QUOTIO_SERVER_TOKEN" http://127.0.0.1:8317/v1/operations/OPERATION_ID
```

Settings patches include the current `revision`; a stale revision returns 409
`revision_conflict`, so read `GET /v1/settings` and retry. `POST /v1/refresh` returns
202 with an operation ID. OAuth begins with `POST /v1/auth/sessions` using
`callback_mode` `relay` or `loopback`; open the returned URL, paste the redirect URL
into the callback endpoint for relay mode, then poll the session with `GET` or cancel
it with `DELETE`.

Provider capabilities include `auth`, supported operations, native-login instructions,
and field metadata. Use each setting's `field_path` to place its value in an account
request: core fields such as `region` are top-level; catalog fields use paths such
as `settings.project_id`. Frontends do not need a separate provider-to-form mapping.

## Refresh and failures

The first refresh starts when the server starts. HTTP reads use memory snapshots
and never trigger another provider fetch. Refreshes run one cycle at a time, with
the configured wait after completion. Each cycle publishes its report atomically.
The shared `UsageCache` service reads
persistent entries also used by `quotio usage`. Only missing or expired accounts
are fetched; the default TTL is 300 seconds, configurable as `cache_ttl_seconds` in
TOML. `--refresh-interval` controls how often the server checks, independently of
that TTL. REST GET requests do not provide a force-refresh option.

Until the first cycle finishes, usage routes return 503 with `not_ready`. Afterwards,
a valid usage report returns 200 even if some or all providers failed. Inspect the
`failures` array to determine provider health; HTTP success only means a report is
available.

A failed account refresh keeps that verified login's last successful snapshot
alongside the new failure. Its original window `fetched_at` values remain unchanged. `generated_at`
is the latest report time, not proof that every account was just fetched. Clients
should display the failure and use each window's `fetched_at` to assess age. Old
snapshots may remain available through repeated failures even after their TTL expires.
A successful refresh replaces them. Removed accounts disappear on the next discovery
cycle. If login identity cannot be verified, no old snapshot is restored. The HTTP
transport does not perform its own stale-data merge.

Disk entries survive server restarts. CLI and REST share the same cache directory;
`QUOTIO_CACHE_DIR` overrides its platform default. See the README's usage cache
section for storage, concurrency, diagnostics and native identity limitations.

This follows OpenUsage's local snapshot approach, but uses Quotio's own report schema.
It is not an implementation of OpenUsage's `/v1/limits` or legacy UI response format.

## Local access and optional authentication

Only loopback listening is supported. The server accepts a Host header matching its
bound address and port, or `localhost` with that port. It rejects requests carrying
an Origin header and does not emit CORS permission headers. Browser pages on other
origins cannot read the API through CORS; this version targets local CLI/native
clients rather than a browser dashboard.

By default, other processes running on the same machine can read the snapshots.
To require authentication, set `QUOTIO_SERVER_TOKEN` before starting the server. It
must contain 32 to 4096 visible ASCII characters. Clients must then send
`Authorization: Bearer <token>` on every route, including `/health`. Keep the token
in the client's secret storage and send it only as a header, never in a URL. There
is no token command-line flag. An empty or malformed configured token prevents startup.

Responses include `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
Account labels, email addresses, usage, and balances can appear just as in CLI JSON;
provider credentials and server tokens are not serialized. There is no request/header
logging. Up to 16 HTTP handlers can run at once; this is a handler limit, not a TCP
connection limit. `--public-url` declares the HTTPS origin of a separately operated reverse proxy; it does not provision TLS or open a remote listener. Quotio itself remains loopback-only.

## Error codes

API errors use `{"error":"code"}`. Provider failures remain inside a usage report.

| Status | Codes |
| --- | --- |
| 400 | `unsupported_query` |
| 401 | `unauthorized` |
| 403 | `origin_not_allowed`, `host_not_allowed` |
| 404 | `not_found`, `provider_not_enabled` |
| 405 | `method_not_allowed` |
| 503 | `not_ready`, `server_busy` |
| 500 | `encoding_failed` |

Managed routes also use `idempotency_key_required`, `invalid_idempotency_key`, `idempotency_conflict`, `operations_full`, `account_storage_disabled`, and account or OAuth-specific errors. A settings patch with a stale `revision` returns 409 `revision_conflict`; read `GET /v1/settings` and retry against the returned revision.

Malformed HTTP is rejected by the HTTP stack before these API handlers. Startup
argument/config errors exit with code 2; initialization or bind errors use code 3.

### Account operation deadlines

Vault reads and waits for the shared mutation lock stop after 10 seconds. A busy
vault produces `account_busy`; settings lock contention produces `settings_busy`
(409). Usage reads return 503 `account_busy` while a write holds the lock too long.
OAuth token exchange and quota validation each have a 30-second deadline.

Once a native credential write starts, Quotio waits for its actual result instead
of reporting a timeout that might hide a successful write. A stalled write remains
running; other requests stop waiting for its lock after 10 seconds. After an
interruption or restart, inspect the account list before submitting another write.

### Operation capacity and retries

Up to 128 operations may run at once. Completed refreshes do not consume running
slots. The latest 128 refresh results are available for up to 15 minutes; older
results return 404. Account write results and their idempotency keys remain until
restart, so retrying a key cannot repeat a write after refresh history is pruned.
The server accepts at most 4096 distinct account write keys per lifetime; further
new keys return 503 `idempotency_full`. Existing keys still replay their result,
and refresh remains available. Complete pending writes and restart to clear this
ledger. Keys and operations cannot be recovered across restart.
