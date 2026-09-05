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
| `--refresh-interval` | `60` | Seconds to wait after each completed refresh, from 1 to 86400 |
| `--timeout` | `10` | Per-provider collection deadline, including retries, from 1 to 3600 seconds |
| `--no-saved-accounts` | Off | Skip the Quotio account vault and use environment/local sources |

Without `--provider`, the server uses `enabled_providers` from the existing CLI
configuration. An empty selection is a startup error. Config and enabled provider
selection are read once at startup. Saved accounts are discovered again each cycle,
so accounts added or removed through `quotio accounts` take effect on refresh.

The same adapters and collector used by `quotio usage` fetch data. Existing provider
credential refresh behavior still applies, including managed OAuth token rotation.
No HTTP endpoint adds accounts, changes credentials, or starts a login.

## Routes

| Request | Response |
| --- | --- |
| `GET /health` | `{"status":"ok","ready":true}`; `ready` means the first refresh has completed, even if providers failed |
| `GET /v1/providers` | `schema_version: 1` and a `providers` array with `id`, `description`, and `enabled` |
| `GET /v1/usage` | Latest report for all enabled providers and their accounts |
| `GET /v1/usage/{provider}` | The same report shape filtered to one enabled, canonical provider ID |

Usage responses use Quotio's existing `schema_version: 1` JSON contract, matching
`quotio usage --format json`: `generated_at`, `providers`, and `failures`. Each usage
entry includes its provider, account identity, optional account reference, and quota
windows. Each window retains its own `fetched_at`, reset time, and provenance.
Unknown usage stays unknown; it is never replaced with zero.

A provider route returns all accounts for that provider, including local and saved
accounts after the collector's normal deduplication. Disabled and unknown providers
return 404. Route IDs are canonical IDs from `/v1/providers`; CLI aliases are not
accepted in HTTP paths. Query parameters are not supported.

`HEAD` is supported with no response body. Other methods, including `OPTIONS`, return
405 unless rejected earlier by host, origin, or authentication checks.

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
connection limit. This server does not provide TLS or remote network access.

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

Malformed HTTP is rejected by the HTTP stack before these API handlers. Startup
argument/config errors exit with code 2; initialization or bind errors use code 3.
