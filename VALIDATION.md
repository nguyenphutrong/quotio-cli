# Provider verification

Code revision: `e6ecd3a64b085f919b8930a100395dfd6cf54af8`. Environment: macOS, Rust/Cargo 1.92.0.
Binary: `target/debug/quotio`, SHA-256 `bac14e75c83be11bad7a075d33dc4e879eb2fa352fb7e7b9563699ab2c85aeb1`.

## Automated checks

All Cargo checks used `CARGO_TARGET_DIR=target CARGO_NET_OFFLINE=true`.
The host's default Cargo target path remains unchanged.

| Command | Result |
| --- | --- |
| `cargo fmt --check` | PASS, exit 0 |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS, exit 0 |
| `cargo test` | PASS, 34 tests, exit 0 |
| `cargo run -- --help` | PASS, exit 0 |
| `cargo run -- providers` | PASS, exit 0 |
| `cargo run -- usage --provider mock --format text` | PASS, exit 0 |
| `cargo run -- usage --provider mock --format json` | PASS, exit 0 |

## Live read-only checks

The final binary ran `usage --provider codex --provider amp --format json --timeout 30`
with an empty temporary config. Result: exit 0, successes [('codex', 4), ('amp', 5)],
failures []. Account identities and raw responses were not retained.
This confirms transport and parsing against the installed accounts; no separate
human dashboard comparison was performed.

Antigravity's earlier local-service probe succeeded but that implementation was
replaced at the user's request. It is not evidence for the final direct API adapter.
Direct Google API token use is awaiting explicit approval after automatic review
rejected it. No direct Antigravity live response was obtained.

Factory's endpoint and schema were inspected in first-party code. The local-auth
extraction/network probe was rejected by automatic review. Local decryption is not
implemented; API-key acceptance is not live-verified. The CLI /limits probe did not
produce usable data. Neither path is reported as a live success.

## Claims and evidence

| Claim / risk | Evidence | Result |
| --- | --- | --- |
| Unknown differs from exhausted | Domain, per-provider parsers, JSON assertions | PASS |
| Credit balances have no fabricated quota | Amp balance fixture; zero balance keeps Unknown | PASS |
| Failures preserve other providers | Collection tests and binary mock + missing Factory key, exit 1 | PASS |
| Subprocess protocol is bounded | Codex scripted stdio exchange; oversized line rejection | PASS |
| Cancellation terminates the owned child | Actual PID test with stdin held open | PASS |
| Request metadata and account scope are correct | Loopback Antigravity/Factory HTTP sequence tests | PASS offline |
| HTTP errors are safe and bounded | Auth/429/503, body size, malformed JSON, redirect tests | PASS offline |
| Projectless API fallback works | Antigravity optional lookup and projectless summary regressions | PASS offline |
| Credential file reads reject symlinks/oversize and do not rewrite | Synthetic temporary files only | PASS offline |
| Both direct API providers work on these accounts | Credential permission prerequisite missing | BLOCKED |

## Independent review and fault detection

A separate read-only reviewer identified the optional Antigravity lookup, missing
projectless retry and Amp percentage-token bug. All were corrected. Regression
runs were observed failing before the Amp and Antigravity fixes, then passing.

The reviewer also found a false-positive child-cleanup test. It now holds stdin
open. Temporarily changing kill_on_drop to false made the test fail; restoration
to true passed. Mutation was reverted before this final artifact was built.

## Compatibility and remaining work

Offline tests call only loopback fixture servers and synthetic local programs;
they never require real credentials or remote endpoints. Actual integration was
checked on this macOS installation only. No Linux/Windows/MSRV matrix was run.
Remote provider contracts and Amp text output remain version-sensitive.

No source/config in the main Quotio or CodexBar checkout was modified. There are
no path dependencies, copied reference files, reference binary calls or submodules.
No new dependency was added; existing Tokio features enable process/IO/network tests.

Verdict: implementation and offline checks pass; milestone live acceptance is
BLOCKED for Antigravity and Factory pending the two explicit credential approvals.
TUI and token-refresh/local-Factory-auth work remain outside this completed slice.
