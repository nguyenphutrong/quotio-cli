# Pre-public security and license review

Reviewed revision: 9ff9d9d98417e10d496cfcbf17cbc1052c9d7f3a.
Date: 2026-09-05. This is an audit report, not a claim of vulnerability-free software.
No push, real credential access, login or Keychain vault access was performed.

## Verdict

Fix the known `time` dependency vulnerability and select/apply a project license
before treating this revision as ready for public use. No leaked credentials were
found by the scans below. The independent runtime source review did not demonstrate
a high/medium credential-disclosure or authentication-bypass issue.

## Actionable findings

### 1. Known dependency DoS in an input parser used by this CLI

Priority: fix before public release. Upstream severity: medium, CVSS 6.8.

`Cargo.toml:14` pins time 0.3.44. [RUSTSEC-2026-0009](https://rustsec.org/advisories/RUSTSEC-2026-0009.html)
/CVE-2026-25727 describes stack exhaustion in RFC 2822 parsing, fixed in 0.3.47.
`src/providers/http.rs:42` parses the remote Retry-After header with precisely that
parser. The body-size limit below it does not constrain this header parse. Ordinary
valid dates are unaffected; malicious nested obsolete syntax can exhaust the stack.

Recommended change: update time to at least 0.3.47, regenerate Cargo.lock and add a
bounded malformed/deep-comment Retry-After regression. The patched release declares
Rust 1.88.0, compatible with this project's declared minimum. Rerun fmt, Clippy,
unit/HTTP tests and the dependency scan. Do not rely on the async timeout to catch
synchronous stack exhaustion. No crash PoC was run against live providers.

The OSV query returned two advisory IDs for this one issue (GHSA-r6v5-fh4h-64xc and
RUSTSEC-2026-0009), not two separate vulnerabilities.

### 2. Missing project license

There is no root LICENSE and Cargo.toml has no package.license. Publishing source
without a license does not provide the clear reuse/fork permissions intended here.
Choose the license, add the full text and set the SPDX identifier before release.

### 3. Accidental-secret prevention is minimal

`.gitignore:1` excludes only target. No real .env/key/certificate was found tracked,
but a future local credential/debug file could be staged unintentionally. Add
appropriate ignores for local environment files and private signing material, plus
CI secret scanning and dependency advisory checks. Keep sanitized examples usable.
This is preventive hardening, not evidence that a secret has leaked.

## Completed evidence

| Check | Scope | Result |
| --- | --- | --- |
| Gitleaks v8.30.1, published binary checksum verified | Git history with --log-opts=--all, redacted report | 0 findings |
| Gitleaks v8.30.1 directory scan | Clean archive of tracked HEAD files | 0 findings |
| Custom privacy/private-key scan | All 273 Git objects, including internal tree refs | 0 matches for private-key patterns and prior personal-data identifiers |
| Commit identity check | All reachable commits | Generic contributor identity only |
| git fsck --full --no-reflogs | Object integrity | PASS |
| OSV querybatch | 206 registry package versions from Cargo.lock, all target entries | One unique time advisory |
| cargo metadata --offline --locked --filter-platform aarch64-apple-darwin | 157 packages, including root | License expressions inspected |
| Independent OAuth source review and synthetic OAuth tests | Account, HTTP, output, subprocess and collection paths | No demonstrated high/medium runtime issue; 4 OAuth tests passed |

Gitleaks was downloaded from its official GitHub release into temporary storage,
not installed globally. Only public package names/versions were sent to OSV, not
source code, repository credentials or user account data. Reports were redacted.
No cargo-audit/cargo-deny binary was available; this used OSV advisory matching and
manifest license inspection instead. Unknown/unreported vulnerabilities remain possible.

## Runtime safeguards and residual limits

Verified in source: fixed HTTPS provider destinations, redirects disabled by the
executable's clients, stdin-only secret input with size limits, fixed safe error
messages, no credential Debug output, control-character filtering in terminal
output, bounded HTTP bodies/subprocess output, and native atomic Keychain updates.

OAuth uses loopback, random state, PKCE, nonce, issuer/audience checks and refresh
identity consistency. ID-token identity is trusted from the fixed TLS token endpoint,
not accepted from arbitrary external JWT input. If configurable endpoints or ID-token
import are added, reassess signature-validation requirements.

A refresh can rotate a token remotely before cancellation/crash prevents local
persistence (`src/accounts/service.rs:221`, `src/fetch.rs:57`). Reconnection may be
needed. This is an availability limit, not a demonstrated disclosure. Avoid claiming
fully cancellation-safe refresh or guaranteed no-write behavior on native timeout.

This audit did not retest live accounts, macOS prompts, notarization, or platform
matrices. Private provider endpoints and text formats remain compatibility risks.
A newly generated Codex internal tree ref was present, but its object content was
included in the privacy scan; no prior personal data was found.

## License recommendation

Recommend [MIT](https://opensource.org/license/mit): short, permissive and aligned
with the MIT licenses inspected in both reference projects (Quotio Swift and
CodexBar). It permits modification, redistribution and commercial use while
requiring preservation of the copyright/license notice. It does not require forks
to publish their changes. It is not a license for provider services or trademarks.

Suggested project attribution, if accurate for the contributors:
`Copyright (c) 2026 Quotio contributors`. This avoids publishing a personal email
or signing team. Set `license = "MIT"` in package metadata after choosing it.

Alternative: [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) if an explicit
patent grant and patent-termination terms matter more than minimal license text.
MIT OR Apache-2.0 is common for reusable Rust libraries, but is extra choice/notice
work for this small CLI and not necessary for the stated goal.

Reference licenses were inspected read-only. They do not automatically license
our independent implementation. If actual source portions are copied in future,
retain the relevant original notices rather than removing third-party attribution.

## Dependency notices for binary distribution

Most resolved macOS dependency licenses are permissive, but not all are MIT:

- option-ext 0.2.0: MPL-2.0. [Mozilla's FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/)
  explains file-level scope and source-availability obligations for distributed
  executables. This does not by itself require licensing unrelated CLI files as MPL.
- webpki-roots 1.0.9: CDLA-Permissive-2.0 certificate data.
- Other expressions include Unicode-3.0, ISC, BSD-3-Clause, MIT and Apache-2.0.

Before publishing binaries, generate/ship third-party notices and the required
license/source references for the exact locked dependency set. A root MIT file
alone does not replace dependency notices. No dependency source was modified here.

## Next changes proposed

1. Patch time and test the affected header path.
2. Apply the chosen MIT license and package metadata.
3. Add local-secret ignores and security/advisory automation.
4. Prepare third-party notices if distributing signed binaries.

This review changes documentation only. Runtime fixes and license application
remain proposed, and the repository has not been pushed.
