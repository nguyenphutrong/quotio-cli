# Security remediation verification

Source/workflow revision: cd5612d. Date: 2026-09-05.

## Changes

- 8b505a3: time 0.3.47, patched for RUSTSEC-2026-0009 / CVE-2026-25727;
  input bound before RFC 2822 parsing, with deep/malformed Retry-After tests.
- 5b582cc: MIT LICENSE and SPDX package metadata.
- 4629ba4: local credential/signing-material ignore rules and template exceptions.
- 7ac72ce: redacted Gitleaks history scan and OSV lockfile advisory checks in CI.
- cd5612d: pinned continuous zizmor audit, with read-only permissions and no SARIF writes.

No personal names, emails, Team IDs or signing fingerprints were added as defaults.
No real provider credentials, OAuth flows or account vault contents were used.

## Verification

- Rust tests: 61 passed, one opt-in native Keychain test skipped.
- cargo fmt --check: PASS.
- cargo clippy --offline --all-targets --all-features -- -D warnings: PASS.
- HTTP regression: deep nested and malformed Retry-After rejected; normal date accepted.
- Advisory-checker unit tests: 3 passed, including private-registry non-disclosure.
- OSV query: 206 locked crates.io versions, zero advisory findings after update.
- Ignore rules: private local file names ignored, sanitized examples/Cargo.lock preserved.
- actionlint: PASS for both workflows.
- zizmor 1.30.0 --offline --strict-collection: PASS, zero findings.
- zizmor 1.30.0 --offline --persona=auditor: PASS, zero findings.

The initial auditor pass found unnamed jobs; names were added and both audit modes
then passed. No inline suppressions were introduced. Action commit pins and the
Gitleaks Linux archive checksum were resolved from official upstream releases.

The first patched dependency build needed a download for missing cached crates;
subsequent Rust tests ran offline. Python unit tests mock the network. The actual
OSV check is online and sends package coordinates only; errors fail closed.

## Deployment boundary

GitHub-hosted execution has not occurred because the workflows have not been pushed.
Local actionlint/zizmor checks do not claim a successful remote CI run. The project
license is applied; third-party license/source notices are still required before
publishing compiled binaries. No notarization, upload or push was performed.

Final signed debug/release builds and strict signature/mock JSON smoke checks: PASS.
Final Gitleaks history and tracked-snapshot scans: zero findings.
