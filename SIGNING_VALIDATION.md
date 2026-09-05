# Developer signing verification

Workflow revision: e30d4bd. Verified on macOS, 2026-09-05.

Identity: Developer ID Application: Developer (<selected-team>).
Identifier: app.quotio.cli. TeamIdentifier: <selected-team>.
The selected team also matches the main Swift Quotio local development config.
Private keys were not exported. No account-vault credentials or ACLs were changed.

## Checks

- Shell syntax: PASS for all three scripts.
- scripts/build-signed.sh --offline --locked: PASS, debug artifact signed.
- scripts/build-signed.sh --release --offline --locked: PASS, release artifact signed.
- codesign --verify --strict: PASS for both final artifacts.
- Debug/release CDHashes differ; designated requirements are identical: PASS.
- Release validated against the debug inline requirement using codesign -R: PASS.
- cargo run --offline -- --help: PASS via signing runner.
- cargo run mock JSON smoke: PASS, JSON stdout remains clean; signing output is stderr.
- Invalid explicit identity: rejected before execution; input binary SHA-256 unchanged.
- Non-product runner path preserves arguments and does not sign test harnesses: PASS.
- cargo test --offline: 60 passed, one opt-in native Keychain test skipped.

Cargo test may relink the product binary, so final signing verification ran after
cargo run re-signed debug. Plain cargo build/test is not a post-link signing hook.
The runner signs before cargo run; the build script guarantees signed build output.

## Final artifacts

| Path | SHA-256 |
| --- | --- |
| `target/debug/quotio` | `376de2aee498830bef98b8f696fcee0640304ef4d022487d244cb10603af68c8` |
| `target/release/quotio` | `a1e7c0c2bea5d79c97361d1d4aed4734aa1f760c92fbe0df6707cac99e7863a6` |

Shared designated requirement:

```text
identifier "app.quotio.cli" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = <selected-team>
```

## Scope and remaining authorization

This is local Developer ID signing with hardened runtime and no added entitlements.
Timestamping/notarization/distribution were not performed. Signing selection is
portable: use the sole Developer ID identity, otherwise a sole development identity,
or require QUOTIO_SIGNING_IDENTITY for an ambiguous installation.

The previous ad-hoc vault trust may require one explicit authorization for the new
signed identity. Run cargo run -- accounts list when ready to grant access. This
verification establishes stable code identity across distinct builds, not that the
user has already approved the new identity on an existing Keychain item.
