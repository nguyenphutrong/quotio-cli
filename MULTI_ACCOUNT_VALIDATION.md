# Codex multi-account verification

Code revisions: 73ac765 (collection), d78c5e0 (Keychain query/exit policy).
Environment: macOS, Rust/Cargo 1.92.0, CARGO_TARGET_DIR=target.

- cargo test --offline: PASS, 60 tests, one opt-in native smoke test skipped.
- cargo clippy --offline --all-targets --all-features -- -D warnings: PASS.
- cargo build --offline: PASS.
- cargo fmt --check and git diff --check: checked before documentation commit.

## Behavior covered offline

Default Codex selection includes local plus all saved accounts, including inactive
accounts. With no installed CLI, saved accounts stand alone. Explicit saved ID
selects only that account; local bypasses vault discovery. Wrong-provider/missing
ID and invalid selector flag combinations are rejected.

Reports retain account_ref on success, timeout and failure. Distinct identities
remain separate. Reconciliation prefers a saved snapshot for an exact account ID
or one unambiguous matching personal-plan email. Business/unknown-plan identities
are not merged by email. Unknown usage and absent windows keep their existing meaning.

A separate reviewer found global refresh locking could block other accounts. A
regression first failed with account A stalled and B waiting. Per-account refresh
locking fixed it. Tests now cover both healthy and expired B, and concurrent reads
of the same expired account perform one refresh. Rotations still persist before
quota retry, and uncertain refresh requests are not replayed.

## Live evidence and Keychain limitation

A normal local-plus-saved Codex request completed with exit 0 in 6 seconds and two
successful results: one local, one saved. No identities or credentials were retained.
That run used the multi-account implementation before the subsequent no-UI fix.

An earlier request exceeded 35 seconds. A bounded account-list diagnostic found the
process waiting inside SecItemCopyMatching. The user reported repeated Keychain
confidential-information prompts. codesign inspection confirmed an ad-hoc linker
signature and no TeamIdentifier, rather than stable signed application identity.

The final binary requests kSecUseAuthenticationUIFail for usage vault reads/writes;
explicit account-management commands remain interactive. The native constant was
verified in the installed Security.framework SDK and the query policy has an offline
test. No ACL or process-global Keychain interaction policy was changed.

Final live check with --timeout 8 returned in 10.9 seconds: local success plus
credential_storage failure for saved accounts, exit 1. It did not hang indefinitely.
This proves bounded command exit and local-result preservation; it is not a claim
that saved Keychain access was authorized for the final rebuilt binary. The user
must authorize the build through an explicit account command if macOS requires it.

The native Keychain operation may still be in progress when the command deadline
expires. Runtime shutdown does not wait forever for it. Successful writes are
awaited; write outcome after timeout/cancellation must be treated as uncertain.

No provider login, cookie extraction, or credential migration was performed for
this change. Production signing remains a separate packaging concern.
