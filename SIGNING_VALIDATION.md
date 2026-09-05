# Developer signing verification

Signing identifier: `dev.quotio.cli`.
Signing identity and Team ID are discovered from the builder's Keychain or selected
through `QUOTIO_SIGNING_IDENTITY`. No personal certificate, Team ID or fingerprint
is pinned in project code/configuration or recorded in this report.

## Validation

The current identifier change passed these checks:

- Shell syntax validation for all signing scripts.
- Signed debug and release builds using the installed developer identity.
- Strict codesign verification of both final binaries.
- Comparison of the two designated requirements, without persisting signer details.
- A cargo-run help smoke test through the signing runner.
- An audit of tracked files against locally installed signing identities and Team IDs.

The previous workflow also passed 60 offline tests, rejected an invalid explicit
identity without modifying/executing the input binary, and preserved clean JSON
stdout. Runtime Rust code is unchanged by this identifier/configuration update.

## Public forks and existing accounts

Each fork builds with its own installed developer certificate. Auto-selection
requires one Developer ID Application identity, or one development identity if no
Developer ID identity exists. Ambiguous installations require the environment
override. There is no ad-hoc fallback or hard-coded developer team.

The existing Keychain storage service `app.quotio.cli.accounts.v1` is retained to
preserve saved accounts. It is not the code-signing identifier. The identifier
change may require one explicit Keychain authorization for the newly signed build;
no vault contents or ACLs are rewritten by the signing workflow.

Signing here is for local use, with hardened runtime and no added entitlements.
Timestamping and notarization are separate distribution steps.
