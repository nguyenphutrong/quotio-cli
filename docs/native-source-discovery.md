# Native source picker

Use `POST /v1/account-sources/discover` with a management bearer token. This is an explicit user action, not a startup scan. Select a `provider` and one `kind` from that provider's `source_references` capability.

```json
{"provider":"copilot","kind":"copilot_native","location":"apps","inspect":true}
```

Without `inspect: true`, the endpoint does not read native data. Fixed-location kinds return registration choices marked `not_checked`: Codex, Claude Code, Kiro, Factory, Devin desktop, Antigravity, Amp and Cursor. These are descriptors, not evidence that files or Keychain entries exist. Their `source` objects use the existing registration contract.

Opt-in inspection supports:

- Grok: entries in the standard native auth file.
- Copilot: exactly one selected `apps` or `hosts` file. `location` is required. `gh_keychain` enumeration returns `unsupported` without accessing Keychain.
- Quotio custom providers: one required `production` or `development` preferences domain, filtered to the selected `clinepass` or `zai` provider. Disabled records are omitted. Other custom-provider types are not supported.

Exact-entry candidates have generic numbered labels and opaque `source` references. Native entry keys, record UUIDs, names, paths, tokens and credential JSON are not returned. This also protects against a token planted in an entry key or display name. The backend retains only native references, not copied credentials.

Pass a candidate's complete `source` object to the existing `POST /v1/account-sources`, with an `Idempotency-Key`. Poll the returned operation for `result.account_id`. Registration re-reads and validates the source; discovery does not prove credentials are usable. Existing caller-supplied registration inputs remain supported.

Opaque references last 600 seconds, are local to one running server, and are not persisted. Inspect again after expiry or restart. At most 256 live references can be held; further inspection returns `account_busy` until older references expire. Use account and operation IDs for subsequent work, rather than retaining discovery references.

## Status

- `not_checked`: no native read occurred.
- `checked`: the selected metadata was read; the candidate list may be empty.
- `available` (candidate): a matching metadata entry exists. Credentials may still be expired, invalid or protected.
- `unavailable`: the selected native source was not found.
- `unreadable`: unsafe file, invalid data, access failure, or inspection limit exceeded. Errors do not contain native paths or contents.
- `unsupported`: this platform or source inspection is not implemented.

Each source is limited to 1 MiB and 64 entries. Over-limit sources are rejected rather than silently truncated. File inspection rejects symlinks in both parent and leaf components and does not open special files for blocking reads. Fixed-location inspection (`inspect: true`) is unsupported; the picker can offer the descriptor and let explicit registration validate it.

No inspection reads `~/.cli-proxy-api`, browser cookies or other providers. It performs no network requests, login, refresh, envelope decryption, or native writes. Custom-provider preferences are read only after explicit domain/provider selection. Real Keychain presence and permission prompts are not tested by static choices.

Tests inject temporary native files, synthetic preferences and an in-memory vault. REST tests cover discovery through registration and account-ID retrieval for Grok, Copilot and ClinePass, including secrets planted in keys and labels. These are not live-provider or real-Keychain acceptance tests.
