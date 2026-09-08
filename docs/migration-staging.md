# Offline PIV envelope assessment

`migration-inspect` checks one explicitly supplied Swift `.qsv` file. It can save
an immutable assessment receipt. It does **not** stage credentials or perform an
account migration. Every result reports `migration_blocked: true` and exits with
status 2, including when receipt staging succeeds.

```sh
quotio migration-inspect \
  --piv-envelope /absolute/path/to/explicit-envelope.qsv \
  --piv-fingerprint SELECTED_64_HEX_FINGERPRINT
```

Add `--stage-dir /absolute/private/directory` to save a receipt. The directory must
already exist, belong to you and have mode 0700. Paths must be absolute and contain
no symlink components. The command does not create directories or discover files.
Do not supply a PIN, token or private key.

## Supported input and results

The parser recognizes the Swift `YubiKeySecretVault.Envelope` version 1 JSON shape:
`version`, `wrappedKey` and `sealedSecret`. The last two fields contain base64 data.
Recognized wrapped-key sizes are 256, 384 and 512 bytes; the sealed secret must have
at least the 12-byte nonce and 16-byte authentication tag. Input is limited to 1 MiB.
These checks establish structure only, not authenticity or successful decryption.

- `absent`: the final file is missing in an accessible parent directory.
- `unreadable`: the file or parent cannot safely be read, including symlinks,
  non-regular files, hardlinks and oversized input. No missing-file claim is made
  when the parent is inaccessible.
- `unsupported_envelope`: the readable data does not match the supported shape.
- `present_locked_or_unverified`: the shape is recognized, but key access has not
  been attempted. This does not claim that a key is attached, unlocked or correct.

The selected PIV hardware-key fingerprint lives separately in Swift's
`yubikeyPIVVaultFingerprint` preference. It is not embedded in `.qsv` files. This
command accepts that fingerprint only as a caller declaration and records the
binding as unverified. It never reads preferences or accesses Keychain or hardware.
Missing, locked, malformed and unsupported inputs never trigger a fallback to a
software vault or Keychain.

## Reruns and receipts

A receipt contains the assessment, declared fingerprint and, only for a recognized
envelope, a SHA-256 digest of its exact bytes. It contains no path, ciphertext,
wrapped key or plaintext credential. Its filename is the SHA-256 digest of the
receipt JSON. Identical inputs reuse and verify the same receipt without replacing
it. Changed ciphertext or a changed declared fingerprint produces a different
receipt. Original files and older receipts remain unchanged.

On macOS and Linux, new receipts use private temporary files, file sync and an
atomic no-replace rename, then directory sync. Existing symlinks, public files,
hardlinks or different receipt bytes are rejected. A sync failure can report an
uncertain commit; rerunning verifies and syncs the receipt. A process interrupted
before publication can leave a private `.tmp` file; reruns ignore it and never
mistake it for a receipt. Receipt staging on other platforms is not supported.

## Explicit metadata and encrypted-file staging API

The Unix library also provides `assess_mapping` and `stage_mapping`. These are not
yet exposed by CLI flags. The existing command above remains receipt-only.

`assess_mapping(metadata_path, envelope_path, fingerprint, &Mapping)` requires both
absolute paths and explicit `account_id`, `provider`, `source`,
`credential_reference` and `service` declarations. It reads only those two files.
There is no account discovery, preference lookup or proxy-directory scan.

Validation follows the inspected Swift `FileAccountMetadataRepository` payload and
`AccountModels.swift` coding keys:

- The root contains `accounts` and `disabledAccountIDs`.
- Each account has `id`, `provider`, `accountKey`, `displayName` and `source`.
  Optional fields are `credentialReference`, `canDelete` and `isDisabled`.
- Account IDs must be unique. Disabled IDs must be unique and refer to a record.
  Unknown fields, invalid types, control characters and unsupported sources fail.
- The selected record must match every declaration exactly. References are compared
  as metadata only, never opened. A `keychain` reference is not a file path.
- The receipt retains record and repository disabled flags separately. Swift's
  selection policy uses the repository disabled-ID set; the tool does not enable
  an account or resolve differing flags by changing the source.

The current Swift account metadata has **no date fields**. Unknown date fields
are rejected, not interpreted as Unix timestamps. Swift's default JSON date format
elsewhere uses seconds since January 1, 2001 UTC, which is 978307200 seconds after
the Unix epoch. This API does not read those credential payloads or convert dates.
It also does not run Swift's legacy `gemini-cli` cleanup or rewrite metadata.

The envelope filename must equal lowercase
`SHA256(UTF8(service + NUL + account_id)) + ".qsv"`, matching
`YubiKeySecretVault.swift`. This is only a filename candidate. Neither the filename
nor the separately declared fingerprint proves account, service or key binding.
A copied or renamed envelope can pass the structural checks. Every plan remains
blocked and explicitly unverified.

Assessment holds the validated bytes in an opaque `MappingAssessment`. Calling
`plan()` returns only a serializable receipt. Account, provider, service and
credential-reference identifiers appear only as hashes. Source values come from
Swift's fixed enum. Names, account keys, raw paths and ciphertext are not printed.
Hashes are not anonymization; keep receipts private too.

Only an explicit call to `stage_mapping(&assessment, directory)` writes files:

1. `<metadata SHA-256>.metadata.json`, an exact copy of the supplied metadata.
2. `<ciphertext SHA-256>.qsv`, an exact copy of the still-encrypted envelope.
3. `<receipt SHA-256>.json`, published last to mark completed staging.

All copies use the private, atomic, no-replace writer described above. Metadata
copies contain account information and must stay private. Files are limited to
1 MiB each. Descriptor-based reads reject symlinks and hardlinks and check for
changes during reading. Staging uses the assessed snapshot, not a second source
path lookup. It does not promise that the owner app has stopped changing its files.

A restart reassesses the supplied files and verifies already published artifacts.
A partial stage can leave complete artifacts without a receipt; rerunning completes
it without replacing them. Changed source bytes produce new artifacts and receipts.
Changed or unsafe destination bytes fail rather than being overwritten. Original
files remain untouched. PIV encryption is never replaced with a software vault.

### Proposed CLI wiring

Require all mapping arguments together. Call `assess_mapping` for the dry run and
serialize `assessment.plan()`. Call `stage_mapping` only with explicit staging
consent and a supplied private directory. Print only the plan and returned receipt
ID, report zero imported accounts, and retain blocked exit status 2. The mapping
functions are Unix-only. Do not send these files to account intake, source
registration, refresh, activation or hardware APIs.

## Remaining migration work

This is a PIV assessment tool, not a general migration importer. It does not scan
Swift accounts, import provider credentials, register borrowed sources, inspect
browser data or discover `~/.cli-proxy-api`. It makes no network requests and never
refreshes credentials, activates accounts or changes production settings.

Actual migration remains blocked on a PIV-preserving credential access/import
implementation, authenticated account/source/key binding and hardware acceptance.
A receipt does not approve a protection downgrade or authorize later import. Retain the original envelope and its selected-key settings.

Synthetic unit and CLI tests cover state distinctions, blocked migration, private
writes, symlink/hardlink rejection, concurrent publication and stable restarted
reruns. They do not establish hardware, Keychain or live-account acceptance.
