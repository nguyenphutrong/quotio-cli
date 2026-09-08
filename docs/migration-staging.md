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

## Remaining migration work

This is a PIV assessment tool, not a general migration importer. It does not scan
Swift accounts, import provider credentials, register borrowed sources, inspect
browser data or discover `~/.cli-proxy-api`. It makes no network requests and never
refreshes credentials, activates accounts or changes production settings.

Actual migration remains blocked on a PIV-preserving credential access/import
implementation, verified key-to-envelope binding, account/source mapping and
hardware acceptance. A receipt does not approve a protection downgrade or authorize
later import. Retain the original envelope and its selected-key settings.

Synthetic unit and CLI tests cover state distinctions, blocked migration, private
writes, symlink/hardlink rejection, concurrent publication and stable restarted
reruns. They do not establish hardware, Keychain or live-account acceptance.
