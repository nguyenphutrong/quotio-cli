# GitHub, npm and Homebrew releases

Quotio uses one version and one set of binaries for all three channels. The npm
package name is `quotio`; its executable is also `quotio`. The intended tap is
`nguyenphutrong/homebrew-tap`. This code prepares and publishes releases only when
the workflows are explicitly triggered. Adding the workflows does not publish a
package or configure external credentials.

## Supported artifacts

| Platform | Release archive target |
| --- | --- |
| macOS Apple Silicon | `aarch64-apple-darwin` |
| macOS Intel | `x86_64-apple-darwin` |
| Linux x64 | `x86_64-unknown-linux-gnu` |

Linux binaries are built on Ubuntu 24.04 and require glibc 2.39 or newer. They do
not support the saved-account Keychain vault. Windows and Linux ARM are not
included in this first release matrix.

GitHub releases contain three `.tar.gz` archives, an npm `.tgz`, a Homebrew formula
and `SHA256SUMS`. Each native archive contains the executable, MIT license and
dependency notices. The npm package bundles all three executables: it needs no
Rust compiler, install script or runtime download. This makes the npm download
larger than a single-platform archive.

## Configure once

Create a GitHub environment named `release`. Restrict which branches can deploy
and configure its approval policy to match your release process. Add these secrets
there; never put their values in Git, workflow inputs or chat:

| Secret | Purpose |
| --- | --- |
| `MACOS_CERTIFICATE_P12` | Base64-encoded Developer ID Application certificate and private key |
| `MACOS_CERTIFICATE_PASSWORD` | Password protecting that certificate export |
| `NOTARY_PRIVATE_KEY` | Apple notarization API private key, in PEM format |
| `NOTARY_KEY_ID` | Associated Apple API key ID |
| `NOTARY_ISSUER_ID` | Associated Apple API issuer ID |
| `HOMEBREW_TAP_TOKEN` | Token restricted to contents read/write on the tap repository |

Set the environment variable `HOMEBREW_TAP_REPOSITORY` in GitHub Actions to
`nguyenphutrong/homebrew-tap`. The publishing workflow writes only
`Formula/quotio.rb` or `Formula/quotio-beta.rb`; other tap entries are preserved.
Forks must change this variable and configure their own secrets and npm ownership.

In npm package settings, configure a GitHub trusted publisher for:

- Repository owner: `nguyenphutrong`
- Repository: `quotio-cli`
- Workflow filename: `publish-release.yml`
- Environment: `release`
- Allowed action: `npm publish`

The workflow uses OIDC (`id-token: write`), not a stored npm token. See npm's
[trusted publishing instructions](https://docs.npmjs.com/trusted-publishers/).
You need publishing rights to the name `quotio`; a registry lookup returning 404
does not reserve that name.

For the first release, if npm cannot configure trust before the package exists,
bootstrap with the **actual prepared tarball** from the GitHub draft release:
verify its checksum, run `npm login` locally, then `npm publish <tarball> --access
public --tag next` for a prerelease (`latest` for stable). Configure trust before
publishing the GitHub release. Do not publish an empty placeholder at the intended
version. The workflow recognizes an already-published tarball only when its SHA-512
integrity matches exactly.

## Prepare and publish

1. Update the version in `Cargo.toml` and `Cargo.lock`, verify and commit it.
   Supported versions are `X.Y.Z`, `X.Y.Z-alpha.N`, `X.Y.Z-beta.N`, or `X.Y.Z-rc.N`.
   npm's version is generated from the release input; its source package is a
   template, not a separately versioned product.
2. Push the intended commit and run **Prepare release** (`release.yml`) on that
   commit/branch, with the matching version without `v`.
3. Each target runs fmt, Clippy and offline tests, builds its binary, and checks
   the executable version. macOS binaries must pass Developer ID signing and
   notarization before their archives can be uploaded. The certificate/keychain
   files exist only on the temporary runner and are removed afterward.
4. The final job assembles the npm package and checksum-pinned Homebrew formula,
   then creates a **draft** GitHub release pointing to the exact workflow commit.
   It does not overwrite an existing release/tag automatically. To change code,
   prepare a new version rather than replacing published assets.
5. Download and verify the draft artifacts on the supported machines. Complete the
   [live acceptance checks](operations.md#release-acceptance). The ZIP submitted to
   Apple is a notarization transport; the distributed raw CLI relies on online
   Gatekeeper ticket lookup, not a stapled installer.
6. Publish the draft in GitHub. **Publish package channels** publishes the verified
   npm tarball, then updates the existing tap through GitHub's contents API.

| Version | npm tag | Homebrew formula |
| --- | --- | --- |
| `0.1.0` | `latest` | `quotio` |
| `0.1.0-beta.1` (also alpha/rc) | `next` | `quotio-beta` |

Install commands after publication:

```sh
npm install -g quotio
npm install -g quotio@next
brew install nguyenphutrong/tap/quotio
brew install nguyenphutrong/tap/quotio-beta
```

Choose one installation for the `quotio` command in your PATH. The Swift app can
bundle the verified platform-specific GitHub binary without requiring npm or brew.

## Retry and limitations

If npm succeeds but the tap update fails, fix the tap credentials and rerun the
failed workflow. An identical npm tarball is skipped; different bytes for an
existing npm version stop publishing. An unchanged tap formula is also skipped.
GitHub publication, npm and the tap are separate services: publishing is not an
atomic transaction across all three. Review all job outcomes before announcing
that every channel is available. Publish versions in order; publishing an older
release later can move the npm tag and tap formula backward.

Workflow lint, local tarball installation and fixture tests validate packaging.
They do not prove hosted signing, notarization, npm ownership, OIDC configuration,
or a live Homebrew install. Those require the external configuration above.

References: [GitHub runner platforms](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
[Homebrew formula format](https://docs.brew.sh/Formula-Cookbook).
