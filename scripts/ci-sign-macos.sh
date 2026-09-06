#!/bin/bash
set -euo pipefail
stage=initialization
trap 'echo "Release signing failed during: $stage" >&2' ERR
# Called only on an ephemeral release runner. No certificate is stored in Git.
: "${MACOS_CERTIFICATE_P12:?Set the Developer ID certificate secret}"
: "${MACOS_CERTIFICATE_PASSWORD:?Set the certificate password secret}"
: "${NOTARY_PRIVATE_KEY:?Set the notarization API key secret}"
: "${NOTARY_KEY_ID:?Set the notarization key ID}"
: "${NOTARY_ISSUER_ID:?Set the notarization issuer ID}"
binary=${1:?Pass the release binary}
staging=$(mktemp -d)
keychain="$staging/release.keychain-db"
original_keychains=()
while IFS= read -r existing; do
  original_keychains+=("$existing")
done < <(security list-keychains -d user | python3 -c 'import shlex,sys; print("\n".join(shlex.split(sys.stdin.read())))')
cleanup() {
  if [ "${#original_keychains[@]}" -gt 0 ]; then
    security list-keychains -d user -s "${original_keychains[@]}" >/dev/null 2>&1 || true
  fi
  security delete-keychain "$keychain" >/dev/null 2>&1 || true
  rm -rf "$staging"
}
trap cleanup EXIT
password=$(openssl rand -hex 32)
printf '%s' "$MACOS_CERTIFICATE_P12" | base64 --decode > "$staging/certificate.p12"
printf '%s' "$NOTARY_PRIVATE_KEY" > "$staging/notary.p8"
chmod 600 "$staging/certificate.p12" "$staging/notary.p8"
stage="create keychain"
security create-keychain -p "$password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$password" "$keychain"
stage="import identity"
security import "$staging/certificate.p12" -k "$keychain" -P "$MACOS_CERTIFICATE_PASSWORD" -T /usr/bin/codesign >/dev/null
stage="register keychain search path"
security list-keychains -d user -s "$keychain" "${original_keychains[@]}"
stage="grant signing access"
security set-key-partition-list -S apple-tool:,apple: -s -k "$password" "$keychain" >/dev/null
stage="find identity"
identity=$(security find-identity -v -p codesigning "$keychain" | awk '/"Developer ID Application:/ {print $2}')
if [ "$(printf '%s\n' "$identity" | awk 'NF {n++} END {print n+0}')" -ne 1 ]; then
  echo 'Release signing requires exactly one Developer ID Application identity.' >&2
  exit 1
fi
stage="codesign"
codesign --force --keychain "$keychain" --sign "$identity" --identifier dev.quotio.cli --options runtime --timestamp "$binary"
codesign --verify --strict "$binary"
ditto -c -k "$binary" "$staging/quotio.zip"
stage="notarize"
xcrun notarytool submit "$staging/quotio.zip" --key "$staging/notary.p8" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER_ID" --wait --output-format json > "$staging/result.json"
python3 - "$staging/result.json" <<'PY'
import json, sys
if json.load(open(sys.argv[1])).get('status') != 'Accepted':
    raise SystemExit('Apple did not accept the notarization submission.')
print('Notarization accepted.')
PY
