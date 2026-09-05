#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ]; then
    echo 'Developer signing requires macOS.' >&2
    exit 1
fi
if [ "$#" -ne 1 ] || [ ! -f "$1" ] || [ -L "$1" ]; then
    echo 'Usage: scripts/sign-macos.sh <regular binary path>' >&2
    exit 2
fi

identities=$(/usr/bin/security find-identity -v -p codesigning)
requested=${QUOTIO_SIGNING_IDENTITY:-}
if [ -n "$requested" ]; then
    candidates=$(printf '%s\n' "$identities" | awk -v wanted="$requested" '
        /"(Developer ID Application|Apple Development|Mac Developer):/ {
            name=$0; sub(/^[^"]*"/, "", name); sub(/"[^\"]*$/, "", name)
            if ($2 == wanted || name == wanted) print $2
        }')
else
    candidates=$(printf '%s\n' "$identities" | awk '/"Developer ID Application:/ {print $2}')
    if [ -z "$candidates" ]; then
        candidates=$(printf '%s\n' "$identities" | awk '/"(Apple Development|Mac Developer):/ {print $2}')
    fi
fi
count=$(printf '%s\n' "$candidates" | awk 'NF {n++} END {print n+0}')
if [ "$count" -ne 1 ]; then
    echo 'Select exactly one installed signing identity with QUOTIO_SIGNING_IDENTITY (full name or SHA-1).' >&2
    echo 'Run: security find-identity -v -p codesigning' >&2
    exit 1
fi

# Sign a copy so a failed signature leaves the input intact and running processes
# can keep using the old inode. The identifier is independent of Cargo's hash.
binary=$1
case "$binary" in /*) ;; *) binary="$(pwd)/$binary" ;; esac
staged=$(mktemp "${binary}.sign.XXXXXX")
trap 'rm -f "$staged"' EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
cp -p "$binary" "$staged"
/usr/bin/codesign --force --sign "$candidates" --identifier dev.quotio.cli \
    --options runtime --timestamp=none "$staged"
/usr/bin/codesign --verify --strict "$staged"
mv -f "$staged" "$binary"
