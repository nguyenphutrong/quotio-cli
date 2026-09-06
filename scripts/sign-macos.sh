#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ]; then
    echo 'Developer signing requires macOS.' >&2
    exit 1
fi
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || [ ! -f "$1" ] || [ -L "$1" ]; then
    echo 'Usage: scripts/sign-macos.sh <regular binary path> [--distribution]' >&2
    exit 2
fi

distribution=false
if [ "$#" -eq 2 ]; then
    if [ "$2" != --distribution ]; then
        echo 'Only --distribution is supported after the binary path.' >&2
        exit 2
    fi
    distribution=true
fi
identities=$(/usr/bin/security find-identity -v -p codesigning)
if [ "$distribution" = true ]; then
    identities=$(printf '%s\n' "$identities" | awk '/"Developer ID Application:/')
fi
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
timestamp=--timestamp=none
if [ "$distribution" = true ]; then timestamp=--timestamp; fi
/usr/bin/codesign --force --sign "$candidates" --identifier dev.quotio.cli \
    --options runtime "$timestamp" "$staged"
/usr/bin/codesign --verify --strict "$staged"
mv -f "$staged" "$binary"
