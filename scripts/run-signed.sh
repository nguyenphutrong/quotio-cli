#!/bin/sh
set -eu
if [ "$#" -eq 0 ]; then
    echo 'Missing executable for Cargo runner.' >&2
    exit 2
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# Cargo also calls its runner for tests; test harnesses are not the product CLI.
if [ "$(basename -- "$1")" = quotio ]; then
    "$script_dir/sign-macos.sh" "$1"
fi
exec "$@"
