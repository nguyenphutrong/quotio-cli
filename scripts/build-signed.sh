#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
profile=debug
for argument in "$@"; do
    case "$argument" in
        --release) profile=release ;;
        --offline|--locked) ;;
        *) echo 'Usage: scripts/build-signed.sh [--release] [--offline] [--locked]' >&2; exit 2 ;;
    esac
done
cd "$project_dir"
# Keep this product's signed outputs in the project, independent of shared caches.
cargo build --target-dir "$project_dir/target" --bin quotio "$@"
"$script_dir/sign-macos.sh" "$project_dir/target/$profile/quotio"
printf 'Signed binary: %s\n' "$project_dir/target/$profile/quotio"
