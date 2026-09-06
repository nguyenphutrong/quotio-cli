#!/bin/sh
set -eu
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH='' cd -- "$script_dir/.." && pwd)
profile=debug
distribution=false
build_args=

for argument in "$@"; do
    case "$argument" in
        --release) profile=release; build_args="$build_args --release" ;;
        --distribution) distribution=true ;;
        --offline|--locked) build_args="$build_args $argument" ;;
        *) echo 'Usage: scripts/build-signed.sh [--release] [--offline] [--locked] [--distribution]' >&2; exit 2 ;;
    esac
done
cd "$project_dir"
# Keep this product's signed outputs in the project, independent of shared caches.
if [ "$distribution" = true ] && [ "$profile" != release ]; then
    echo '--distribution requires --release.' >&2
    exit 2
fi
# build_args contains only the literal flags accepted above.
# shellcheck disable=SC2086
cargo build --target-dir "$project_dir/target" --bin quotio $build_args
if [ "$distribution" = true ]; then
    "$script_dir/sign-macos.sh" "$project_dir/target/$profile/quotio" --distribution
else
    "$script_dir/sign-macos.sh" "$project_dir/target/$profile/quotio"
fi
printf 'Signed binary: %s\n' "$project_dir/target/$profile/quotio"
