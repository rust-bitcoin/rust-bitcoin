#!/usr/bin/env bash
#
# Checks the public API of crates, exits with non-zero if there are currently
# changes to the public API not already committed to in the various api/*.txt
# files.

set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)
API_DIR="$REPO_DIR/api"

NIGHTLY=$(cat nightly-version)
# Our docs have broken intra doc links if all features are not enabled.
RUSTDOCFLAGS="-A rustdoc::broken_intra_doc_links"

# `sort -n -u` doesn't work for some reason.
SORT="sort --numeric-sort"

# Sort order is effected by locale. See `man sort`.
# > Set LC_ALL=C to get the traditional sort order that uses native byte values.
export LC_ALL=C

main() {
    need_nightly
    need_cargo_public_api

    generate_api_files "hashes"
    generate_api_files "io"
    generate_api_files "primitives"
    generate_api_files "units"

    check_for_changes
}

# Uses `CARGO` to generate API files in the specified crate.
#
# Files:
#
# - no-features.txt
# - alloc-only.txt
# - all-features.txt
generate_api_files() {
    local crate=$1
    pushd "$REPO_DIR/$crate" > /dev/null

    run_cargo --no-default-features | $SORT | uniq > "$API_DIR/$crate/no-features.txt"
    run_cargo --no-default-features --features=alloc | $SORT | uniq > "$API_DIR/$crate/alloc-only.txt"
    run_cargo_all_features | $SORT | uniq > "$API_DIR/$crate/all-features.txt"

    popd > /dev/null
}

# Check if there are changes (dirty git index) to the `api/` directory.
check_for_changes() {
    pushd "$REPO_DIR" > /dev/null

    if [[ $(git status --porcelain api) ]]; then
        git diff --color=always
        echo
        err "You have introduced changes to the public API, commit the changes to api/ currently in your working directory"
    else
        echo "No changes to the current public API"
    fi

    popd > /dev/null
}

# Run cargo when --all-features is not used.
run_cargo() {
    RUSTDOCFLAGS="$RUSTDOCFLAGS" cargo +"$NIGHTLY" public-api --simplified "$@"
}

# Run cargo with all features enabled.
run_cargo_all_features() {
    cargo +"$NIGHTLY" public-api --simplified --all-features
}

need_nightly() {
    cargo_ver=$(cargo +"$NIGHTLY" --version)
    if echo "$cargo_ver" | grep -q -v nightly; then
        err "Need a nightly compiler; have $cargo_ver"
    fi
}

need_cargo_public_api() {
    if command -v cargo-public-api > /dev/null; then
        return
    fi
    err "cargo-public-api is not installed; please run 'cargo +nightly install cargo-public-api --locked'"
}

err() {
    echo "$1" >&2
    exit 1
}

#
# Main script
#
main "$@"
exit 0
