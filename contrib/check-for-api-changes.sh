#!/usr/bin/env bash
#
# Checks the public API of crates, exits with non-zero if there are currently
# changes to the public API not already committed to in the various api/*.txt
# files.

set -ex

REPO_DIR=$(git rev-parse --show-toplevel)
API_DIR="$REPO_DIR/api"

CARGO="cargo +nightly public-api --simplified"
# `sort -n -u` doesn't work for some reason.
SORT="sort --numeric-sort"

# Sort order is effected by locale. See `man sort`.
# > Set LC_ALL=C to get the traditional sort order that uses native byte values.
export LC_ALL=C

main() {
    # cargo public-api uses nightly so the toolchain must be available.
    if ! cargo +nightly --version > /dev/null; then
        echo "script requires a nightly toolchain to be installed (possibly >= nightly-2023-05-24)" >&2
        exit 1
    fi

    generate_api_files_bitcoin

    # These ones have an "alloc" feature we want to check.
    generate_api_files "hashes"
    generate_api_files "units"
    generate_api_files "io"

    check_for_changes
}

generate_api_files_bitcoin() {
    local crate="bitcoin"

    pushd "$REPO_DIR/$crate" > /dev/null

    $CARGO | $SORT | uniq > "$API_DIR/$crate/default-features.txt"
    $CARGO --no-default-features | $SORT | uniq > "$API_DIR/$crate/no-features.txt"
    $CARGO --all-features | $SORT | uniq > "$API_DIR/$crate/all-features.txt"

    popd > /dev/null
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

    $CARGO --no-default-features | $SORT | uniq > "$API_DIR/$crate/no-features.txt"
    $CARGO --no-default-features --features=alloc | $SORT | uniq > "$API_DIR/$crate/alloc-only.txt"
    $CARGO --all-features | $SORT | uniq > "$API_DIR/$crate/all-features.txt"

    popd > /dev/null
}

# Check if there are changes (dirty git index) to the `api/` directory. 
check_for_changes() {
    pushd "$REPO_DIR" > /dev/null
    if [[ $(git status --porcelain api) ]]; then
        git diff --color=always

        echo
        echo "You have introduced changes to the public API, commit the changes to api/ currently in your working directory" >&2
    else
        echo "No changes to the current public API"
    fi
    popd > /dev/null
}

#
# Main script
#
main "$@"
exit 0
