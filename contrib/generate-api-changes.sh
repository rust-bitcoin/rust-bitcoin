#!/usr/bin/env bash
#
# Creates a temporary branch with an api-changes patch for each commit back to master.

set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)
API_DIR="$REPO_DIR/api"

NIGHTLY=$(cat nightly-version)
# Our docs have broken intra doc links if all features are not enabled.
RUSTDOCFLAGS="-A rustdoc::broken_intra_doc_links"

# `sort -n -u` doesn't work for some reason.
SORT="sort --numeric-sort"

# Get temporary branch name.
TEMP_BRANCH=$(mktemp -u temp-branch-XXXXXX)

# Sort order is effected by locale. See `man sort`.
# > Set LC_ALL=C to get the traditional sort order that uses native byte values.
export LC_ALL=C

main() {
    need_nightly

    # Create a new temporary branch
    current_branch=$(git branch --show-current)

    # Find commits on current branch that are not in master
    commits=$(git rev-list master.."$current_branch")

    git checkout -b "$TEMP_BRANCH" master || exit 1

    mkdir "api"
    for crate in base58 bitcoin hashes io units; do
        mkdir "api/$crate"
    done

    # Reverse the commit list to process from oldest to newest
    commits=$(echo "$commits" | tac)

    # Iterate through each commit, checking API before cherry picking the commit.
    for commit in $commits; do
        create_api_patch
        git cherry-pick "$commit"
    done

    # And do the final check.
    create_api_patch
}

create_api_patch() {
    check_api
    commit_changes
}

check_api() {
    generate_api_files_base58
    generate_api_files_bitcoin

    # These ones have an "alloc" feature we want to check.
    generate_api_files "hashes"
    generate_api_files "io"
    generate_api_files "units"
}

commit_changes() {
    pushd "$REPO_DIR" > /dev/null

    if [[ $(git status --porcelain api) ]]; then
        git add -A
        git commit -m "api: Run check-for-api-changes.sh" -n
    fi

    popd > /dev/null
}

generate_api_files_bitcoin() {
    local crate="bitcoin"
    pushd "$REPO_DIR/$crate" > /dev/null

    run_cargo | $SORT | uniq > "$API_DIR/$crate/default-features.txt"
    run_cargo --no-default-features | $SORT | uniq > "$API_DIR/$crate/no-features.txt"
    run_cargo_all_features | $SORT | uniq > "$API_DIR/$crate/all-features.txt"

    popd > /dev/null
}

generate_api_files_base58() {
    local crate="base58"
    pushd "$REPO_DIR/$crate" > /dev/null

    run_cargo | $SORT | uniq > "$API_DIR/$crate/default-features.txt"
    run_cargo --no-default-features | $SORT | uniq > "$API_DIR/$crate/no-features.txt"

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

    run_cargo --no-default-features | $SORT | uniq > "$API_DIR/$crate/no-features.txt"
    run_cargo --no-default-features --features=alloc | $SORT | uniq > "$API_DIR/$crate/alloc-only.txt"
    run_cargo_all_features | $SORT | uniq > "$API_DIR/$crate/all-features.txt"

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

err() {
    echo "$1" >&2
    exit 1
}

#
# Main script
#
main "$@"
exit 0
