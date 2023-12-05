#!/usr/bin/env bash
#
# Check that we can publish crates in their current form if there are changes on top of the tip of
# master that imply that we are about to do a release.

set -ex

main () {
    for crate in "internals" "hashes" "bitcoin"; do
        if release_changes $crate; then
            echo "$crate has changes implying this is a release PR, checking if we can publish ..."

            # Check if there is any mention of TBD which means the
            # next version number should be filled in.
            if grep -qr "since = \"TBD" ./$crate; then
                echo Version number needs to be filled in following places:
                grep -r "since = \"TBD" ./$crate
                exit 1
            fi

            # Then try to dry-run cargo publish
            publish_dry_run $crate
        fi
    done
}

# Returns 0 if crate ($1) contains changes since tip of master that imply this patch set is done in
# preparation for releasing the crate.
release_changes() {
    local crate=$1
    git log --patch --reverse master.. -- $crate/Cargo.toml | grep version
}

# Do a dry run publish to crates.io using the correct package name for crate ($1).
# We use `set -e` so this will fail the script if the dry-run fails.
publish_dry_run() {
    local crate=$1
    if [ "$crate" == "hashes" ]; then
        cargo publish -p "bitcoin_hashes" --dry-run
    elif [ "$crate" == "internals" ]; then
        cargo publish -p "bitcoin-internals" --dry-run
    elif [ "$crate" == "bitcoin" ]; then
        cargo publish -p "bitcoin" --dry-run
    fi
}

#
# Main script.
#
main $@
