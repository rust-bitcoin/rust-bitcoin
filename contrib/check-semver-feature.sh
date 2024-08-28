#!/usr/bin/env bash
#
# Checks semver compatibility between the `--no-features` and `all-features`.
# This is important since it tests for the presence non-additive cargo features.
#
# Under the hood uses cargo semver-checks to check for breaking changes.
# We cannot use it directly since it only supports checking against published
# crates.
# That's the intended use case for cargo semver-checks:
# you run before publishing a new version of a crate to check semver breaks.
# Here we are hacking it by first generating JSON files from cargo doc
# and then using those files to check for breaking changes with
# cargo semver-checks.

set -euo pipefail

# These are the hardcoded flags that cargo semver-checks uses
# under the hood to invoke rustdoc.
RUSTDOCFLAGS="-Z unstable-options --document-private-items --document-hidden-items --output-format=json --cap-lints=allow"

main() {
    # Generate JSON files for no-features and all-features
    # 1. bitcoin
    generate_json_files_all_features "bitcoin"
    generate_json_files_no_default_features "bitcoin"

    # 2. base58ck
    generate_json_files_all_features "base58ck"
    generate_json_files_no_default_features "base58ck"

    # 3. bitcoin_hashes
    generate_json_files_all_features "bitcoin_hashes"
    generate_json_files_no_default_features "bitcoin_hashes"

    # 4. bitcoin-units
    generate_json_files_all_features "bitcoin-units"
    generate_json_files_no_default_features "bitcoin-units"

    # 5. bitcoin-io
    generate_json_files_all_features "bitcoin-io"
    generate_json_files_no_default_features "bitcoin-io"

    # Check for API semver non-addivite cargo features on all the generated JSON files above.
    run_cargo_semver_check "bitcoin"
    run_cargo_semver_check "base58ck"
    run_cargo_semver_check "bitcoin_hashes"
    run_cargo_semver_check "bitcoin-units"
    run_cargo_semver_check "bitcoin-io"

    # Invoke cargo semver-checks to check for non-additive cargo features
    # in all generated files.
    check_for_non_additive_cargo_features
}

# Run cargo doc with the cargo semver-checks rustdoc flags.
# We don't care about dependencies.
run_cargo_doc() {
    RUSTDOCFLAGS="$RUSTDOCFLAGS" RUSTC_BOOTSTRAP=1 cargo doc --no-deps "$@"
}

# Run cargo semver-check
run_cargo_semver_check() {
    local crate="$1"

    echo "Running cargo semver-checks for $crate"
    # Hack to not fail on errors.
    # This is necessary since cargo semver-checks will fail if the
    # semver check fails.
    # We check that manually later.
    set +e
    cargo semver-checks -v --baseline-rustdoc "$crate-no-default-features.json" --current-rustdoc "$crate-all-features.json" > "$crate--additive-features.txt" 2>&1
    set -e
}

# The following function uses cargo doc to generate JSON files that
# cargo semver-checks can use.
# - no-default-features: generate JSON doc files with no default features.
generate_json_files_no_default_features() {
    local crate="$1"

    echo "Running cargo doc no-default-features for $crate"
    run_cargo_doc --no-default-features -p "$crate"

    # replace _ for - in crate name.
    # This is necessary since some crates have - in their name
    # which will be converted to _ in the output file by cargo doc.
    mv "target/doc/${crate//-/_}.json" "$crate-no-default-features.json"
}
# - all-features: generate JSON doc files with all features.
generate_json_files_all_features() {
    local crate="$1"

    echo "Running cargo doc all-features for $crate"
    run_cargo_doc --all-features -p "$crate"

    # replace _ for - in crate name.
    # This is necessary since some crates have - in their name
    # which will be converted to _ in the output file by cargo doc.
    mv -v "target/doc/${crate//-/_}.json" "$crate-all-features.json"
}

# Check if there are non-additive cargo features.
# We loop through all the generated files and check if there is a FAIL
# in the cargo semver-checks output.
# If we detect a fail, we create an empty file non-additive-cargo.
# If the following CI step finds this file, it will add:
# 1. a comment on the PR.
# 2. a label to the PR.
check_for_non_additive_cargo_features() {
    for file in *additive-features.txt; do
        echo "Checking $file"
        if grep -q "FAIL" "$file"; then
            echo "You have introduced non-additive cargo features"
            echo "FAIL found in $file"
            cat "$file"
            # flag it as a breaking change
            # Handle the case where FAIL is found
            touch non-additive-cargo
        fi
    done
    if ! [ -f non-additive-cargo ]; then
       echo "No non-additive cargo features found"
    else
        err "Non-additive cargo features found"
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
