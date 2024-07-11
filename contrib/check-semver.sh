#!/usr/bin/env bash
#
# Checks semver compatibility between the current and target branches.
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

# These will be set to the commit SHA from the PR's target branch
# GitHub Actions CI.
# NOTE: if running locally this will be set to master.
if [ -n "${GITHUB_BASE_REF+x}" ]; then
  TARGET_COMMIT=$GITHUB_BASE_REF # running on CI
else
  TARGET_COMMIT=$(git rev-parse master) # running locally
fi

main() {
    # On current commit:
    # 1. bitcoin: all-features and no-default-features.
    generate_json_files_all_features "bitcoin" "current"
    generate_json_files_no_default_features "bitcoin" "current"

    # 2. base58ck: all-features and no-default-features.
    generate_json_files_all_features "base58ck" "current"
    generate_json_files_no_default_features "base58ck" "current"

    # 3. bitcoin_hashes: all-features, no-default-features and alloc feature.
    generate_json_files_all_features "bitcoin_hashes" "current"
    generate_json_files_no_default_features "bitcoin_hashes" "current"
    generate_json_files_features_alloc "bitcoin_hashes" "current"

    # 4. bitcoin-units: all-features, no-default-features and alloc feature.
    generate_json_files_all_features "bitcoin-units" "current"
    generate_json_files_no_default_features "bitcoin-units" "current"
    generate_json_files_features_alloc "bitcoin-units" "current"

    # 5. bitcoin-io: all-features, no-default-features and alloc feature.
    generate_json_files_all_features "bitcoin-io" "current"
    generate_json_files_no_default_features "bitcoin-io" "current"
    generate_json_files_features_alloc "bitcoin-io" "current"


    # Switch to target commit.
    echo "Checking out target commit at $TARGET_COMMIT"
    git checkout "$TARGET_COMMIT"

    # On target commit:
    # 1. bitcoin: all-features and no-default-features.
    generate_json_files_all_features "bitcoin" "master"
    generate_json_files_no_default_features "bitcoin" "master"

    # 2. base58ck: all-features and no-default-features.
    generate_json_files_all_features "base58ck" "master"
    generate_json_files_no_default_features "base58ck" "master"

    # 3. bitcoin_hashes: all-features, no-default-features and alloc feature.
    generate_json_files_all_features "bitcoin_hashes" "master"
    generate_json_files_no_default_features "bitcoin_hashes" "master"
    generate_json_files_features_alloc "bitcoin_hashes" "master"

    # 4. bitcoin-units: all-features, no-default-features and alloc feature.
    generate_json_files_all_features "bitcoin-units" "master"
    generate_json_files_no_default_features "bitcoin-units" "master"
    generate_json_files_features_alloc "bitcoin-units" "master"

    # 5. bitcoin-io: all-features, no-default-features and alloc feature.
    generate_json_files_all_features "bitcoin-io" "master"
    generate_json_files_no_default_features "bitcoin-io" "master"
    generate_json_files_features_alloc "bitcoin-io" "master"

    # Check for API semver breaks on all the generated JSON files above.
    run_cargo_semver_check "bitcoin" "all-features"
    run_cargo_semver_check "bitcoin" "no-default-features"
    run_cargo_semver_check "base58ck" "all-features"
    run_cargo_semver_check "base58ck" "no-default-features"
    run_cargo_semver_check "bitcoin_hashes" "all-features"
    run_cargo_semver_check "bitcoin_hashes" "no-default-features"
    run_cargo_semver_check "bitcoin_hashes" "alloc"
    run_cargo_semver_check "bitcoin-units" "all-features"
    run_cargo_semver_check "bitcoin-units" "no-default-features"
    run_cargo_semver_check "bitcoin-units" "alloc"
    run_cargo_semver_check "bitcoin-io" "all-features"
    run_cargo_semver_check "bitcoin-io" "no-default-features"
    run_cargo_semver_check "bitcoin-io" "alloc"

    # Invoke cargo semver-checks to check for breaking changes
    # in all generated files.
    check_for_breaking_changes
}

# Run cargo doc with the cargo semver-checks rustdoc flags.
# We don't care about dependencies.
run_cargo_doc() {
    RUSTDOCFLAGS="$RUSTDOCFLAGS" RUSTC_BOOTSTRAP=1 cargo doc --no-deps "$@"
}

# Run cargo semver-check
run_cargo_semver_check() {
    local crate="$1"
    local variant="$2"

    echo "Running cargo semver-checks for $crate $variant"
    # Hack to not fail on errors.
    # This is necessary since cargo semver-checks will fail if the
    # semver check fails.
    # We check that manually later.
    set +e
    cargo semver-checks -v --baseline-rustdoc "$crate-master-$variant.json" --current-rustdoc "$crate-current-$variant.json" > "$crate-$variant-semver.txt" 2>&1
    set -e
}

# The following function uses cargo doc to generate JSON files that
# cargo semver-checks can use.
# - no-default-features: generate JSON doc files with no default features.
generate_json_files_no_default_features() {
    local crate="$1"
    local version="$2"

    echo "Running cargo doc no-default-features for $crate $version"
    run_cargo_doc --no-default-features -p "$crate"

    # replace _ for - in crate name.
    # This is necessary since some crates have - in their name
    # which will be converted to _ in the output file by cargo doc.
    mv "target/doc/${crate//-/_}.json" "$crate-$version-no-default-features.json"
}
# - all-features: generate JSON doc files with all features.
generate_json_files_all_features() {
    local crate="$1"
    local version="$2"

    echo "Running cargo doc all-features for $crate $version"
    run_cargo_doc --all-features -p "$crate"

    # replace _ for - in crate name.
    # This is necessary since some crates have - in their name
    # which will be converted to _ in the output file by cargo doc.
    mv -v "target/doc/${crate//-/_}.json" "$crate-$version-all-features.json"
}
# - alloc: generate JSON doc files with the alloc feature.
generate_json_files_features_alloc() {
    local crate="$1"
    local version="$2"

    echo "Running cargo doc --features alloc for $crate $version"
    run_cargo_doc --no-default-features --features alloc -p "$crate"

    # replace _ for - in crate name.
    # This is necessary since some crates have - in their name
    # which will be converted to _ in the output file by cargo doc.
    mv -v "target/doc/${crate//-/_}.json" "$crate-$version-alloc.json"
}

# Check if there are breaking changes.
# We loop through all the generated files and check if there is a FAIL
# in the cargo semver-checks output.
# If we detect a fail, we create an empty file semver-break.
# If the following CI step finds this file, it will add:
# 1. a comment on the PR.
# 2. a label to the PR.
check_for_breaking_changes() {
    for file in *semver.txt; do
        echo "Checking $file"
        if grep -q "FAIL" "$file"; then
            echo "You have introduced changes to the public API"
            echo "FAIL found in $file"
            # flag it as a breaking change
            # Handle the case where FAIL is found
            touch semver-break
        fi
    done
    if ! [ -f semver-break ]; then
       echo "No breaking changes found"
    fi
}

#
# Main script
#
main "$@"
exit 0