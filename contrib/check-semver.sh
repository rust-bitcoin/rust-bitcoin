#!/usr/bin/env bash
#
# Checks the public API of crates, exits with non-zero if there are currently
# changes to the public API not already committed to in the various api/*.txt
# files.

set -euo pipefail
set -x #remove me

NIGHTLY=$(cat nightly-version)
# Our docs have broken intra doc links if all features are not enabled.
RUSTDOCFLAGS="-Z unstable-options --document-private-items --document-hidden-items --output-format=json --cap-lints=allow"

if [ -n "${GITHUB_BASE_REF+x}" ]; then
  MASTER_COMMIT=$GITHUB_BASE_REF # running on CI
else
  MASTER_COMMIT=$(git rev-parse master)
fi

main() {
    need_nightly

    # on current commit
    generate_json_files_all_features "bitcoin" "current"
    generate_json_files_no_default_features "bitcoin" "current"

    generate_json_files_all_features "base58ck" "current"
    generate_json_files_no_default_features "base58ck" "current"

    generate_json_files_no_default_features "bitcoin_hashes" "current"
    generate_json_files_features_alloc "bitcoin_hashes" "current"

    generate_json_files_no_default_features "bitcoin-units" "current"
    generate_json_files_features_alloc "bitcoin-units" "current"

    generate_json_files_no_default_features "bitcoin-io" "current"
    generate_json_files_features_alloc "bitcoin-io" "current"


    # switch to master
    echo "Checking out master at $MASTER_COMMIT"
    git checkout "$MASTER_COMMIT"

    generate_json_files_all_features "bitcoin" "master"
    generate_json_files_no_default_features "bitcoin" "master"

    generate_json_files_all_features "base58ck" "master"
    generate_json_files_no_default_features "base58ck" "master"

    generate_json_files_no_default_features "bitcoin_hashes" "master"
    generate_json_files_features_alloc "bitcoin_hashes" "master"

    generate_json_files_no_default_features "bitcoin-units" "master"
    generate_json_files_features_alloc "bitcoin-units" "master"

    generate_json_files_no_default_features "bitcoin-io" "master"
    generate_json_files_features_alloc "bitcoin-io" "master"

    # Check for API semver breaks
    run_cargo_semver_check "bitcoin" "all-features"
    run_cargo_semver_check "bitcoin" "no-default-features"
    run_cargo_semver_check "base58ck" "all-features"
    run_cargo_semver_check "base58ck" "no-default-features"
    run_cargo_semver_check "bitcoin_hashes" "no-default-features"
    run_cargo_semver_check "bitcoin_hashes" "alloc"
    run_cargo_semver_check "bitcoin-units" "no-default-features"
    run_cargo_semver_check "bitcoin-units" "alloc"
    run_cargo_semver_check "bitcoin-io" "no-default-features"
    run_cargo_semver_check "bitcoin-io" "alloc"

    check_for_breaking_changes
}

# Run cargo doc
run_cargo_doc() {
    RUSTDOCFLAGS="$RUSTDOCFLAGS" cargo +"$NIGHTLY" doc --no-deps "$@"
}

# Run cargo semver-check
run_cargo_semver_check() {
    local crate="$1"
    local variant="$2"

    echo "Running cargo semver-checks for $crate $variant"
    cargo semver-checks -v --baseline-rustdoc "$crate-master-$variant.json" --current-rustdoc "$crate-current-$variant.json" > "$crate-$variant-semver.txt" 2>&1
}

# Uses cargo doc to generate JSON files that cargo semver-checks can use.
generate_json_files_no_default_features() {
    local crate="$1"
    local version="$2"

    echo "Running cargo doc no-default-features for $crate $version"
    run_cargo_doc --no-default-features -p "$crate"

    # replace _ for - in crate name
    mv "target/doc/${crate//-/_}.json" "$crate-$version-no-default-features.json"
}
generate_json_files_all_features() {
    local crate="$1"
    local version="$2"

    echo "Running cargo doc all-features for $crate $version"
    run_cargo_doc --all-features -p "$crate"

    # replace _ for - in crate name
    mv -v "target/doc/${crate//-/_}.json" "$crate-$version-all-features.json"
}
generate_json_files_features_alloc() {
    local crate="$1"
    local version="$2"

    echo "Running cargo doc --features alloc for $crate $version"
    run_cargo_doc --no-default-features --features alloc -p "$crate"

    # replace _ for - in crate name
    mv -v "target/doc/${crate//-/_}.json" "$crate-$version-alloc.json"
}

# Check if there are breaking changes
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