#!/usr/bin/env bash

set -ex

# Make all cargo invocations verbose.
export CARGO_TERM_VERBOSE=true

REPO_DIR=$(git rev-parse --show-toplevel)

main() {
    if [ "$DO_LINT" = true ];
    then
        lint
        exit 0
    fi

    if [ "$DO_DOCSRS" = true ];
    then
        build_docs_with_nightly_toolchain
        exit 0
    fi

    if [ "$DO_DOCS" = true ];
    then
        build_docs_with_stable_toolchain
        exit 0
    fi

    if [ "$DO_BENCH" = true ];
    then
        bench
        exit 0
    fi

    if [ "$AS_DEPENDENCY" = true ]
    then
        use_bitcoin_as_a_dependency
        exit 0
    fi

    run_per_crate_test_scripts
}

run_per_crate_test_scripts() {
    local crates="bitcoin hashes units internals fuzz"
    local deps="recent minimal"

    for dep in ${deps}
    do
        cp "Cargo-$dep.lock" Cargo.lock
        for crate in ${crates}
        do
            (
                cd "$crate"
                ./contrib/test.sh
            )
        done
        if [ "$dep" = recent ];
        then
            # We always test committed dependencies but we want to warn if they could've been updated
            cargo update
            if diff Cargo-recent.lock Cargo.lock;
            then
                echo Dependencies are up to date
            else
                echo "::warning file=Cargo-recent.lock::Dependencies could be updated"
            fi
        fi
    done
}

lint() {
    # Run clippy on the whole workspace - this does not lint any code in `examples/` directories.
    cargo +nightly clippy --workspace

    # Run clippy against all the examples - this should be an exhaustive list of examples.
    # Verify with `fd .rs | grep examples/`
    cargo +nightly clippy --manifest-path bitcoin/Cargo.toml --example bip32 -- -D warnings
    cargo +nightly clippy --manifest-path bitcoin/Cargo.toml --example handshake --features=rand-std -- -D warnings
    cargo +nightly clippy --manifest-path bitcoin/Cargo.toml --example ecdsa-psbt --features=bitcoinconsensus -- -D warnings
    cargo +nightly clippy --manifest-path bitcoin/Cargo.toml --example sign-tx-segwit-v0 --features=rand-std -- -D warnings
    cargo +nightly clippy --manifest-path bitcoin/Cargo.toml --example sign-tx-taproot --features=rand-std -- -D warnings
    cargo +nightly clippy --manifest-path bitcoin/Cargo.toml --example taproot-psbt --features=rand-std,bitcoinconsensus -- -D warnings
}

# Build the docs with a nightly toolchain, in unison with the function
# below this checks that we feature guarded docs imports correctly.
build_docs_with_nightly_toolchain() {
    local crates="bitcoin hashes units"

    for crate in ${crates}
    do
        pushd "$REPO_DIR/$crate" > /dev/null || exit 1
        RUSTDOCFLAGS="--cfg docsrs -D warnings -D rustdoc::broken-intra-doc-links" cargo +nightly doc --all-features
        popd > /dev/null || exit 1
    done
}

# Build the docs with a stable toolchain, in unison with the function
# above this checks that we feature guarded docs imports correctly.
build_docs_with_stable_toolchain() {
    local crates="bitcoin hashes units"

    for crate in ${crates}
    do
        pushd "$REPO_DIR/$crate" > /dev/null || exit 1
        RUSTDOCFLAGS="-D warnings" cargo +stable doc --all-features
        popd > /dev/null || exit 1
    done
}

# Bench only works with a non-stable toolchain (nightly, beta).
bench() {
    RUSTFLAGS='--cfg=bench' cargo bench
}

# Checks that be can build/test an empty crate that uses bitcoin as a dependency.
# TODO: Add comment about why we do this.
use_bitcoin_as_a_dependency() {
    cargo new dep_test 2> /dev/null # Mute warning about workspace, fixed below.
    cd dep_test
    printf 'bitcoin = { path = "../bitcoin", features = ["serde"] }\n\n' >> Cargo.toml
    # Adding an empty workspace section excludes this crate from the rust-bitcoin workspace.
    printf '[workspace]\n\n' >> Cargo.toml

    # We have to patch all the local crates same as we do in main workspace.
    printf '[patch.crates-io.bitcoin_hashes]\npath = "../hashes"\n\n' >> Cargo.toml
    printf '[patch.crates-io.bitcoin-internals]\npath = "../internals"\n\n' >> Cargo.toml
    printf '[patch.crates-io.bitcoin-io]\npath = "../io"\n\n' >> Cargo.toml
    printf '[patch.crates-io.bitcoin-units]\npath = "../units"\n\n' >> Cargo.toml

    cargo test --verbose
}
#
# Main script
#
main "$@"
exit 0
