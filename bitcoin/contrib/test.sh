#!/usr/bin/env bash

set -ex

FEATURES="std rand-std rand serde secp-recovery bitcoinconsensus-std base64 bitcoinconsensus"

if [ "$DO_COV" = true ]
then
    export RUSTFLAGS="-C link-dead-code"
fi

cargo --version
rustc --version

# Defaults / sanity checks
cargo build
cargo test

if [ "$DO_LINT" = true ]
then
    # We should not have any duplicate dependencies. This catches mistakes made upgrading dependencies
    # in one crate and not in another (e.g. upgrade bitcoin_hashes in bitcoin but not in secp).
    duplicate_dependencies=$(
        # Only show the actual duplicated deps, not their reverse tree, then
        # whitelist the 'syn' crate which is duplicated but it's not our fault.
        #
        # Whitelist `bitcoin_hashes` while we release it and until secp v0.28.0 comes out.
        cargo tree  --target=all --all-features --duplicates \
            | grep '^[0-9A-Za-z]' \
            | grep -v 'syn' \
            | grep -v 'bitcoin_hashes' \
            | wc -l
                          )
    if [ "$duplicate_dependencies" -ne 0 ]; then
        echo "Dependency tree is broken, contains duplicates"
        cargo tree  --target=all --all-features --duplicates
        exit 1
    fi
fi

if [ "$DO_FEATURE_MATRIX" = true ]; then
    cargo build --locked --no-default-features
    cargo test --locked --no-default-features

    # All features
    cargo build --locked --no-default-features --features="$FEATURES"
    cargo test --locked --no-default-features --features="$FEATURES"
    # Single features
    for feature in ${FEATURES}
    do
        cargo build --locked --no-default-features --features="$feature"
        cargo test --locked --no-default-features --features="$feature"
		# All combos of two features
		for featuretwo in ${FEATURES}; do
			cargo build --locked --no-default-features --features="$feature $featuretwo"
			cargo test --locked --no-default-features --features="$feature $featuretwo"
		done
    done
fi

cargo run --locked --example bip32 7934c09359b234e076b9fa5a1abfd38e3dc2a9939745b7cc3c22a48d831d14bd
cargo run --locked --no-default-features --example bip32 7934c09359b234e076b9fa5a1abfd38e3dc2a9939745b7cc3c22a48d831d14bd

cargo run --locked --example ecdsa-psbt --features=bitcoinconsensus
cargo run --locked --example sign-tx-segwit-v0 --features=rand-std -- -D warnings
cargo run --locked --example sign-tx-taproot --features=rand-std -- -D warnings
cargo run --locked --example taproot-psbt --features=rand-std,bitcoinconsensus

# Use as dependency if told to
if [ "$AS_DEPENDENCY" = true ]
then
    cargo new dep_test 2> /dev/null # Mute warning about workspace, fixed below.
    cd dep_test
    echo 'bitcoin = { path = "..", features = ["serde"] }\n\n' >> Cargo.toml
    # Adding an empty workspace section excludes this crate from the rust-bitcoin workspace.
    echo '[workspace]\n\n' >> Cargo.toml

    cargo test --verbose
fi
