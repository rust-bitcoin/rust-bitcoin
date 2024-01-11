#!/usr/bin/env bash

set -ex

FEATURES="std rand-std rand serde secp-recovery bitcoinconsensus-std base64 bitcoinconsensus"
CARGO="cargo --locked"

if [ "$DO_COV" = true ]
then
    export RUSTFLAGS="-C link-dead-code"
fi

$CARGO --version
rustc --version

# Defaults / sanity checks
$CARGO build
$CARGO test

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
    $CARGO build --no-default-features
    $CARGO test --no-default-features

    # All features
    $CARGO build --no-default-features --features="$FEATURES"
    $CARGO test --no-default-features --features="$FEATURES"
    # Single features
    for feature in ${FEATURES}
    do
        $CARGO build --no-default-features --features="$feature"
        $CARGO test --no-default-features --features="$feature"
		# All combos of two features
		for featuretwo in ${FEATURES}; do
			$CARGO build --no-default-features --features="$feature $featuretwo"
			$CARGO test --no-default-features --features="$feature $featuretwo"
		done
    done
fi

$CARGO run --example bip32 7934c09359b234e076b9fa5a1abfd38e3dc2a9939745b7cc3c22a48d831d14bd
$CARGO run --no-default-features --example bip32 7934c09359b234e076b9fa5a1abfd38e3dc2a9939745b7cc3c22a48d831d14bd

$CARGO run --example ecdsa-psbt --features=bitcoinconsensus
$CARGO run --example sign-tx-segwit-v0 --features=rand-std -- -D warnings
$CARGO run --example sign-tx-taproot --features=rand-std -- -D warnings
$CARGO run --example taproot-psbt --features=rand-std,bitcoinconsensus
