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
