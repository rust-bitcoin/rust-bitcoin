#!/usr/bin/env bash

set -ex

FEATURES="serde serde-std std io alloc"
CARGO="cargo --locked"

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

    # Other combos
    $CARGO test --no-default-features --features="std,schemars"
fi
