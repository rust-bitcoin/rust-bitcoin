#!/usr/bin/env bash

set -ex

FEATURES="std alloc"
CARGO="cargo --locked"

$CARGO --version
rustc --version

# Defaults / sanity checks
$CARGO build
$CARGO test

if [ "$DO_FEATURE_MATRIX" = true ]; then
    # No features
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
    done
fi
