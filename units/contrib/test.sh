#!/usr/bin/env bash

set -ex

# FEATURES="std alloc serde"
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

    # Default features (this is std and alloc)
    $CARGO build --locked
    $CARGO test --locked

    # All features
    $CARGO build --no-default-features --all-features
    $CARGO test --no-default-features --all-features
fi
