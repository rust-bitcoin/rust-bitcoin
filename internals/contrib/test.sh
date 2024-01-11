#!/usr/bin/env bash

set -ex

FEATURES="std alloc"

cargo --version
rustc --version

# Defaults / sanity checks
cargo --locked build
cargo --locked test

if [ "$DO_FEATURE_MATRIX" = true ]; then
    # No features
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
    done
fi
