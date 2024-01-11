#!/usr/bin/env bash

set -ex

FEATURES="std alloc serde"

cargo --version
rustc --version

# Work out if we are using a nightly toolchain.
NIGHTLY=false
if cargo --version | grep nightly >/dev/null; then
    NIGHTLY=true
fi

# Defaults / sanity checks
cargo build
cargo test

if [ "$DO_FEATURE_MATRIX" = true ]; then
    # No features
    cargo build --locked --no-default-features
    cargo test --locked --no-default-features

    # Default features (this is std and alloc)
    cargo build --locked
    cargo test --locked

    # All features
    cargo build --locked --no-default-features --all-features
    cargo test --locked --no-default-features --all-features
fi
