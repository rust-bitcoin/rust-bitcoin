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

# Make all cargo invocations verbose
export CARGO_TERM_VERBOSE=true

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

# Bench if told to, only works with non-stable toolchain (nightly, beta).
if [ "$DO_BENCH" = true ]
then
    if [ "$NIGHTLY" = false ]
    then
        if [ -n "$RUSTUP_TOOLCHAIN" ]
        then
            echo "RUSTUP_TOOLCHAIN is set to a non-nightly toolchain but DO_BENCH requires a nightly toolchain"
        else
            echo "DO_BENCH requires a nightly toolchain"
        fi
        exit 1
    fi
    RUSTFLAGS='--cfg=bench' cargo bench
fi
