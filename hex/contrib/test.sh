#!/bin/sh
#
# CI script for the `hex` crate.

set -ex

FEATURES="std alloc"

# Sanity checks.
cargo --version
rustc --version

cargo build --all-features
cargo test --all-features

if [ "$DO_FEATURE_MATRIX" = true ]; then
    # No features.
    cargo build --no-default-features
    cargo test --no-default-features

    # Single features.
    for feature in ${FEATURES}
    do
        cargo build --no-default-features --features="$feature"
        cargo test --no-default-features --features="$feature"
    done
fi

# Build the docs if told to (this only works with the nightly toolchain).
if [ "$DO_DOCS" = true ]; then
    RUSTDOCFLAGS="--cfg docsrs" cargo doc --all-features
fi

# Bench if told to, only works with non-stable toolchain (nightly, beta).
if [ "$DO_BENCH" = true ]; then
   RUSTFLAGS='--cfg=bench' cargo bench
fi
