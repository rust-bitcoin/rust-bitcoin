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

if [ "$DO_LINT" = true ]
then
    cargo clippy --locked --all-features --all-targets -- -D warnings
fi

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

REPO_DIR=$(git rev-parse --show-toplevel)

# Build the docs if told to (this only works with the nightly toolchain)
if [ "$DO_DOCSRS" = true ]; then
    RUSTDOCFLAGS="--cfg docsrs -D warnings -D rustdoc::broken-intra-doc-links" cargo +nightly doc --all-features
fi

# Build the docs with a stable toolchain, in unison with the DO_DOCSRS command
# above this checks that we feature guarded docs imports correctly.
if [ "$DO_DOCS" = true ]; then
    RUSTDOCFLAGS="-D warnings" cargo +stable doc --all-features
fi

# Run formatter if told to.
if [ "$DO_FMT" = true ]; then
    if [ "$NIGHTLY" = false ]; then
        echo "DO_FMT requires a nightly toolchain (consider using RUSTUP_TOOLCHAIN)"
        exit 1
    fi
    rustup component add rustfmt
    cargo fmt --check
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
