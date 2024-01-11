#!/usr/bin/env bash

set -ex

FEATURES="serde serde-std std io alloc"

cargo --version
rustc --version

# Defaults / sanity checks
cargo build
cargo test

if [ "$DO_FEATURE_MATRIX" = true ]; then
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
		# All combos of two features
		for featuretwo in ${FEATURES}; do
			cargo build --locked --no-default-features --features="$feature $featuretwo"
			cargo test --locked --no-default-features --features="$feature $featuretwo"
		done
    done

    # Other combos
    cargo test --locked --no-default-features --features="std,schemars"
fi

REPO_DIR=$(git rev-parse --show-toplevel)

# Webassembly stuff
if [ "$DO_WASM" = true ]; then
    clang --version &&
    CARGO_TARGET_DIR=wasm cargo install --force wasm-pack &&
    printf '\n[target.wasm32-unknown-unknown.dev-dependencies]\nwasm-bindgen-test = "0.3"\n' >> Cargo.toml &&
    printf '\n[lib]\ncrate-type = ["cdylib", "rlib"]\n' >> Cargo.toml &&
    CC=clang-9 wasm-pack build &&
    CC=clang-9 wasm-pack test --node;
fi
