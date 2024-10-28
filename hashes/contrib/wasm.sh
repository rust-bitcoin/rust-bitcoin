#!/usr/bin/env bash
#
# Run the WASM tests.

set -euox pipefail

clang --version &&
    CARGO_TARGET_DIR=wasm cargo install --force wasm-pack &&
    printf '\n[target.wasm32-unknown-unknown.dev-dependencies]\nwasm-bindgen-test = "0.3"\n' >> Cargo.toml &&
    printf '\n[lib]\ncrate-type = ["cdylib", "rlib"]\n' >> Cargo.toml &&
    CC=clang-9 wasm-pack build;
# wasm-pack test isn't currently working.
#    CC=clang-9 wasm-pack test --node;
