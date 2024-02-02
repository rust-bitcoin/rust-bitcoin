#!/usr/bin/env bash

set -ex

FEATURES=""

cargo --version
rustc --version

# Make all cargo invocations verbose
export CARGO_TERM_VERBOSE=true

# Pin dependencies as required if we are using MSRV toolchain.
if cargo --version | grep "1\.41"; then
    # 1.0.157 uses syn 2.0 which requires edition 2021
    cargo update -p serde --precise 1.0.156
    # 1.0.108 uses `matches!` macro so does not work with Rust 1.41.1, bad `syn` no biscuit.
    cargo update -p syn --precise 1.0.107
    # Half 1.8 uses edition 2021 features
    cargo update -p half --precise 1.7.1
fi

if [ "$DO_LINT" = true ]
then
    cargo clippy --all-features --all-targets -- -D warnings
fi

# Defaults / sanity checks
cargo build
cargo test

# Address Sanitizer
if [ "$DO_ASAN" = true ]; then
    cargo clean
    CC='clang -fsanitize=address -fno-omit-frame-pointer'                                        \
    RUSTFLAGS='-Zsanitizer=address -Clinker=clang -Cforce-frame-pointers=yes'                    \
    ASAN_OPTIONS='detect_leaks=1 detect_invalid_pointer_pairs=1 detect_stack_use_after_return=1' \
    cargo test --lib --no-default-features --features="$FEATURES" -Zbuild-std --target x86_64-unknown-linux-gnu
    cargo clean
    CC='clang -fsanitize=memory -fno-omit-frame-pointer'                                         \
    RUSTFLAGS='-Zsanitizer=memory -Zsanitizer-memory-track-origins -Cforce-frame-pointers=yes'   \
    cargo test --lib --no-default-features --features="$FEATURES" -Zbuild-std --target x86_64-unknown-linux-gnu
fi

