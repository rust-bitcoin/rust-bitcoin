#!/usr/bin/env bash

set -ex

# We can't test this in the usual fashion because `serde` can only be enabled with `crypto` in `std`
# builds. Otherwise one must manually enable `secp256k1/serde`.
cargo test --no-default-features --features=serde
