#!/usr/bin/env bash

set -euox pipefail

REPO_DIR=$(git rev-parse --show-toplevel)

pushd "$REPO_DIR/hashes/extended_tests/schemars" > /dev/null

# This comment mentions Rust 1.63 to assist grepping when doing MSRV update.
#
if cargo --version | grep -q '1\.63'; then
   cargo update -p regex --precise 1.7.3
fi

cargo test
popd > /dev/null
