#!/usr/bin/env bash

set -euox pipefail

REPO_DIR=$(git rev-parse --show-toplevel)

pushd "$REPO_DIR/hashes/extended_tests/schemars" > /dev/null
cargo test
popd > /dev/null
