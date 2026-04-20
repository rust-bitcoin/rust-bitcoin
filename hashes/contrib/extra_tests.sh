#!/usr/bin/env bash

set -ex

REPO_DIR=$(git rev-parse --show-toplevel)

if [ "${DO_SCHEMARS_TESTS:=false}" = true ]; then
    pushd "$REPO_DIR/hashes/extended_tests/schemars" > /dev/null
    cargo test
    popd > /dev/null
fi
