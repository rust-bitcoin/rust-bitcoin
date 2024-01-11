#!/usr/bin/env bash

set -ex

FEATURES=""

cargo --version
rustc --version

# Defaults / sanity checks
cargo build
cargo test
