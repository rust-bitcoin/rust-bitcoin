#!/usr/bin/env bash

set -ex

cargo clippy --all-targets --no-default-features --keep-going -- -D warnings
