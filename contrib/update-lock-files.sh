#!/usr/bin/env bash
#
# Update the minimal/recent lock file

set -euo pipefail

for file in Cargo-minimal.lock Cargo-recent.lock; do
    cp --force "$file" Cargo.lock
    cargo check
    cp --force Cargo.lock "$file"
done
