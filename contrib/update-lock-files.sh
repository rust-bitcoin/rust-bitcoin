#!/usr/bin/env bash
#
# Update the minimal/recent lock file

set -euo pipefail

for file in Cargo-minimal.lock Cargo-recent.lock; do
    cp -f "$file" Cargo.lock
    cargo check
    cp -f Cargo.lock "$file"
done
