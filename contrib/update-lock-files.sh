#!/usr/bin/env bash
#
# Update the minimal and recent lockfiles.

set -euo pipefail


NIGHTLY=$(cat nightly-version)

# Resolve the minimal versions lockfile. direct-minimal-versions forces
# the workspace to use a consistent minimal version for direct dependencies.
# Transitive dependencies are allowed to update following the resolver's policy,
# since their minimal version's might be wrong.
cargo +"$NIGHTLY" update -Z direct-minimal-versions
cargo check
cp -f Cargo.lock Cargo-minimal.lock

# Conservatively bump of recent dependencies.
cp -f Cargo-recent.lock Cargo.lock
cargo check
cp -f Cargo.lock Cargo-recent.lock
