#!/usr/bin/env bash
#
# Update the minimal and recent lockfiles.

set -euo pipefail


NIGHTLY=$(cat nightly-version)

# direct-minimal-versions overrides check's already
# conservative dependecy resolving to force
# consistent minimal versions for direct dependencies
# of the workspace. Transitive dependencies are only
# updated if they must be due to manifest changes.
cp -f Cargo-minimal.lock Cargo.lock
cargo +"$NIGHTLY" check -Z direct-minimal-versions
cp -f Cargo.lock Cargo-minimal.lock

# Conservatively bump of recent dependencies.
cp -f Cargo-recent.lock Cargo.lock
cargo check
cp -f Cargo.lock Cargo-recent.lock
