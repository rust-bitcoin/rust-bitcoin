#!/usr/bin/env bash
#
# Update the minimal and recent lock files.

set -euo pipefail

NIGHTLY=$(cat nightly-version)

# The `direct-minimal-versions` and `minimal-versions` dependency
# resolution strategy flags each have a little quirk. `direct-minimal-versions`
# allows transitive versions to upgrade, so we are not testing against
# the actual minimum tree. `minimal-versions` allows the direct dependency
# versions to resolve upward due to transitive requirements, so we are
# not testing the manifest's versions. Combo'd together though, we
# can get the best of both worlds to ensure the actual minimum dependencies
# listed in the crate manifests build.

# Check that all explicit direct dependency versions are not lying,
# as in, they are not being bumped up by transitive dependency constraints.
rm -f Cargo.lock && cargo +"$NIGHTLY" check -Z direct-minimal-versions
# Now that our own direct dependency versions can be trusted, check
# against the lowest versions of the dependency tree which still
# satisfy constraints. Use this as the minimal version lock file.
rm -f Cargo.lock && cargo +"$NIGHTLY" check -Z minimal-versions
cp -f Cargo.lock Cargo-minimal.lock

# Conservatively bump of recent dependencies.
cp -f Cargo-recent.lock Cargo.lock
cargo check
cp -f Cargo.lock Cargo-recent.lock
