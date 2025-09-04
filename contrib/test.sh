#!/bin/sh

set -ex

REPO_DIR=$(git rev-parse --show-toplevel)
CRATES="bitcoin hashes internals"

# All `cargo` invocations excl. ones that are run by setting environment
# variables (eg DO_FMT) use `--locked` so as not to update this.
cp "$REPO_DIR/Cargo-recent.lock" "$REPO_DIR/Cargo.lock"

for crate in ${CRATES}
do
    (
        cd "$crate"
        ./contrib/test.sh
    )
done

exit 0
