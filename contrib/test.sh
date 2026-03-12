#!/bin/sh

set -ex

REPO_DIR=$(git rev-parse --show-toplevel)
CRATES="bitcoin hashes internals"

# Don't use point release because `cargo --version` shows 1.56.0 even when running with version 1.56.1
MSRV="1.56"                     

# All `cargo` invocations excl. ones that are run by setting environment
# variables (eg DO_FMT) use `--locked` so as not to update this.
if cargo --version | grep "$MSRV"; then
    cp "$REPO_DIR/Cargo-minimal.lock" "$REPO_DIR/Cargo.lock"
else
    cp "$REPO_DIR/Cargo-recent.lock" "$REPO_DIR/Cargo.lock"
fi

for crate in ${CRATES}
do
    (
        cd "$crate"
        ./contrib/test.sh
    )
done

exit 0
