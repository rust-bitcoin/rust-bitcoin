#!/bin/sh

set -ex

FEATURES="std"

cargo --version
rustc --version

if [ "$DO_LINT" = true ]
then
    cargo clippy --all-features --all-targets -- -D warnings
fi

# Test each feature
for feature in ${FEATURES}
do
    echo "********* Testing $feature *************"
    cargo test --verbose --features="$feature"
done

# Build the docs if told to (this only works with the nightly toolchain)
if [ "$DO_DOCS" = true ]; then
    RUSTDOCFLAGS="--cfg docsrs" cargo +nightly rustdoc --features="$FEATURES" -- -D rustdoc::broken-intra-doc-links
fi
