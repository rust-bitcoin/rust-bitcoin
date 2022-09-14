#!/bin/sh

set -ex

FEATURES="std alloc"

if [ "$DO_LINT" = true ]
then
    cargo clippy --frozen --all-features --all-targets -- -D warnings
fi

if [ "$DO_NO_STD" = true ]
then
    echo "********* Testing no-std build *************"
    # Build no_std, to make sure that cfg(test) doesn't hide any issues
    cargo build --frozen --verbose
    cargo test --frozen --verbose
fi

# Test each feature
for feature in ${FEATURES}
do
    echo "********* Testing $feature *************"
    cargo test --frozen --verbose --features="$feature"
done
