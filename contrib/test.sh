#!/bin/sh -ex

FEATURES="secp256k1 consensus use-serde use-serde,secp256k1 serde-decimal serde-decimal,secp256k1"

# Use toolchain if explicitly specified
if [ -n "$TOOLCHAIN" ]
then
    alias cargo="cargo +$TOOLCHAIN"
fi

# Test without any features first
cargo test --no-default-features --verbose

# Test each feature
for feature in ${FEATURES}
do
    cargo test --no-default-features --verbose --features="$feature"
done

# Fuzz if told to
if [ "$DO_FUZZ" = true ]
then
    (
        cd fuzz
        cargo test --verbose
        ./travis-fuzz.sh
    )
fi

# Bench if told to
if [ "$DO_BENCH" = true ]
then
    cargo bench --features unstable
fi
