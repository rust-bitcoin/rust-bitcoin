#!/bin/sh -ex

FEATURES="base64 bitcoinconsensus use-serde rand"

if [ "$DO_COV" = true ]
then
    export RUSTFLAGS="-C link-dead-code"
fi


# Use toolchain if explicitly specified
if [ -n "$TOOLCHAIN" ]
then
    alias cargo="cargo +$TOOLCHAIN"
fi

# Test without any features first
cargo test --verbose --no-default-features
# Then test with the default features
cargo test --verbose

# Test each feature
for feature in ${FEATURES}
do
    cargo test --verbose --features="$feature"
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

# Use as dependency if told to
if [ -n "$AS_DEPENDENCY" ]
then
    cargo new dep_test
    cd dep_test
    echo 'bitcoin = { path = "..", features = ["use-serde"] }' >> Cargo.toml

    # Pin `cc` for Rust 1.29
    if [ "$TRAVIS_RUST_VERSION" = "1.29.0" ]; then
        cargo generate-lockfile --verbose
        cargo update -p cc --precise "1.0.41" --verbose
    fi

    cargo test --verbose
fi
