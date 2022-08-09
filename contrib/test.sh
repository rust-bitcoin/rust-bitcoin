#!/bin/sh -ex

FEATURES="base64 bitcoinconsensus serde rand secp-recovery"

# Use toolchain if explicitly specified
if [ -n "$TOOLCHAIN" ]
then
    alias cargo="cargo +$TOOLCHAIN"
fi

if [ "$DO_COV" = true ]
then
    export RUSTFLAGS="-C link-dead-code"
fi

cargo --version
rustc --version

# Work out if we are using a nightly toolchain.
NIGHTLY=false
if cargo --version | grep nightly; then
    NIGHTLY=true
fi

# We should not have any duplicate dependencies. This catches mistakes made upgrading dependencies
# in one crate and not in another (e.g. upgrade bitcoin_hashes in bitcoin but not in secp).
cargo update -p serde --precise 1.0.142
cargo update -p serde_test --precise 1.0.142
cargo update -p serde_derive --precise 1.0.142
duplicate_dependencies=$(cargo tree  --target=all --all-features --duplicates | wc -l)
if [ "$duplicate_dependencies" -ne 0 ]; then
    echo "Dependency tree is broken, contains duplicates"
    cargo tree  --target=all --all-features --duplicates
    exit 1
fi

if [ "$DO_LINT" = true ]
then
    cargo clippy --all-features --all-targets -- -D warnings
    cargo clippy --example bip32 -- -D warnings
    cargo clippy --example handshake -- -D warnings
    cargo clippy --example ecdsa-psbt --features=bitcoinconsensus -- -D warnings
fi

echo "********* Testing std *************"
# Test without any features other than std first
cargo test --verbose --no-default-features --features="std"

echo "********* Testing default *************"
# Then test with the default features
cargo test --verbose

if [ "$DO_NO_STD" = true ]
then
    echo "********* Testing no-std build *************"
    # Build no_std, to make sure that cfg(test) doesn't hide any issues
    cargo build --verbose --features="no-std" --no-default-features

    # Build std + no_std, to make sure they are not incompatible
    cargo build --verbose --features="no-std"

    # Test no_std
    cargo test --verbose --features="no-std" --no-default-features

    # Build all features
    cargo build --verbose --features="no-std $FEATURES" --no-default-features

    # Build specific features
    for feature in ${FEATURES}
    do
        cargo build --verbose --features="no-std $feature"
    done

    cargo run --example bip32 7934c09359b234e076b9fa5a1abfd38e3dc2a9939745b7cc3c22a48d831d14bd
    cargo run --no-default-features --features no-std --example bip32 7934c09359b234e076b9fa5a1abfd38e3dc2a9939745b7cc3c22a48d831d14bd
fi

# Test each feature
for feature in ${FEATURES}
do
    echo "********* Testing "$feature" *************"
    cargo test --verbose --features="$feature"
done

cargo run --example ecdsa-psbt --features=bitcoinconsensus

# Build the docs if told to (this only works with the nightly toolchain)
if [ "$DO_DOCS" = true ]; then
    RUSTDOCFLAGS="--cfg docsrs" cargo +nightly rustdoc --features="$FEATURES" -- -D rustdoc::broken-intra-doc-links
fi

# Fuzz if told to
if [ "$DO_FUZZ" = true ]
then
    (
        cd fuzz
        cargo test --verbose
        ./travis-fuzz.sh
    )
fi

# Bench if told to, only works with non-stable toolchain (nightly, beta).
if [ "$DO_BENCH" = true ]
then
    if [ "NIGHTLY" = false ]
    then
        if [ -n "TOOLCHAIN" ]
        then
            echo "TOOLCHAIN is set to a non-nightly toolchain but DO_BENCH requires a nightly toolchain"
        else
            echo "DO_BENCH requires a nightly toolchain"
        fi
        exit 1
    fi
    RUSTFLAGS='--cfg=bench' cargo bench
fi

# Use as dependency if told to
if [ "$AS_DEPENDENCY" = true ]
then
    cargo new dep_test
    cd dep_test
    echo 'bitcoin = { path = "..", features = ["serde"] }' >> Cargo.toml
    cargo update -p serde --precise 1.0.142
    cargo update -p serde_derive --precise 1.0.142

    cargo test --verbose
fi
