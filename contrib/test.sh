#!/bin/sh -ex

FEATURES="base64 bitcoinconsensus use-serde rand secp-recovery"

# Use toolchain if explicitly specified
if [ -n "$TOOLCHAIN" ]
then
    alias cargo="cargo +$TOOLCHAIN"
fi

pin_common_verions() {
    cargo generate-lockfile --verbose
    cargo update -p cc --precise "1.0.41" --verbose
    cargo update -p serde --precise "1.0.98" --verbose
    cargo update -p serde_derive --precise "1.0.98" --verbose
}

# Pin `cc` for Rust 1.29
if [ "$PIN_VERSIONS" = true ]; then
    pin_common_verions
    cargo update -p byteorder --precise "1.3.4"
fi

if [ "$DO_COV" = true ]
then
    export RUSTFLAGS="-C link-dead-code"
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

  cargo run --example bip32 L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D
  cargo run --no-default-features --features no-std --example bip32 L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D
fi

# Test each feature
for feature in ${FEATURES}
do
    echo "********* Testing "$feature" *************"
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
if [ "$AS_DEPENDENCY" = true ]
then
    cargo new dep_test
    cd dep_test
    echo 'bitcoin = { path = "..", features = ["use-serde"] }' >> Cargo.toml

    # Pin `cc` for Rust 1.29
    if [ -n "$PIN_VERSIONS" ]; then
        pin_common_verions
    fi

    cargo test --verbose
fi
