#!/bin/sh

set -ex

FEATURES="base64 bitcoinconsensus serde rand secp-recovery"

if [ "$DO_COV" = true ]
then
    export RUSTFLAGS="-C link-dead-code"
fi

cargo --version
rustc --version

# Some tests require certain toolchain types.
NIGHTLY=false
STABLE=true
if cargo --version | grep nightly; then
    STABLE=false
    NIGHTLY=true
fi
if cargo --version | grep beta; then
    STABLE=false
fi

# Pin dependencies as required if we are using MSRV toolchain.
if cargo --version | grep "1\.41"; then
    # 1.0.157 uses syn 2.0 which requires edition 2018
    cargo update -p serde --precise 1.0.156
    # 1.0.108 uses `matches!` macro so does not work with Rust 1.41.1, bad `syn` no biscuit.
    cargo update -p syn --precise 1.0.107
fi

# Pin dependencies as above (required for no-std tests that use Rust 1.47 toolchain).
if cargo --version | grep "1\.47"; then
    cargo update -p serde --precise 1.0.156
    cargo update -p syn --precise 1.0.107
fi

# We should not have any duplicate dependencies. This catches mistakes made upgrading dependencies
# in one crate and not in another (e.g. upgrade bitcoin_hashes in bitcoin but not in secp).
duplicate_dependencies=$(
    # Only show the actual duplicated deps, not their reverse tree, then
    # whitelist the 'syn' crate which is duplicated but it's not our fault.
    cargo tree  --target=all --all-features --duplicates \
        | grep '^[0-9A-Za-z]' \
        | grep -v 'syn' \
        | wc -l
)
if [ "$duplicate_dependencies" -ne 0 ]; then
    echo "Dependency tree is broken, contains duplicates"
    cargo tree  --target=all --all-features --duplicates
    exit 1
fi

if [ "$DO_LINT" = true ]
then
    cargo clippy --all-features --all-targets -- -D warnings
    cargo clippy --example bip32 -- -D warnings
    cargo clippy --example handshake --features=rand-std -- -D warnings
    cargo clippy --example ecdsa-psbt --features=bitcoinconsensus -- -D warnings
    cargo clippy --example taproot-psbt --features=rand-std,bitcoinconsensus -- -D warnings
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
        cargo build --verbose --features="no-std $feature" --no-default-features
    done

    cargo run --example bip32 7934c09359b234e076b9fa5a1abfd38e3dc2a9939745b7cc3c22a48d831d14bd
    cargo run --no-default-features --features no-std --example bip32 7934c09359b234e076b9fa5a1abfd38e3dc2a9939745b7cc3c22a48d831d14bd
fi

# Test each feature
for feature in ${FEATURES}
do
    echo "********* Testing $feature *************"
    cargo test --verbose --features="$feature"
done

cargo run --example ecdsa-psbt --features=bitcoinconsensus
cargo run --example taproot-psbt --features=rand-std,bitcoinconsensus

# Build the docs if told to (this only works with the nightly toolchain)
if [ "$DO_DOCSRS" = true ]; then
    RUSTDOCFLAGS="--cfg docsrs -D warnings -D rustdoc::broken-intra-doc-links" cargo +nightly doc --all-features
fi

# Build the docs with a stable toolchain, in unison with the DO_DOCSRS command
# above this checks that we feature guarded docs imports correctly.
if [ "$DO_DOCS" = true ]; then
    RUSTDOCFLAGS="-D warnings" cargo +stable doc --all-features
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

# Run formatter if told to.
if [ "$DO_FMT" = true ]; then
    if [ "$NIGHTLY" = false ]; then
        echo "DO_FMT requires a nightly toolchain (consider using RUSTUP_TOOLCHAIN)"
        exit 1
    fi
    rustup component add rustfmt
    cargo fmt --check
fi

# Bench if told to, only works with non-stable toolchain (nightly, beta).
if [ "$DO_BENCH" = true ]
then
    if [ "$STABLE" = true ]; then
        if [ -n "$RUSTUP_TOOLCHAIN" ]; then
            echo "RUSTUP_TOOLCHAIN is set to a stable toolchain but DO_BENCH requires a non-stable (beta, nightly) toolchain"
        else
            echo "DO_BENCH requires a non-stable (beta, nightly) toolchain"
        fi
        exit 1
    fi
    RUSTFLAGS='--cfg=bench' cargo bench
fi

# Use as dependency if told to
if [ "$AS_DEPENDENCY" = true ]
then
    cargo new dep_test 2> /dev/null # Mute warning about workspace, fixed below.
    cd dep_test
    echo 'bitcoin = { path = "..", features = ["serde"] }\n\n' >> Cargo.toml
    # Adding an empty workspace section excludes this crate from the rust-bitcoin workspace.
    echo '[workspace]\n\n' >> Cargo.toml

    cargo test --verbose
fi
