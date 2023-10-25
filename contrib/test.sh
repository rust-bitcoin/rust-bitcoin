#!/bin/sh

set -ex

CRATES="bitcoin hashes internals fuzz"
DEPS="recent minimal"
MSRV="1\.48\.0"

# Test pinned versions.
if cargo --version | grep ${MSRV}; then
    cargo update -p serde_json --precise 1.0.99
    cargo update -p serde --precise 1.0.156
    cargo update -p quote --precise 1.0.30
    cargo update -p proc-macro2 --precise 1.0.63
    cargo update -p serde_test --precise 1.0.175
    # Have to pin this so we can pin `schemars_derive`
    cargo update -p schemars --precise 0.8.12
    # schemars_derive 0.8.13 uses edition 2021
    cargo update -p schemars_derive --precise 0.8.12
    # memchr 2.6.0 uses edition 2021
    cargo update -p memchr --precise 2.5.0
    # byteorder 1.5.0 uses edition 2021
    cargo update -p byteorder --precise 1.4.3

    # Build MSRV with pinned versions.
    cargo check --all-features --all-targets
fi

for dep in $DEPS
do
    cp "Cargo-$dep.lock" Cargo.lock
    for crate in ${CRATES}
    do
        (
            cd "$crate"
            ./contrib/test.sh
        )
    done
    if [ "$dep" = recent ];
    then
        # We always test committed dependencies but we want to warn if they could've been updated
        cargo update
        if diff Cargo-recent.lock Cargo.lock;
        then
            echo Dependencies are up to date
        else
            echo "::warning file=Cargo-recent.lock::Dependencies could be updated"
        fi
    fi
done

exit 0
