#!/bin/sh

set -ex

CRATES="bitcoin hashes units internals fuzz"
DEPS="recent minimal"

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
