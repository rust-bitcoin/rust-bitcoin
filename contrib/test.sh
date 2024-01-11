#!/usr/bin/env bash

set -ex

main() {
    run_per_crate_test_scripts
}

run_per_crate_test_scripts() {
    local crates="bitcoin hashes units internals fuzz"
    local deps="recent minimal"

    for dep in ${deps}
    do
        cp "Cargo-$dep.lock" Cargo.lock
        for crate in ${crates}
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
}

#
# Main script
#
main "$@"
exit 0
