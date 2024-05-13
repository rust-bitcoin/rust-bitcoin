#!/usr/bin/env bash
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

# Crates in this workspace to test (note "fuzz" is only built not tested).
CRATES=("base58" "bitcoin" "fuzz" "hashes" "internals" "io" "units")
