# No shebang, this file should not be executed.
# shellcheck disable=SC2148
#
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

# Crates in this workspace to test (note "fuzz" is only built not tested).
CRATES=("addresses" "base58" "bitcoin" "primitives" "hashes" "internals" "io" "units" "fuzz")
