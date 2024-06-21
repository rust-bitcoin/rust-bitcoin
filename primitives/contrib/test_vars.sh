# No shebang, this file should not be executed.
# shellcheck disable=SC2148
#
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

# Test all these features with "std" enabled.
FEATURES_WITH_STD="rand-std bitcoinconsensus-std rand-std crytpo-serde-std base64 ordered"

# Test all these features without "std" or "alloc" enabled.
# `serde` is tested in `extra_tests.sh `.
FEATURES_WITHOUT_STD="rand secp-recovery bitcoinconsensus crypto base64 ordered"

# Run these examples.
EXAMPLES=""
