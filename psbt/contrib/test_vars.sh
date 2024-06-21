# No shebang, this file should not be executed.
# shellcheck disable=SC2148
#
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

# Test all these features with "std" enabled.
FEATURES_WITH_STD="rand-std serde base64"

# Test all these features without "std" or "alloc" enabled.
# `serde` is tested in `extra_tests.sh `.
FEATURES_WITHOUT_STD="rand serde base64"

# Run these examples.
EXAMPLES=""
