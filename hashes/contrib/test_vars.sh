# No shebang, this file should not be executed.
# shellcheck disable=SC2148
#
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

# Test all these features with "std" enabled.
FEATURES_WITH_STD="arbitrary serde small-hash"

# Test all these features without "std" enabled.
FEATURES_WITHOUT_STD="arbitrary alloc serde small-hash"

# Run these examples.
EXAMPLES=""
