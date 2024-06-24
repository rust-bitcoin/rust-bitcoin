# No shebang, this file should not be executed.
# shellcheck disable=SC2148
#
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

# Test all these features with "std" enabled.
FEATURES_WITH_STD="serde bitcoinconsensus-std base58-std bech32-std rand-std ordered secp256k1"

# Test all these features without "std" or "alloc" enabled.
FEATURES_WITHOUT_STD="serde bitcoinconsensus base58 bech32 ordered secp256k1"

# Run these examples.
EXAMPLES=""
