# No shebang, this file should not be executed.
# shellcheck disable=SC2148
#
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

# Test all these features with "std" enabled.
FEATURES_WITH_STD="rand-std serde secp-recovery bitcoinconsensus base64 ordered"

# Test all these features without "std" or "alloc" enabled.
FEATURES_WITHOUT_STD="rand serde secp-recovery bitcoinconsensus base64 ordered"

# Run these examples.
EXAMPLES="ecdsa-psbt:std,bitcoinconsensus sign-tx-segwit-v0:rand-std sign-tx-taproot:rand-std taproot-psbt:bitcoinconsensus,rand-std sighash:std"
