#!/usr/bin/env bash
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

# Test all these features with "std" enabled.
FEATURES_WITH_STD="crypto-std crypto-serde-std serde bitcoinconsensus-std"

# Test all these features without "std" enabled.
FEATURES_WITHOUT_STD="alloc serde bitcoinconsensus crypto ordered"

# Run these examples.
EXAMPLES=""
