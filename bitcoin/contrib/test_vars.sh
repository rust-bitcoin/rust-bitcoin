#!/usr/bin/env bash

# Test all these features with "std" enabled.
FEATURES_WITH_STD="rand-std serde secp-recovery bitcoinconsensus-std base64 ordered"

# Test all these features without "std" or "alloc" enabled.
FEATURES_WITHOUT_STD="rand serde secp-recovery bitcoinconsensus base64 ordered"

# Run and lint these examples.
EXAMPLES="ecdsa-psbt:std,bitcoinconsensus sign-tx-segwit-v0:rand-std sign-tx-taproot:rand-std taproot-psbt:bitcoinconsensus,rand-std sighash:std"
