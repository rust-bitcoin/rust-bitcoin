#!/usr/bin/env bash

# Test all these features with "std" enabled.
FEATURES_WITH_STD="io serde small-hash schemars"

# Test all these features without "std" enabled.
FEATURES_WITHOUT_STD="alloc serde small-hash"

# Run address sanitizer with these features.
ASAN_FEATURES="std io serde"

# Run and lint these examples.
EXAMPLES=""
