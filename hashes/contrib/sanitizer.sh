#!/usr/bin/env bash
#
# Run the Address/Memory Sanitizer tests.

set -euox pipefail

# Run the sanitizer with these features.
FEATURES="std bitcoin-io serde"

cargo clean
CC='clang -fsanitize=address -fno-omit-frame-pointer'                                        \
  RUSTFLAGS='-Zsanitizer=address -Clinker=clang -Cforce-frame-pointers=yes'                    \
  ASAN_OPTIONS='detect_leaks=1 detect_invalid_pointer_pairs=1 detect_stack_use_after_return=1' \
  cargo test --lib --no-default-features --features="$FEATURES" -Zbuild-std --target x86_64-unknown-linux-gnu

# There is currently a bug in the MemorySanitizer (MSAN) - disable the job for now.
#
# cargo clean
# CC='clang -fsanitize=memory -fno-omit-frame-pointer'                                         \
    #   RUSTFLAGS='-Zsanitizer=memory -Zsanitizer-memory-track-origins -Cforce-frame-pointers=yes'   \
    #   cargo test --lib --no-default-features --features="$FEATURES" -Zbuild-std --target x86_64-unknown-linux-gnu
