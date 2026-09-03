#!/usr/bin/env bash

# Shared RUSTFLAGS selection for the fuzz targets, sourced by fuzz scripts.

# Use stubs as hashes and cryptography libraries by default, unless targets
# are fuzzing the hashes themselves.
fuzz_rustflags() {
  local target="${1:?fuzz_rustflags TARGET}"
  if [[ "$target" =~ ^hashes_ ]]; then
    echo ''
  else
    echo '--cfg=hashes_fuzz --cfg=secp256k1_fuzz'
  fi
}
