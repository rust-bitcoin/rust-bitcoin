#!/usr/bin/env bash

set -e

REPO_DIR=$(git rev-parse --show-toplevel)

listTargetFiles() {
  pushd "$REPO_DIR/fuzz" > /dev/null
  find fuzz_targets/ -type f -name "*.rs"
  popd > /dev/null
}

targetFileToName() {
  echo "$1" \
    | sed 's/^fuzz_targets\///' \
    | sed 's/\.rs$//' \
    | sed 's/\//_/g'
}

listTargetNames() {
  for target in $(listTargetFiles); do
    targetFileToName "$target"
  done
}


