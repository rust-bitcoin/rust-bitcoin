#!/usr/bin/env bash
# This script is used to briefly fuzz every target when no target is provided. Otherwise, it will briefly fuzz the
# provided target

set -euox pipefail

REPO_DIR=$(git rev-parse --show-toplevel)

# can't find the file because of the ENV var
# shellcheck source=/dev/null
source "$REPO_DIR/fuzz/fuzz-util.sh"

# Check that input files are correct Windows file names
checkWindowsFiles

if [ -z "${1:-}" ]; then
  targetFiles="$(listTargetFiles)"
else
  targetFiles=fuzz_targets/"$1".rs
fi

cargo --version
rustc --version

# Testing
cargo install --force cargo-fuzz
for targetFile in $targetFiles; do
  targetName=$(targetFileToName "$targetFile")
  echo "Fuzzing target $targetName ($targetFile)"
  # cargo-fuzz will check for the corpus at fuzz/corpus/<target>
  cargo +nightly fuzz run "$targetName" -- -runs=10000
  checkReport "$targetName"
done
