#!/usr/bin/env bash
set -ex

REPO_DIR=$(git rev-parse --show-toplevel)

# shellcheck source=./fuzz-util.sh
source "$REPO_DIR/fuzz/fuzz-util.sh"

# Check that input files are correct Windows file names
checkWindowsFiles

if [ "$1" == "" ]; then
  targetFiles="$(listTargetFiles)"
else
  targetFiles=fuzz_targets/"$1".rs
fi

cargo --version
rustc --version

# Testing
cargo install --force honggfuzz --no-default-features
for targetFile in $targetFiles; do
  targetName=$(targetFileToName "$targetFile")
  echo "Fuzzing target $targetName ($targetFile)"
  if [ -d "hfuzz_input/$targetName" ]; then
    HFUZZ_INPUT_ARGS="-f hfuzz_input/$targetName/input\""
  else
    HFUZZ_INPUT_ARGS=""
  fi
  HFUZZ_RUN_ARGS="--run_time 30 --exit_upon_crash -v $HFUZZ_INPUT_ARGS" cargo hfuzz run "$targetName"

  checkReport "$targetName"
done
