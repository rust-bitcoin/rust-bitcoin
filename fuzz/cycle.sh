#!/usr/bin/env bash

# Continuously cycle over fuzz targets running each for 1 hour.
# It uses chrt SCHED_IDLE so that other process takes priority.
#
# For cargo-fuzz usage see https://github.com/rust-fuzz/cargo-fuzz?tab=readme-ov-file#usage

set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)
# can't find the file because of the ENV var
# shellcheck source=/dev/null
source "$REPO_DIR/fuzz/fuzz-util.sh"

while :
do
  for targetFile in $(listTargetFiles); do
    targetName=$(targetFileToName "$targetFile")
    echo "Fuzzing target $targetName ($targetFile)"

    # fuzz for one hour
    chrt -i 0 cargo +nightly fuzz run "$targetName" -- -max_total_time=3600
    cargo +nightly fuzz cmin "$targetName" 
  done
done

