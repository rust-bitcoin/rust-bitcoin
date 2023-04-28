#!/usr/bin/env bash

# Continuosly cycle over fuzz targets running each for 1 hour.
# It uses chrt SCHED_IDLE so that other process takes priority.
#
# For hfuzz options see https://github.com/google/honggfuzz/blob/master/docs/USAGE.md

set -e
REPO_DIR=$(git rev-parse --show-toplevel)
# shellcheck source=./fuzz-util.sh
source "$REPO_DIR/fuzz/fuzz-util.sh"

while :
do
  for targetFile in $(listTargetFiles); do
    targetName=$(targetFileToName "$targetFile")
    echo "Fuzzing target $targetName ($targetFile)"

    # fuzz for one hour
    HFUZZ_RUN_ARGS='--run_time 3600' chrt -i 0 cargo hfuzz run "$targetName"
    # minimize the corpus
    HFUZZ_RUN_ARGS="-i hfuzz_workspace/$targetName/input/ -P -M" chrt -i 0 cargo hfuzz run "$targetName"
  done
done

