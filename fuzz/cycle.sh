#!/bin/bash

# Continuosly cycle over fuzz targets running each for 1 hour.
# It uses chrt SCHED_IDLE so that other process takes priority.
#
# For hfuzz options see https://github.com/google/honggfuzz/blob/master/docs/USAGE.md

export HFUZZ_BUILD_ARGS='--features honggfuzz_fuzz'

while :
do
  for FILE in fuzz_targets/*;
  do
    TARGET=$(echo $FILE | cut -c 14- | cut -f 1 -d '.')

    # fuzz for one hour
    HFUZZ_RUN_ARGS='--run_time 3600' chrt -i 0 cargo hfuzz run $TARGET

    # minimize the corpus
    HFUZZ_RUN_ARGS="-i hfuzz_workspace/$TARGET/input/ -P -M" chrt -i 0 cargo hfuzz run $TARGET
  done
done

