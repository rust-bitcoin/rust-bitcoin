#!/bin/bash
#
# List all fuzz targets

set -e

for dir in bitcoin/fuzz/fuzz_targets hashes/fuzz/fuzz_targets
do
    ls $dir
done | sort

exit 0
