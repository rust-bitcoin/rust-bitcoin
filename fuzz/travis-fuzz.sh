#!/bin/bash
set -e

# Check that input files are correct Windows file names
incorrectFilenames=$(find . -type f -name "*,*" -o -name "*:*" -o -name "*<*" -o -name "*>*" -o -name "*|*" -o -name "*\?*" -o -name "*\**" -o -name "*\"*" | wc -l)

if [ ${incorrectFilenames} -gt 0 ]; then
	exit 2
fi

if [ "$1" == "" ]; then
	TARGETS=fuzz_targets/*
else
	TARGETS=fuzz_targets/"$1".rs
fi

cargo --version
rustc --version

# Testing
cargo install --force honggfuzz --no-default-features
for TARGET in $TARGETS; do
	echo "Fuzzing target $TARGET"
	FILENAME=$(basename $TARGET)
	FILE="${FILENAME%.*}"
	if [ -d hfuzz_input/$FILE ]; then
	    HFUZZ_INPUT_ARGS="-f hfuzz_input/$FILE/input"
	fi
	HFUZZ_BUILD_ARGS="--features honggfuzz_fuzz" HFUZZ_RUN_ARGS="--run_time 30 --exit_upon_crash -v $HFUZZ_INPUT_ARGS" cargo hfuzz run $FILE

	if [ -f hfuzz_workspace/$FILE/HONGGFUZZ.REPORT.TXT ]; then
		cat hfuzz_workspace/$FILE/HONGGFUZZ.REPORT.TXT
		for CASE in hfuzz_workspace/$FILE/SIG*; do
			cat $CASE | xxd -p
		done
		exit 1
	fi
done
