#!/usr/bin/env bash

# Fuzz the provided target(s), or all targets if none provided.
#
# Usage: fuzz.sh [TARGET] [-max_total_time=SECONDS] [-cycle]
#
# Options:
#   TARGET                  Specific fuzz target to run (e.g., bitcoin_deserialize_block)
#   -max_total_time=SECONDS Fuzzing duration in seconds (default: 100 in normal mode, 3600 in cycle mode)
#   -cycle                  Continuous fuzzing: loop through all targets indefinitely,
#                           running corpus minimization after each target, with low process priority

set -euox pipefail

REPO_DIR=$(git rev-parse --show-toplevel)

# can't find the file because of the ENV var
# shellcheck source=/dev/null
source "$REPO_DIR/fuzz/fuzz-util.sh"

target=
max_total_time=
cycle_mode=false

for arg in "$@"; do
  case "$arg" in
    -max_total_time=*)
      max_total_time="${arg#-max_total_time=}"
      ;;
    -cycle)
      cycle_mode=true
      ;;
    -*)
      echo "Unknown option: $arg"
      exit 2
      ;;
    *)
      if [ -n "$target" ]; then
        echo "Unexpected argument: $arg"
        exit 2
      fi
      target="$arg"
      ;;
  esac
done

# Set default max_total_time based on mode, 1 hour for cycle, 100 seconds for default.
if [ -z "$max_total_time" ]; then
  if [ "$cycle_mode" = true ]; then
    max_total_time=3600
  else
    max_total_time=100
  fi
fi

case "$max_total_time" in
  ''|*[!0-9]*)
    echo "-max_total_time must be a non-negative integer number of seconds"
    exit 2
    ;;
esac

# Check that input files are correct Windows file names
checkWindowsFiles

if [ -z "$target" ]; then
  targetFiles="$(listTargetFiles)"
else
  targetFiles=fuzz_targets/"$target".rs
fi

cargo --version
rustc --version

cargo install --force --locked --version 0.12.0 cargo-fuzz
while :; do
  for targetFile in $targetFiles; do
    targetName=$(targetFileToName "$targetFile")

    echo "Fuzzing target $targetName ($targetFile) for $max_total_time seconds"
    # Enable fuzz stubs in the hashes and cryptography libraries by default,
    # unless we are fuzzing the hashes targets themselves.
    fuzz_rustflags=''
    if [[ ! "$targetName" =~ ^hashes_ ]]; then
      fuzz_rustflags='--cfg=hashes_fuzz --cfg=secp256k1_fuzz'
    fi
    # cargo-fuzz will check for the corpus at fuzz/corpus/<target>
    # Use chrt to run at SCHED_IDLE priority (lowest) to avoid blocking other work.
    chrt_cmd=''
    if [ "$cycle_mode" = true ]; then
      chrt_cmd='chrt -i 0'
    fi
    RUSTFLAGS="$RUSTFLAGS $fuzz_rustflags" $chrt_cmd cargo +nightly fuzz run "$targetName" -- -max_total_time="$max_total_time"

    echo "Minimizing corpus for target $targetName"
    cargo +nightly fuzz cmin "$targetName"

    # Check for artifacts/crashes in normal mode.
    if [ "$cycle_mode" = false ]; then
      checkReport "$targetName"
    fi
  done

  # Exit after one cycle if not in cycle mode.
  if [ "$cycle_mode" = false ]; then
    break
  fi
done
