#!/usr/bin/env bash

# Sort order is affected by locale. See `man sort`.
# > Set LC_ALL=C to get the traditional sort order that uses native byte values.
export LC_ALL=C

REPO_DIR=$(git rev-parse --show-toplevel)

listTargetFiles() {
  pushd "$REPO_DIR/fuzz" > /dev/null || exit 1
  find fuzz_targets/ -type f -name "*.rs" | sort
  popd > /dev/null || exit 1
}

targetFileToName() {
  echo "$1" \
    | sed 's/^fuzz_targets\///' \
    | sed 's/\.rs$//' \
    | sed 's/\//_/g' \
    | sed 's/^_//g'
}

# Utility function to avoid CI failures on Windows
checkWindowsFiles() {
  incorrectFilenames=$(find . -type f -name "*,*" -o -name "*:*" -o -name "*<*" -o -name "*>*" -o -name "*|*" -o -name "*\?*" -o -name "*\**" -o -name "*\"*" | wc -l)
  if [ "$incorrectFilenames" -gt 0 ]; then
    echo "Bailing early because there is a Windows-incompatible filename in the tree."
    exit 2
  fi
}

# Checks whether a fuzz case has artifacts, and dumps them in hex
checkReport() {
  artifactDir="fuzz/artifacts/$1"
  if [ -d "$artifactDir" ] && [ -n "$(ls -A "$artifactDir" 2>/dev/null)" ]; then
    echo "Artifacts found for target: $1"
    for artifact in "$artifactDir"/*; do
      if [ -f "$artifact" ]; then
        echo "Artifact: $(basename "$artifact")"
        xxd -p -c10000 < "$artifact"
      fi
    done
    exit 1
  fi
}
