#!/usr/bin/env bash
#
# Discovers the [[bin]] fuzz targets for the fuzz/Cargo.toml,
# while preserving the rest of the manifest.

set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)

# Sort order is affected by locale. See `man sort`.
# > Set LC_ALL=C to get the traditional sort order that uses native byte values.
export LC_ALL=C

# List all fuzz target files.
listTargetFiles() {
  pushd "$REPO_DIR/fuzz" > /dev/null || exit 1
  find fuzz_targets/ -type f -name "*.rs" | sort
  popd > /dev/null || exit 1
}

# Convert fuzz target file path to target name
# Example: fuzz_targets/bitcoin/deserialize_block.rs -> bitcoin_deserialize_block
targetFileToName() {
  echo "$1" \
    | sed 's/^fuzz_targets\///' \
    | sed 's/\.rs$//' \
    | sed 's/\//_/g' \
    | sed 's/^_//g'
}

source "$REPO_DIR/fuzz/generate-encoding-roundtrip.sh"

CARGO_TOML="$REPO_DIR/fuzz/Cargo.toml"
CARGO_TOML_TMP=$(mktemp)
# Ensure cleanup on exit.
trap 'rm -f "$CARGO_TOML_TMP"' EXIT

# Extract the unmanged part of the manifest (everything before the first [[bin]]).
awk '/^\[\[bin\]\]/{exit} {print}' "$CARGO_TOML" > "$CARGO_TOML_TMP"

# Generate the [[bin]] sections.
for targetFile in $(listTargetFiles); do
    targetName=$(targetFileToName "$targetFile")
    cat >> "$CARGO_TOML_TMP" <<EOF
[[bin]]
name = "$targetName"
path = "$targetFile"
test = false
doc = false
bench = false

EOF
done

mv "$CARGO_TOML_TMP" "$CARGO_TOML"
