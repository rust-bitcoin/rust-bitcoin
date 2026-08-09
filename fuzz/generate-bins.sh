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
list_target_files() {
  pushd "$REPO_DIR/fuzz" > /dev/null || exit 1
  find fuzz_targets/ -type f -name "*.rs" | sort
  popd > /dev/null || exit 1
}

# Convert fuzz target file path to target name
# Example: fuzz_targets/bitcoin/deserialize_block.rs -> bitcoin_deserialize_block
target_file_to_name() {
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
for target_file in $(list_target_files); do
    target_name=$(target_file_to_name "$target_file")
    cat >> "$CARGO_TOML_TMP" <<EOF
[[bin]]
name = "$target_name"
path = "$target_file"
test = false
doc = false
bench = false

EOF
done

mv "$CARGO_TOML_TMP" "$CARGO_TOML"
