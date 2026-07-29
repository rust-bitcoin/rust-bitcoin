#!/usr/bin/env bash
#
# Discovers the [[bin]] fuzz targets for the fuzz/Cargo.toml,
# while preserving the rest of the manifest.

set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)

# can't find the file because of the ENV var
# shellcheck source=/dev/null
source "$REPO_DIR/fuzz/fuzz-util.sh"
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
