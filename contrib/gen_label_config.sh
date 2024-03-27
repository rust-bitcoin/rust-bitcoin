#!/usr/bin/env bash

set -euo pipefail

# Generates the label configuration using crates in the repository.
# The label configuration is appended to the labeler config file.

config=.github/labeler.yml

# Define a default value for SCAN_DIR if not set
: "${SCAN_DIR:=.}"

if [ "${1:-default}" '!=' "--force" ] && ! git diff --exit-code "$config";
then
	echo "Error: $config is not committed."
	echo "Refusing to overwrite it to prevent disaster."
	echo "Run the script with --force to override this."
	exit 1
fi

excluded_crates="fuzz|dep_test"

CRATES="`cd "$SCAN_DIR" && cargo metadata --no-deps --format-version 1 | jq -j -r '.packages | map(.manifest_path | rtrimstr("/Cargo.toml") | ltrimstr("'$PWD'/")) | join(" ")'`"

for crate in $CRATES;
do
	if echo "$crate" | grep -qE "$excluded_crates";
	then
		continue
	fi

	echo "C-$crate:" >> "$config"
	echo "  - changed-files:" >> "$config"
	echo "    - any-glob-to-any-file: $crate/**" >> "$config"
done
