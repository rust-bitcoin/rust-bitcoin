#!/usr/bin/env bash

set -euo pipefail

# Generates the label configuration using crates in the repository.
# The label configuration is appended to the labeler config file.
#
# Label names are derived from each crate's directory path, not its Cargo.toml
# package name. Renaming a crate directory therefore orphans the old `C-<old-name>`
# label: this script starts generating `C-<new-name>` for future PRs, but any PR
# already carrying the old label keeps it until it gets a new push, since
# actions/labeler only removes labels it can see in the current config. When you
# rename a crate directory, also delete (or rename) the stale `C-<old-name>` label
# in the repository settings so it doesn't linger. See
# https://github.com/rust-bitcoin/rust-bitcoin/issues/6706.

config=.github/labeler.yml

# Define a default value for SCAN_DIR if not set
: "${SCAN_DIR:=.}"

if [ "${1:-default}" != "--force" ] && ! git diff --exit-code "$config";
then
	echo "Error: $config is not committed."
	echo "Refusing to overwrite it to prevent disaster."
	echo "Run the script with --force to override this."
	exit 1
fi

excluded_crates="fuzz"

CRATES="$(cd "$SCAN_DIR" && cargo metadata --no-deps --format-version 1 | jq -j -r '.packages | map(.manifest_path | rtrimstr("/Cargo.toml") | ltrimstr("'"$PWD"'/")) | join(" ")')"

for crate in $CRATES;
do
	if echo "$crate" | grep -qE "$excluded_crates";
	then
		continue
	fi

	{
		echo "C-$crate:"
		echo "  - changed-files:"
		echo "    - any-glob-to-any-file: $crate/**"
	} >> "$config"
done
