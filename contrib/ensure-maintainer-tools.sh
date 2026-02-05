#!/usr/bin/env bash
#
# Ensure maintainer tools are available locally for CI task execution.

set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)

cd "$REPO_DIR"

if ! command -v cargo-rbmt >/dev/null 2>&1; then
    echo "Error: cargo-rmbt is required for maintainer tools but not found in PATH" >&2
    echo "Please ensure it's available in your environment or install cargo-rbmt using:" >&2
    echo "cargo +stable install --git https://github.com/rust-bitcoin/rust-bitcoin-maintainer-tools.git --rev \"$(cat "$REPO_DIR/rbmt-version")\" cargo-rbmt --locked" >&2
    exit 1
fi
