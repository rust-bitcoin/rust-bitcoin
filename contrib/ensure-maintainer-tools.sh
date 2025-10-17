#!/usr/bin/env bash
#
# Ensure maintainer tools are available locally for CI task execution.

set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)
MAINTAINER_TOOLS_REF=$(cat "$REPO_DIR/maintainer-tools-version")

cd "$REPO_DIR"

if [ ! -d ".maintainer-tools" ]; then
    echo "Fetching maintainer tools..."
    git clone "https://github.com/rust-bitcoin/rust-bitcoin-maintainer-tools.git" ".maintainer-tools"
    cd ".maintainer-tools"
    git checkout "$MAINTAINER_TOOLS_REF"
else
    cd ".maintainer-tools"
    CURRENT_REF=$(git rev-parse HEAD)
    if [ "$CURRENT_REF" != "$MAINTAINER_TOOLS_REF" ]; then
        echo "Updating maintainer tools to $MAINTAINER_TOOLS_REF"
        git fetch
        git checkout "$MAINTAINER_TOOLS_REF"
    fi
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required for maintainer tools but not found in PATH" >&2
    echo "Please install jq or ensure it's available in your environment" >&2
    exit 1
fi
