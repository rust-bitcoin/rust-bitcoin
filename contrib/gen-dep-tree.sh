#!/usr/bin/env bash
# 
# Generate dependency tree for all workspace packages except fuzz.
set -euo pipefail

exec cargo tree \
    --workspace \
    --exclude bitcoin-fuzz \
    --all-features \
    --edges=no-dev,no-build \
    --format='{lib}' \
    --no-dedupe \
    --prune=serde_json \
    --prune=rand \
    --prune=bincode \
    --prune=serde
