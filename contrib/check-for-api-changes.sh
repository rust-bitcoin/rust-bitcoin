#!/usr/bin/env bash
#
# Checks the public API of crates, exits with non-zero if there are currently
# changes to the public API not already committed to in the various api/*.txt
# files.

set -e

export RUSTDOCFLAGS='-A rustdoc::broken-intra-doc-links'
REPO_DIR=$(git rev-parse --show-toplevel)
API_DIR="$REPO_DIR/api"
CMD="cargo +nightly public-api --simplified"

# cargo public-api uses nightly so the toolchain must be available.
if ! cargo +nightly --version > /dev/null; then
    echo "script requires a nightly toolchain to be installed (possibly >= nightly-2023-05-24)" >&2
    exit 1
fi

pushd "$REPO_DIR/hashes" > /dev/null
$CMD --no-default-features | sort --unique > "$API_DIR/hashes/api-no-features.txt"
$CMD | sort --unique > "$API_DIR/hashes/api-default-features.txt"
$CMD --no-default-features --features=alloc | sort --unique > "$API_DIR/hashes/api-alloc.txt"
$CMD --all-features | sort --unique > "$API_DIR/hashes/api-all-features.txt"
popd > /dev/null

pushd "$REPO_DIR" > /dev/null
if [[ $(git status --porcelain api) ]]; then
    echo "You have introduced changes to the public API, commit the changes to api/ currently in your working directory" >&2
else
    echo "No changes to the current public API"
fi
popd > /dev/null
