#!/usr/bin/env bash
#
# Checks that a change to `bitcoin-internals` source is accompanied by a version bump.
#
# Usage: check-internals-version.sh BASELINE
#   BASELINE: Git revision to compare against (commit, branch, tag, etc).
#
# Exit Codes:
#   0 - Success. Either `internals/` is unchanged, or it changed and the version was bumped.
#   1 - Failure. `internals/` changed but `internals/Cargo.toml`'s version was not bumped.

set -euo pipefail

WORKSPACE_ROOT="$(git rev-parse --show-toplevel)"
INTERNALS_DIR="$WORKSPACE_ROOT/internals"
INTERNALS_MANIFEST="$INTERNALS_DIR/Cargo.toml"

main() {
    check_required_commands

    local baseline="${1:?Usage: check-internals-version.sh BASELINE}"

    if ! internals_changed "$baseline"; then
        echo "No changes to $INTERNALS_DIR/ detected. OK."
        return 0
    fi

    echo "Changes detected in bitcoin-internals!"
    changed_files "$baseline"

    if version_bumped "$baseline"; then
        local new_version
        new_version=$(internals_version HEAD)
        echo "Version was bumped to $new_version. OK."
        return 0
    fi

    err "bitcoin-internals was changed, but the version was not bumped!"
}

# Returns list of changed files in internals between the given baseline and HEAD, excluding docs.
changed_files() {
    local baseline="$1"
    git diff --name-only "$baseline"...HEAD -- "$INTERNALS_DIR" \
        ":!$INTERNALS_DIR/CHANGELOG.md" ":!$INTERNALS_DIR/README.md"
}

# Returns true (0) if any non-documentation changes between the given baseline and HEAD.
internals_changed() {
    local baseline="$1"
    [[ -n "$(changed_files "$baseline")" ]]
}

# Returns true (0) if internal's version differs between the given baseline and HEAD.
version_bumped() {
    local baseline="$1"
    local old_version new_version
    old_version=$(internals_version "$baseline")
    new_version=$(internals_version HEAD)

    [[ "$old_version" != "$new_version" ]]
}

# Extracts the `version = "..."` value from internal's manifest at a given git ref.
internals_version() {
    local ref="$1"
    git show "$ref:$INTERNALS_MANIFEST" 2>/dev/null \
        | awk -F'"' '/^version[[:space:]]*=/{print $2; exit}'
}

check_required_commands() {
    need_cmd git
    need_cmd awk
}

err() {
    local msg="$*"
    echo "ERROR: $msg" >&2
    exit 1
}

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1; then
        err "need '$1' (command not found)"
    fi
}

main "$@"
