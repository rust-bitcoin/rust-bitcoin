#!/bin/bash
#
# Check if PR abides by our policy.

set -euo pipefail

# When running script locally the name used for the `github.com/rust-bitcoin/rust-bitcoin` remote.
REMOTE="upstream"

main() {
    check_required_commands

    if low_level_import_usage; then
        err "Please do not import directly from low level crates, import using 'use crate::' instead"
    fi
}

# Enforces import policy.
#
# See `./policy.md` section: `### On re-exports`.
# Greps patch for imports that violate the policy, returns true if an
# violations are found.
low_level_import_usage() {
    local crates=("units" "primitives" "hashes" "internals" "io" "base58")
    local found_violation=false
    local violations;

    # Determine the base branch - common CI environment variables.
    local base_branch="$REMOTE/master"
    if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
        base_branch="$GITHUB_BASE_REF"
    elif [[ -n "${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-}" ]]; then
        base_branch="$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
    fi

    for crate in "${crates[@]}"; do
        violations=$(git diff "$base_branch"...HEAD -- '*.rs' | grep "^+" | grep -E "use ${crate}::" | grep -v "pub use ${crate}::" || true)
        if [[ -n "$violations" ]]; then
            say_err "invalid import statement: '${violations:1}'"
            found_violation=true
        fi
    done

    $found_violation
}

# Check all the commands we use are present in the current environment.
check_required_commands() {
    need_cmd grep
    need_cmd git
}

say() {
    echo "policy: $1"
}

say_err() {
    say "$1" >&2
}

err() {
    echo "$1" >&2
    exit 1
}

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1
    then err "need '$1' (command not found)"
    fi
}

#
# Main script
#
main "$@"
exit 0
