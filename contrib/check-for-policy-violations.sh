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
    # Crate doing the import and the low level crate it re-exports.
    local pairs=("primitives:units" "bitcoin:units" "bitcoin:primitives")
    local found_violation=false
    local violations;
    # An added line where the import is the first thing on it, `use`, `pub use`
    # or `pub(crate) use`. But comments that mention `use units::` do not match
    # because the line must start with `use` or `pub`, not `//`.
    local import="^\+\s*(pub(\([a-z]+\))? )?use"
    # An added line that is a plain `pub use`, a re-export, which is allowed.
    local reexport="^\+\s*pub use"

    # Determine the base branch - common CI environment variables.
    local base_branch="$REMOTE/master"
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        base_branch="origin/${GITHUB_BASE_REF:-$GITHUB_REF_NAME}"
    elif [[ -n "${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-}" ]]; then
        base_branch="$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
    fi

    for pair in "${pairs[@]}"; do
        # Split the pair at the colon, importing crate first, low level crate second.
        local dir="${pair%%:*}"
        local crate="${pair##*:}"

        # Lines the patch adds to the importing crate that import from the low level one.
        violations=$(git diff "$base_branch"...HEAD -- "$dir/src/*.rs" | grep -E "$import ${crate}::" | grep -vE "$reexport ${crate}::" || true)
        if [[ -n "$violations" ]]; then
            # Drop the leading `+` of the diff line.
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
