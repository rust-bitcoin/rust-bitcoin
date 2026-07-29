#!/usr/bin/env bash
#
# Check that every error type defined in an `error` submodule is re-exported
# at the parent module level.
#
# The policy is: if a type is defined at `foo::error::BarError` then it must
# also be accessible as `foo::BarError` (i.e. re-exported by the parent module).
#
# Uses the API text files to verify the policy. Types are identified by
# `pub struct` or `pub enum` lines whose path contains `::error::` as a path
# segment (not as part of a type name). A re-export is present when the same
# type name appears at the parent path in any `pub struct`, `pub enum`, or
# `pub type` line (without the `::error::` segment).
#
# Usage: ./contrib/check-error-reexports.sh

set -euo pipefail

main() {
    check_required_commands

    local has_violations=false

    # Auto-discover all crates that have API files.
    while IFS= read -r api_file; do
        local crate
        crate=$(basename "$(dirname "$(dirname "$api_file")")")

        # Collect all types defined in ::error:: submodules.
        # We match `pub struct` and `pub enum` lines where the path contains
        # `::error::` as a segment, and the type name is the final segment
        # (no further `::` after the type name).
        local error_module_types
        error_module_types=$(grep -oP '^(?:#\[non_exhaustive\] )?pub (?:struct|enum|use) \K[A-Za-z0-9_]+(?:::[A-Za-z0-9_]+)*::error::[A-Za-z0-9_]+Error(?=\(|;|\s|<|$)' "$api_file" \
            | sort -u || true)

        if [[ -z "$error_module_types" ]]; then
            say "$crate: OK (no ::error:: submodule types found)"
            continue
        fi

        local violations=""

        while IFS= read -r type_path; do
            # Derive the expected re-export path by removing the `::error` segment.
            # e.g. foo::bar::error::BazError -> foo::bar::BazError
            local parent_path
            parent_path="${type_path/::error::/::}"

            # Escape the path for use as a fixed string in grep.
            local escaped
            escaped=$(printf '%s' "$parent_path" | sed 's/[.[\*^$]/\\&/g')

            # A re-export is present when pub struct, enum, or type appears at
            # exactly this path (followed by end-of-input, whitespace, or `(`).
            # The line may be prefixed with an attribute such as `#[non_exhaustive]`.
            if ! grep -qP "^(?:#\[[^\]]+\] )?pub (?:struct|enum|type|use) ${escaped}(?:\(|;|\s|<|$)" "$api_file"; then
                violations="${violations}  - ${type_path} -> missing ${parent_path}"$'\n'
            fi
        done <<< "$error_module_types"

        if [[ -n "$violations" ]]; then
            has_violations=true
            say_err "Crate '$crate': error types without a parent-level re-export:"
            say_err "$violations"
        else
            say "$crate: OK"
        fi
    done < <(find . -path "*/api/all-features.txt" | sort)

    if $has_violations; then
        err "Some error types are missing a re-export in the parent module."
    fi

    say "All checks passed."
}

check_required_commands() {
    need_cmd find
    need_cmd grep
    need_cmd sed
    need_cmd sort
}

say() {
    echo "$1"
}

say_err() {
    echo "$1" >&2
}

err() {
    echo "$1" >&2
    exit 1
}

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1; then
        err "need '$1' (command not found)"
    fi
}

#
# Main script
#
main "$@"
exit 0
