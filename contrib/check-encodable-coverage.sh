#!/usr/bin/env bash
#
# Check that all types implementing encoding::Encodable are covered in the fuzz
# test that compares encoding between old and new bitcoin crates.

set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)
FUZZ_FILE="$REPO_DIR/fuzz/fuzz_targets/bitcoin/compare_consensus_encoding.rs"
TRAIT_IMPL_JS="$REPO_DIR/target/doc/trait.impl/bitcoin_consensus_encoding/encode/trait.Encodable.js"

# Known exclusions (types that don't exist in old_bitcoin 0.32 or are generic).
# Add types here that have new Encodable but no old_bitcoin equivalent.
EXCLUSIONS="Alert BlockHeight BlockTime FeeFilter HeadersMessage InventoryPayload \
ProtocolVersion Script UserAgent V2NetworkMessage"

main() {
    check_required_commands

    generate_docs
    check_trait_impl_file

    local new_types fuzz_types missing
    new_types=$(extract_new_types)
    fuzz_types=$(extract_fuzz_types)
    missing=$(find_missing_types "$new_types" "$fuzz_types")

    if [ -n "$missing" ]; then
        echo "The following types implement encoding::Encodable but are not in the fuzz test:" >&2
        for type in $missing; do
            echo "  - $type" >&2
        done
        err "Either add them to compare_consensus_encoding.rs or add to EXCLUSIONS in this script"
    fi

    echo "All encoding::Encodable types are covered (or excluded)"
}

generate_docs() {
    echo "Generating docs to discover Encodable implementors..."
    cargo doc --workspace --no-deps --quiet
}

check_trait_impl_file() {
    if [ ! -f "$TRAIT_IMPL_JS" ]; then
        err "Could not find trait implementors file at $TRAIT_IMPL_JS"
    fi
}

# Extract type names from the rustdoc implementors JS file.
# Split on '>' then find lines starting with TypeName< pattern, excluding "Encodable" itself.
extract_new_types() {
    tr '>' '\n' < "$TRAIT_IMPL_JS" \
        | grep -oE '^[A-Z][a-zA-Z0-9_]+<' \
        | sed 's/<$//' \
        | grep -v '^Encodable$' \
        | sort -u
}

# Extract types from the fuzz test file.
extract_fuzz_types() {
    grep -E 'compare_encoding!' "$FUZZ_FILE" \
        | grep -v '//' \
        | sed -E 's/.*compare_encoding!\s*\(\s*data\s*,\s*//' \
        | sed -E 's/\s*\);.*//' \
        | sed -E 's/.*:://' \
        | sed -E 's/,.*$//' \
        | grep -E '^[A-Z]' \
        | sort -u
}

# Find types that are in new_types but not in fuzz_types or exclusions.
find_missing_types() {
    local new_types=$1
    local fuzz_types=$2
    local missing=""

    for type in $new_types; do
        if ! echo "$fuzz_types" | grep -qw "$type"; then
            if ! echo "$EXCLUSIONS" | grep -qw "$type"; then
                missing="$missing $type"
            fi
        fi
    done

    echo "$missing"
}

check_required_commands() {
    need_cmd grep
    need_cmd sed
    need_cmd tr
}

err() {
    echo "ERROR: $1" >&2
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
