#!/usr/bin/env bash
#
# Check that all types implementing encoding::Encodable are covered in the fuzz
# tests:
#   1. compare_consensus_encoding.rs - compares encoding between old and new bitcoin crates.
#   2. encoding_roundtrip.rs - verifies roundtrip encoding/decoding for all Encodable types.

set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)
COMPARE_FUZZ_FILE="$REPO_DIR/fuzz/fuzz_targets/bitcoin/compare_consensus_encoding.rs"
ROUNDTRIP_FUZZ_FILE="$REPO_DIR/fuzz/fuzz_targets/bitcoin/encoding_roundtrip.rs"
TRAIT_IMPL_JS="$REPO_DIR/target/doc/trait.impl/bitcoin_consensus_encoding/encode/trait.Encodable.js"

# Known exclusions for compare_consensus_encoding (types that don't exist in old_bitcoin 0.32 or are generic).
# Add types here that have new Encodable but no old_bitcoin equivalent.
EXCLUSIONS="Alert BlockHeight BlockTime FeeFilter HeadersMessage InventoryPayload \
ProtocolVersion Script UserAgent V2NetworkMessage"

main() {
    check_required_commands

    generate_docs
    check_trait_impl_file

    local new_types
    new_types=$(extract_new_types)

    local failed=0

    # Check compare_consensus_encoding.rs (with exclusions)
    local compare_types compare_missing
    compare_types=$(extract_compare_fuzz_types)
    compare_missing=$(find_missing_types "$new_types" "$compare_types" "$EXCLUSIONS")

    if [ -n "$compare_missing" ]; then
        echo "The following types implement encoding::Encodable but are not in compare_consensus_encoding.rs:" >&2
        for type in $compare_missing; do
            echo "  - $type" >&2
        done
        echo "Either add them to compare_consensus_encoding.rs or add to EXCLUSIONS in this script" >&2
        failed=1
    fi

    # Check encoding_roundtrip.rs (only exclude Script due to type aliases - must cover all Encodable types)
    local roundtrip_types roundtrip_missing
    roundtrip_types=$(extract_roundtrip_fuzz_types)
    roundtrip_missing=$(find_missing_types "$new_types" "$roundtrip_types" "Script")

    if [ -n "$roundtrip_missing" ]; then
        echo "The following types implement encoding::Encodable but are not in encoding_roundtrip.rs:" >&2
        for type in $roundtrip_missing; do
            echo "  - $type" >&2
        done
        echo "Add them to encoding_roundtrip.rs" >&2
        failed=1
    fi

    if [ "$failed" -ne 0 ]; then
        exit 1
    fi

    echo "All encoding::Encodable types are covered"
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

# Extract types from compare_consensus_encoding.rs.
extract_compare_fuzz_types() {
    grep -E 'compare_encoding!' "$COMPARE_FUZZ_FILE" \
        | grep -v '//' \
        | sed -E 's/.*compare_encoding!\s*\(\s*data\s*,\s*//' \
        | sed -E 's/\s*\);.*//' \
        | sed -E 's/.*:://' \
        | sed -E 's/,.*$//' \
        | grep -E '^[A-Z]' \
        | sort -u
}

# Extract types from encoding_roundtrip.rs.
extract_roundtrip_fuzz_types() {
    grep -E 'check_roundtrip!' "$ROUNDTRIP_FUZZ_FILE" \
        | grep -v '//' \
        | sed -E 's/.*check_roundtrip!\s*\(\s*data\s*,\s*//' \
        | sed -E 's/\s*\);.*//' \
        | sed -E 's/.*:://' \
        | grep -E '^[A-Z]' \
        | sort -u
}

# Find types that are in new_types but not in fuzz_types or exclusions.
find_missing_types() {
    local new_types=$1
    local fuzz_types=$2
    local exclusions=$3
    local missing=""

    for type in $new_types; do
        if ! echo "$fuzz_types" | grep -qw "$type"; then
            if [ -z "$exclusions" ] || ! echo "$exclusions" | grep -qw "$type"; then
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
