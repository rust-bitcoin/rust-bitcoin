#!/usr/bin/env bash

# Generates one fuzz target file per Encodable/Decodable type under
# fuzz_targets/bitcoin/encoding_roundtrip/.
#
# After running this script, re-run fuzz/generate-files.sh to update Cargo.toml
# and the fuzz CI workflow.

set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)
TARGET_DIR="$REPO_DIR/fuzz/fuzz_targets/bitcoin/encoding_roundtrip"

mkdir -p "$TARGET_DIR"

# Types tested with check_roundtrip (standard Encodable + Decodable).
ROUNDTRIP_TYPES=(
    "bitcoin::Amount"
    "bitcoin::Block"
    "bitcoin::BlockHash"
    "bitcoin::BlockHeight"
    "bitcoin::BlockTime"
    "bitcoin::CompactTarget"
    "bitcoin::OutPoint"
    "bitcoin::Sequence"
    "bitcoin::Transaction"
    "bitcoin::TxIn"
    "bitcoin::TxMerkleNode"
    "bitcoin::TxOut"
    "bitcoin::Witness"
    "bitcoin::WitnessMerkleNode"
    "bitcoin::absolute::LockTime"
    "bitcoin::block::Header"
    "bitcoin::block::Version"
    "bitcoin::transaction::Version"
    "p2p::Magic"
    "p2p::ProtocolVersion"
    "p2p::ServiceFlags"
    "p2p::address::AddrV1Message"
    "p2p::address::AddrV2"
    "p2p::address::AddrV2Message"
    "p2p::address::Address"
    "p2p::bip152::BlockTransactions"
    "p2p::bip152::BlockTransactionsRequest"
    "p2p::bip152::HeaderAndShortIds"
    "p2p::bip152::PrefilledTransaction"
    "p2p::bip152::ShortId"
    "p2p::merkle_tree::MerkleBlock"
    "p2p::merkle_tree::PartialMerkleTree"
    "p2p::message::AddrPayload"
    "p2p::message::AddrV2Payload"
    "p2p::message::CommandString"
    "p2p::message::FeeFilter"
    "p2p::message::HeadersMessage"
    "p2p::message::InventoryPayload"
    "p2p::message::NetworkHeader"
    "p2p::message::Ping"
    "p2p::message::Pong"
    "p2p::message::V1MessageHeader"
    "p2p::message::V1NetworkMessage"
    "p2p::message_blockdata::BlockLocator"
    "p2p::message_blockdata::GetBlocksMessage"
    "p2p::message_blockdata::GetHeadersMessage"
    "p2p::message_blockdata::Inventory"
    "p2p::message_bloom::BloomFlags"
    "p2p::message_bloom::FilterAdd"
    "p2p::message_bloom::FilterLoad"
    "p2p::message_compact_blocks::SendCmpct"
    "p2p::message_filter::CFCheckpt"
    "p2p::message_filter::CFHeaders"
    "p2p::message_filter::CFilter"
    "p2p::message_filter::FilterHash"
    "p2p::message_filter::FilterHeader"
    "p2p::message_filter::GetCFCheckpt"
    "p2p::message_filter::GetCFHeaders"
    "p2p::message_filter::GetCFilters"
    "p2p::message_network::Alert"
    "p2p::message_network::Reject"
    "p2p::message_network::RejectReason"
    "p2p::message_network::UserAgent"
    "p2p::message_network::VersionMessage"
    "p2p::message_erlay::SendTxRcnCl"
)

# Types tested with check_script_roundtrip (Buf types that Deref to their Encodable target).
SCRIPT_ROUNDTRIP_TYPES=(
    "bitcoin::RedeemScriptBuf"
    "bitcoin::ScriptPubKeyBuf"
    "bitcoin::ScriptSigBuf"
    "bitcoin::TapScriptBuf"
    "bitcoin::WitnessScriptBuf"
)

# Convert a Rust type path to a snake_case filename stem.
#
# bitcoin::Amount              -> amount
# bitcoin::block::Header       -> block_header
# bitcoin::transaction::Version -> transaction_version
# p2p::Magic                   -> p2p_magic
# p2p::bip152::HeaderAndShortIds -> p2p_bip152_header_and_short_ids
type_to_stem() {
    local type="$1"
    local result

    # Strip the `bitcoin::` crate prefix; leave `p2p::` intact so p2p types
    # stay distinguishable from bitcoin types with the same short name.
    if [[ "$type" == bitcoin::* ]]; then
        result="${type#bitcoin::}"
    else
        result="$type"
    fi

    # Replace `::` with `_`.
    result="${result//::/_}"

    # CamelCase -> snake_case: insert `_` before each uppercase letter, then
    # lowercase everything, then collapse any runs of `__` caused by the
    # inserted underscores landing next to existing ones.
    result=$(echo "$result" \
        | sed 's/\([A-Z]\)/_\1/g' \
        | tr '[:upper:]' '[:lower:]' \
        | sed 's/__*/_/g' \
        | sed 's/^_//')

    echo "$result"
}

generate_roundtrip() {
    local type="$1"
    local stem filepath
    stem="$(type_to_stem "$type")"
    filepath="$TARGET_DIR/$stem.rs"

    cat > "$filepath" <<RUST
#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use bitcoin_fuzz::check_roundtrip;
use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fuzz_target!(|data: &[u8]| {
    check_roundtrip::<$type>(data);
});
RUST
}

generate_script_roundtrip() {
    local type="$1"
    local stem filepath
    stem="$(type_to_stem "$type")"
    filepath="$TARGET_DIR/$stem.rs"

    cat > "$filepath" <<RUST
#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use bitcoin_fuzz::check_script_roundtrip;
use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fuzz_target!(|data: &[u8]| {
    check_script_roundtrip::<$type>(data);
});
RUST
}

for type in "${ROUNDTRIP_TYPES[@]}"; do
    generate_roundtrip "$type"
done

for type in "${SCRIPT_ROUNDTRIP_TYPES[@]}"; do
    generate_script_roundtrip "$type"
done

echo "Generated $(( ${#ROUNDTRIP_TYPES[@]} + ${#SCRIPT_ROUNDTRIP_TYPES[@]} )) targets in $TARGET_DIR"
