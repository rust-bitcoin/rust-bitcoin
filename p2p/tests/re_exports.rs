// SPDX-License-Identifier: CC0-1.0

//! Test that the public message types are re-exported at the crate root.
//!
//! This is a compile-time check: if a re-export is removed the test stops building.

#![allow(unused_imports)]

#[test]
fn compact_block_types_are_re_exported_at_crate_root() {
    use bitcoin_p2p_messages::{
        BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds, PrefilledTransaction,
        SendCmpct, ShortId,
    };
}

#[test]
fn filter_types_are_re_exported_at_crate_root() {
    use bitcoin_p2p_messages::{
        CFCheckpt, CFHeaders, CFilter, FilterHash, FilterHeader, GetCFCheckpt, GetCFHeaders,
        GetCFilters,
    };
}

#[test]
fn bloom_and_merkle_types_are_re_exported_at_crate_root() {
    use bitcoin_p2p_messages::{BloomFlags, FilterAdd, FilterLoad, MerkleBlock, PartialMerkleTree};
}

#[test]
fn blockdata_and_feature_types_are_re_exported_at_crate_root() {
    use bitcoin_p2p_messages::{
        BlockLocator, Feature, FeatureData, FeatureId, GetBlocksMessage, GetHeadersMessage,
        Inventory, SendTxRcnCl,
    };
}

#[test]
#[cfg(feature = "std")]
fn address_types_are_re_exported_at_crate_root() {
    use bitcoin_p2p_messages::{AddrV1Message, AddrV2, AddrV2Message, Address};
}

#[test]
#[cfg(feature = "std")]
fn message_types_are_re_exported_at_crate_root() {
    use bitcoin_p2p_messages::{
        AddrPayload, AddrV2Payload, CommandString, FeeFilter, HeadersMessage, InventoryPayload,
        NetworkHeader, NetworkMessage, Ping, Pong, V1MessageHeader, V1NetworkMessage,
        V2NetworkMessage,
    };
}
