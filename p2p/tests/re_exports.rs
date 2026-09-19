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
