// SPDX-License-Identifier: CC0-1.0

//!
//! BIP-0152  Compact Blocks network messages

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bitcoin::bip152;

use crate::consensus::impl_consensus_encoding;

/// sendcmpct message
#[derive(PartialEq, Eq, Clone, Debug, Copy, PartialOrd, Ord, Hash)]
pub struct SendCmpct {
    /// Request to be sent compact blocks.
    pub send_compact: bool,
    /// Compact Blocks protocol version number.
    pub version: u64,
}
impl_consensus_encoding!(SendCmpct, send_compact, version);

/// cmpctblock message
///
/// Note that the rules for validation before relaying compact blocks is
/// different from headers and regular block messages. Thus, you shouldn't use
/// compact blocks when relying on an upstream full node to have validated data
/// being forwarded to you.
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct CmpctBlock {
    /// The Compact Block.
    pub compact_block: bip152::HeaderAndShortIds,
}
impl_consensus_encoding!(CmpctBlock, compact_block);

/// getblocktxn message
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct GetBlockTxn {
    /// The block transactions request.
    pub txs_request: bip152::BlockTransactionsRequest,
}
impl_consensus_encoding!(GetBlockTxn, txs_request);

/// blocktxn message
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct BlockTxn {
    /// The requested block transactions.
    pub transactions: bip152::BlockTransactions,
}
impl_consensus_encoding!(BlockTxn, transactions);

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for SendCmpct {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(SendCmpct { send_compact: u.arbitrary()?, version: u.arbitrary()? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for CmpctBlock {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(CmpctBlock { compact_block: u.arbitrary()? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for GetBlockTxn {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(GetBlockTxn { txs_request: u.arbitrary()? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for BlockTxn {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(BlockTxn { transactions: u.arbitrary()? })
    }
}
