//!
//! BIP152  Compact Blocks network messages
//!

use crate::bip152;
use crate::internal_macros::impl_consensus_encoding;

/// sendcmpct message
#[derive(PartialEq, Eq, Clone, Debug, Copy, PartialOrd, Ord, Hash)]
pub struct SendCmpct {
    /// Request to be send compact blocks.
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
