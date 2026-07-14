// SPDX-License-Identifier: CC0-1.0

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

impl crate::consensus::Encodable for SendCmpct {
    #[inline]
    fn consensus_encode<R: crate::io::Write + ?Sized>(
        &self,
        r: &mut R,
    ) -> core::result::Result<usize, crate::io::Error> {
        let mut len = 0;
        len += self.send_compact.consensus_encode(r)?;
        len += self.version.consensus_encode(r)?;
        Ok(len)
    }
}

impl crate::consensus::Decodable for SendCmpct {
    #[inline]
    fn consensus_decode<R: crate::io::Read + ?Sized>(
        r: &mut R,
    ) -> core::result::Result<Self, crate::consensus::encode::Error> {
        let send_compact: u8 = crate::consensus::Decodable::consensus_decode(r)?;
        let version = crate::consensus::Decodable::consensus_decode(r)?;

        if send_compact == 1 || send_compact == 0 {
            let send_compact = send_compact != 0;
            Ok(SendCmpct { send_compact, version })
        } else {
            Err(crate::consensus::encode::Error::ParseFailed("first byte was not 0 or 1"))
        }
    }
}

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
