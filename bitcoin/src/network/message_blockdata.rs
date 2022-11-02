// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blockdata network messages.
//!
//! This module describes network messages which are used for passing
//! Bitcoin data (blocks and transactions) around.
//!

use crate::consensus::encode::{self, Decodable, Encodable};
use crate::hash_types::{BlockHash, Txid, Wtxid};
use crate::hashes::{sha256d, Hash as _};
use crate::internal_macros::impl_consensus_encoding;
use crate::io;
use crate::network::constants;
use crate::prelude::*;

/// An inventory item.
#[derive(PartialEq, Eq, Clone, Debug, Copy, Hash, PartialOrd, Ord)]
pub enum Inventory {
    /// Error --- these inventories can be ignored
    Error,
    /// Transaction
    Transaction(Txid),
    /// Block
    Block(BlockHash),
    /// Compact Block
    CompactBlock(BlockHash),
    /// Witness Transaction by Wtxid
    WTx(Wtxid),
    /// Witness Transaction
    WitnessTransaction(Txid),
    /// Witness Block
    WitnessBlock(BlockHash),
    /// Unknown inventory type
    Unknown {
        /// The inventory item type.
        inv_type: u32,
        /// The hash of the inventory item
        hash: [u8; 32],
    },
}

impl Encodable for Inventory {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        macro_rules! encode_inv {
            ($code:expr, $item:expr) => {
                u32::consensus_encode(&$code, w)? + $item.consensus_encode(w)?
            };
        }
        Ok(match *self {
            Inventory::Error => encode_inv!(0, sha256d::Hash::all_zeros()),
            Inventory::Transaction(ref t) => encode_inv!(1, t),
            Inventory::Block(ref b) => encode_inv!(2, b),
            Inventory::CompactBlock(ref b) => encode_inv!(4, b),
            Inventory::WTx(w) => encode_inv!(5, w),
            Inventory::WitnessTransaction(ref t) => encode_inv!(0x40000001, t),
            Inventory::WitnessBlock(ref b) => encode_inv!(0x40000002, b),
            Inventory::Unknown { inv_type: t, hash: ref d } => encode_inv!(t, d),
        })
    }
}

impl Decodable for Inventory {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let inv_type: u32 = Decodable::consensus_decode(r)?;
        Ok(match inv_type {
            0 => Inventory::Error,
            1 => Inventory::Transaction(Decodable::consensus_decode(r)?),
            2 => Inventory::Block(Decodable::consensus_decode(r)?),
            4 => Inventory::CompactBlock(Decodable::consensus_decode(r)?),
            5 => Inventory::WTx(Decodable::consensus_decode(r)?),
            0x40000001 => Inventory::WitnessTransaction(Decodable::consensus_decode(r)?),
            0x40000002 => Inventory::WitnessBlock(Decodable::consensus_decode(r)?),
            tp => Inventory::Unknown { inv_type: tp, hash: Decodable::consensus_decode(r)? },
        })
    }
}

// Some simple messages

/// The `getblocks` message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetBlocksMessage {
    /// The protocol version
    pub version: u32,
    /// Locator hashes --- ordered newest to oldest. The remote peer will
    /// reply with its longest known chain, starting from a locator hash
    /// if possible and block 1 otherwise.
    pub locator_hashes: Vec<BlockHash>,
    /// References the block to stop at, or zero to just fetch the maximum 500 blocks
    pub stop_hash: BlockHash,
}

/// The `getheaders` message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetHeadersMessage {
    /// The protocol version
    pub version: u32,
    /// Locator hashes --- ordered newest to oldest. The remote peer will
    /// reply with its longest known chain, starting from a locator hash
    /// if possible and block 1 otherwise.
    pub locator_hashes: Vec<BlockHash>,
    /// References the header to stop at, or zero to just fetch the maximum 2000 headers
    pub stop_hash: BlockHash,
}

impl GetBlocksMessage {
    /// Construct a new `getblocks` message
    pub fn new(locator_hashes: Vec<BlockHash>, stop_hash: BlockHash) -> GetBlocksMessage {
        GetBlocksMessage { version: constants::PROTOCOL_VERSION, locator_hashes, stop_hash }
    }
}

impl_consensus_encoding!(GetBlocksMessage, version, locator_hashes, stop_hash);

impl GetHeadersMessage {
    /// Construct a new `getheaders` message
    pub fn new(locator_hashes: Vec<BlockHash>, stop_hash: BlockHash) -> GetHeadersMessage {
        GetHeadersMessage { version: constants::PROTOCOL_VERSION, locator_hashes, stop_hash }
    }
}

impl_consensus_encoding!(GetHeadersMessage, version, locator_hashes, stop_hash);

#[cfg(test)]
mod tests {
    use super::{GetBlocksMessage, GetHeadersMessage, Vec};
    use crate::consensus::encode::{deserialize, serialize};
    use crate::hashes::Hash;
    use crate::internal_macros::hex;

    #[test]
    fn getblocks_message_test() {
        let from_sat = hex!("72110100014a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b0000000000000000000000000000000000000000000000000000000000000000");
        let genhash = hex!("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");

        let decode: Result<GetBlocksMessage, _> = deserialize(&from_sat);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.version, 70002);
        assert_eq!(real_decode.locator_hashes.len(), 1);
        assert_eq!(serialize(&real_decode.locator_hashes[0]), genhash);
        assert_eq!(real_decode.stop_hash, Hash::all_zeros());

        assert_eq!(serialize(&real_decode), from_sat);
    }

    #[test]
    fn getheaders_message_test() {
        let from_sat = hex!("72110100014a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b0000000000000000000000000000000000000000000000000000000000000000");
        let genhash = hex!("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");

        let decode: Result<GetHeadersMessage, _> = deserialize(&from_sat);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.version, 70002);
        assert_eq!(real_decode.locator_hashes.len(), 1);
        assert_eq!(serialize(&real_decode.locator_hashes[0]), genhash);
        assert_eq!(real_decode.stop_hash, Hash::all_zeros());

        assert_eq!(serialize(&real_decode), from_sat);
    }
}
