// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blockdata network messages.
//!
//! This module describes network messages which are used for passing
//! Bitcoin data (blocks and transactions) around.

use alloc::vec::Vec;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bitcoin::block::BlockHash;
use bitcoin::consensus::encode::{self, Decodable, Encodable};
use bitcoin::transaction::{Txid, Wtxid};
use io::{BufRead, Write};

use crate::consensus::impl_consensus_encoding;
use crate::ProtocolVersion;
use crate::message_utreexo::PackedPositions;

/// An inventory item.
#[derive(PartialEq, Eq, Clone, Debug, Copy, Hash, PartialOrd, Ord)]
pub enum Inventory {
    /// Error --- these inventories can be ignored.
    /// While a 32 byte hash is expected over the wire, the value is meaningless.
    Error([u8; 32]),
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
    /// Utreexo Proof hashes.
    UtreexoProofHash(PackedPositions),
    /// Utreexo Summary
    UtreexoSummary(BlockHash),
    /// Utreexo Transaction
    UtreexoTransaction(Txid),
    /// Witness Utreexo Transaction
    WitnessUtreexoTransaction(Txid),
    /// Unknown inventory type
    Unknown {
        /// The inventory item type.
        inv_type: u32,
        /// The hash of the inventory item
        hash: [u8; 32],
    },
}

impl Inventory {
    /// Returns the item value represented as a SHA256-d hash.
    ///
    /// Returns [None] only for [Inventory::Error] who's hash value is meaningless.
    pub fn network_hash(&self) -> Option<[u8; 32]> {
        match self {
            Inventory::Error(_) => None,
            Inventory::Transaction(t) => Some(t.to_byte_array()),
            Inventory::Block(b) => Some(b.to_byte_array()),
            Inventory::CompactBlock(b) => Some(b.to_byte_array()),
            Inventory::WTx(t) => Some(t.to_byte_array()),
            Inventory::WitnessTransaction(t) => Some(t.to_byte_array()),
            Inventory::WitnessBlock(b) => Some(b.to_byte_array()),
            Inventory::UtreexoProofHash(p) => Some(p.to_byte_array()),
            Inventory::UtreexoSummary(s) => Some(s.to_byte_array()),
            Inventory::UtreexoTransaction(t) => Some(t.to_byte_array()),
            Inventory::WitnessUtreexoTransaction(t) => Some(t.to_byte_array()),
            Inventory::Unknown { hash, .. } => Some(*hash),
        }
    }
}

impl Encodable for Inventory {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        macro_rules! encode_inv {
            ($code:expr, $item:expr) => {
                u32::consensus_encode(&$code, w)? + $item.consensus_encode(w)?
            };
        }
        Ok(match *self {
            Inventory::Error(ref e) => encode_inv!(0, e),
            Inventory::Transaction(ref t) => encode_inv!(1, t),
            Inventory::Block(ref b) => encode_inv!(2, b),
            Inventory::CompactBlock(ref b) => encode_inv!(4, b),
            Inventory::WTx(ref w) => encode_inv!(5, w),
            Inventory::WitnessTransaction(ref t) => encode_inv!(0x40000001, t),
            Inventory::WitnessBlock(ref b) => encode_inv!(0x40000002, b),
            Inventory::UtreexoProofHash(ref p) => encode_inv!(6, p),
            Inventory::UtreexoSummary(ref s) => encode_inv!(7, s),
            Inventory::UtreexoTransaction(ref t) => encode_inv!(0x01000001, t),
            Inventory::WitnessUtreexoTransaction(ref t) => encode_inv!(0x41000001, t),
            Inventory::Unknown { inv_type: t, hash: ref d } => encode_inv!(t, d),
        })
    }
}

impl Decodable for Inventory {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let inv_type: u32 = Decodable::consensus_decode(r)?;
        Ok(match inv_type {
            0 => Inventory::Error(Decodable::consensus_decode(r)?),
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
    pub version: ProtocolVersion,
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
    pub version: ProtocolVersion,
    /// Locator hashes --- ordered newest to oldest. The remote peer will
    /// reply with its longest known chain, starting from a locator hash
    /// if possible and block 1 otherwise.
    pub locator_hashes: Vec<BlockHash>,
    /// References the header to stop at, or zero to just fetch the maximum 2000 headers
    pub stop_hash: BlockHash,
}

impl_consensus_encoding!(GetBlocksMessage, version, locator_hashes, stop_hash);

impl_consensus_encoding!(GetHeadersMessage, version, locator_hashes, stop_hash);

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for GetHeadersMessage {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(GetHeadersMessage {
            version: u.arbitrary()?,
            locator_hashes: Vec::<BlockHash>::arbitrary(u)?,
            stop_hash: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for GetBlocksMessage {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(GetBlocksMessage {
            version: u.arbitrary()?,
            locator_hashes: Vec::<BlockHash>::arbitrary(u)?,
            stop_hash: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Inventory {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=7)? {
            0 => Ok(Inventory::Error(u.arbitrary()?)),
            1 => Ok(Inventory::Transaction(u.arbitrary()?)),
            2 => Ok(Inventory::Block(u.arbitrary()?)),
            3 => Ok(Inventory::CompactBlock(u.arbitrary()?)),
            4 => Ok(Inventory::WTx(u.arbitrary()?)),
            5 => Ok(Inventory::WitnessTransaction(u.arbitrary()?)),
            6 => Ok(Inventory::WitnessBlock(u.arbitrary()?)),
            _ => Ok(Inventory::Unknown { inv_type: u.arbitrary()?, hash: u.arbitrary()? }),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::consensus::encode::{deserialize, serialize};
    use hex_lit::hex;

    use super::*;

    #[test]
    fn getblocks_message() {
        let from_sat = hex!("72110100014a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b0000000000000000000000000000000000000000000000000000000000000000");
        let genhash = hex!("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");

        let decode: Result<GetBlocksMessage, _> = deserialize(&from_sat);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.version.0, 70002);
        assert_eq!(real_decode.locator_hashes.len(), 1);
        assert_eq!(serialize(&real_decode.locator_hashes[0]), genhash);
        assert_eq!(real_decode.stop_hash, BlockHash::GENESIS_PREVIOUS_BLOCK_HASH);

        assert_eq!(serialize(&real_decode), from_sat);
    }

    #[test]
    fn getheaders_message() {
        let from_sat = hex!("72110100014a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b0000000000000000000000000000000000000000000000000000000000000000");
        let genhash = hex!("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");

        let decode: Result<GetHeadersMessage, _> = deserialize(&from_sat);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.version.0, 70002);
        assert_eq!(real_decode.locator_hashes.len(), 1);
        assert_eq!(serialize(&real_decode.locator_hashes[0]), genhash);
        assert_eq!(real_decode.stop_hash, BlockHash::GENESIS_PREVIOUS_BLOCK_HASH);

        assert_eq!(serialize(&real_decode), from_sat);
    }
}
