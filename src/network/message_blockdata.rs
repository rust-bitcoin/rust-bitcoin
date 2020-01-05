// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Blockdata network messages
//!
//! This module describes network messages which are used for passing
//! Bitcoin data (blocks and transactions) around.
//!

use std::io;

use hashes::sha256d;

use network::constants;
use consensus::encode::{self, Decodable, Encodable};
use hash_types::{BlockHash, Txid, Wtxid};

/// An inventory item.
#[derive(PartialEq, Eq, Clone, Debug, Copy, Hash)]
pub enum Inventory {
    /// Error --- these inventories can be ignored
    Error,
    /// Transaction
    Transaction(Txid),
    /// Block
    Block(BlockHash),
    /// Witness Transaction
    WitnessTransaction(Wtxid),
    /// Witness Block
    WitnessBlock(BlockHash),
}

impl Encodable for Inventory {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, encode::Error> {
        macro_rules! encode_inv {
            ($code:expr, $item:expr) => {
                u32::consensus_encode(&$code, &mut s)? +
                $item.consensus_encode(&mut s)?
            }
        }
        Ok(match *self {
            Inventory::Error => encode_inv!(0, sha256d::Hash::default()),
            Inventory::Transaction(ref t) => encode_inv!(1, t),
            Inventory::Block(ref b) => encode_inv!(2, b),
            Inventory::WitnessTransaction(ref t) => encode_inv!(0x40000001, t),
            Inventory::WitnessBlock(ref b) => encode_inv!(0x40000002, b),
        })
    }
}

impl Decodable for Inventory {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let inv_type: u32 = Decodable::consensus_decode(&mut d)?;
        Ok(match inv_type {
            0 => Inventory::Error,
            1 => Inventory::Transaction(Decodable::consensus_decode(&mut d)?),
            2 => Inventory::Block(Decodable::consensus_decode(&mut d)?),
            0x40000001 => Inventory::WitnessTransaction(Decodable::consensus_decode(&mut d)?),
            0x40000002 => Inventory::WitnessBlock(Decodable::consensus_decode(&mut d)?),
            tp => return Err(encode::Error::UnknownInventoryType(tp)),
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
    pub stop_hash: BlockHash
}

impl GetBlocksMessage {
    /// Construct a new `getblocks` message
    pub fn new(locator_hashes: Vec<BlockHash>, stop_hash: BlockHash) -> GetBlocksMessage {
        GetBlocksMessage {
            version: constants::PROTOCOL_VERSION,
            locator_hashes: locator_hashes.clone(),
            stop_hash: stop_hash
        }
    }
}

impl_consensus_encoding!(GetBlocksMessage, version, locator_hashes, stop_hash);

impl GetHeadersMessage {
    /// Construct a new `getheaders` message
    pub fn new(locator_hashes: Vec<BlockHash>, stop_hash: BlockHash) -> GetHeadersMessage {
        GetHeadersMessage {
            version: constants::PROTOCOL_VERSION,
            locator_hashes: locator_hashes,
            stop_hash: stop_hash
        }
    }
}

impl_consensus_encoding!(GetHeadersMessage, version, locator_hashes, stop_hash);

#[cfg(test)]
mod tests {
    use super::{GetHeadersMessage, GetBlocksMessage};

    use hex::decode as hex_decode;

    use consensus::encode::{deserialize, serialize};
    use std::default::Default;

    #[test]
    fn getblocks_message_test() {
        let from_sat = hex_decode("72110100014a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let genhash = hex_decode("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b").unwrap();

        let decode: Result<GetBlocksMessage, _> = deserialize(&from_sat);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.version, 70002);
        assert_eq!(real_decode.locator_hashes.len(), 1);
        assert_eq!(serialize(&real_decode.locator_hashes[0]), genhash);
        assert_eq!(real_decode.stop_hash, Default::default());

        assert_eq!(serialize(&real_decode), from_sat);
    }

    #[test]
    fn getheaders_message_test() {
        let from_sat = hex_decode("72110100014a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let genhash = hex_decode("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b").unwrap();

        let decode: Result<GetHeadersMessage, _> = deserialize(&from_sat);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.version, 70002);
        assert_eq!(real_decode.locator_hashes.len(), 1);
        assert_eq!(serialize(&real_decode.locator_hashes[0]), genhash);
        assert_eq!(real_decode.stop_hash, Default::default());

        assert_eq!(serialize(&real_decode), from_sat);
    }
}

