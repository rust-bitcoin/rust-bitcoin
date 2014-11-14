// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! # Blockdata network messages
//!
//! This module describes network messages which are used for passing
//! Bitcoin data (blocks and transactions) around.
//!

use network::constants;
use network::encodable::{ConsensusDecodable, ConsensusEncodable};
use network::serialize::{SimpleDecoder, SimpleEncoder};
use util::hash::Sha256dHash;

#[deriving(PartialEq, Eq, Clone, Show)]
/// The type of an inventory object
pub enum InvType {
  /// Error --- these inventories can be ignored
  InvError,
  /// Transaction
  InvTransaction,
  /// Block
  InvBlock
}

// Some simple messages

/// The `getblocks` message
#[deriving(PartialEq, Eq, Clone, Show)]
pub struct GetBlocksMessage {
  /// The protocol version
  pub version: u32,
  /// Locator hashes --- ordered newest to oldest. The remote peer will
  /// reply with its longest known chain, starting from a locator hash
  /// if possible and block 1 otherwise.
  pub locator_hashes: Vec<Sha256dHash>,
  /// References the block to stop at, or zero to just fetch the maximum 500 blocks
  pub stop_hash: Sha256dHash
}

/// The `getheaders` message
#[deriving(PartialEq, Eq, Clone, Show)]
pub struct GetHeadersMessage {
  /// The protocol version
  pub version: u32,
  /// Locator hashes --- ordered newest to oldest. The remote peer will
  /// reply with its longest known chain, starting from a locator hash
  /// if possible and block 1 otherwise.
  pub locator_hashes: Vec<Sha256dHash>,
  /// References the header to stop at, or zero to just fetch the maximum 2000 headers
  pub stop_hash: Sha256dHash
}

/// An inventory object --- a reference to a Bitcoin object
#[deriving(PartialEq, Eq, Clone, Show)]
pub struct Inventory {
  /// The type of object that is referenced
  pub inv_type: InvType,
  /// The object's hash
  pub hash: Sha256dHash
}

impl GetBlocksMessage {
  /// Construct a new `getblocks` message
  pub fn new(locator_hashes: Vec<Sha256dHash>, stop_hash: Sha256dHash) -> GetBlocksMessage {
    GetBlocksMessage {
      version: constants::PROTOCOL_VERSION,
      locator_hashes: locator_hashes.clone(),
      stop_hash: stop_hash
    }
  }
}

impl_consensus_encoding!(GetBlocksMessage, version, locator_hashes, stop_hash)

impl GetHeadersMessage {
  /// Construct a new `getheaders` message
  pub fn new(locator_hashes: Vec<Sha256dHash>, stop_hash: Sha256dHash) -> GetHeadersMessage {
    GetHeadersMessage {
      version: constants::PROTOCOL_VERSION,
      locator_hashes: locator_hashes,
      stop_hash: stop_hash
    }
  }
}

impl_consensus_encoding!(GetHeadersMessage, version, locator_hashes, stop_hash)

impl<S:SimpleEncoder<E>, E> ConsensusEncodable<S, E> for Inventory {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), E> {
    try!(match self.inv_type {
      InvError => 0u32,
      InvTransaction => 1,
      InvBlock => 2
    }.consensus_encode(s));
    self.hash.consensus_encode(s)
  }
}

impl<D:SimpleDecoder<E>, E> ConsensusDecodable<D, E> for Inventory {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<Inventory, E> {
    let int_type: u32 = try!(ConsensusDecodable::consensus_decode(d));
    Ok(Inventory {
      inv_type: match int_type {
        0 => InvError,
        1 => InvTransaction,
        2 => InvBlock,
        // TODO do not fail here
        _ => { panic!("bad inventory type field") }
      },
      hash: try!(ConsensusDecodable::consensus_decode(d))
    })
  }
}

#[cfg(test)]
mod tests {
  use super::{GetHeadersMessage, GetBlocksMessage};

  use std::io::IoResult;
  use serialize::hex::FromHex;

  use network::serialize::{deserialize, serialize};
  use std::default::Default;

  #[test]
  fn getblocks_message_test() {
    let from_sat = "72110100014a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b0000000000000000000000000000000000000000000000000000000000000000".from_hex().unwrap();
    let genhash = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".from_hex().unwrap();

    let decode: IoResult<GetBlocksMessage> = deserialize(from_sat.clone());
    assert!(decode.is_ok());
    let real_decode = decode.unwrap();
    assert_eq!(real_decode.version, 70002);
    assert_eq!(real_decode.locator_hashes.len(), 1);
    assert_eq!(serialize(&real_decode.locator_hashes[0]), Ok(genhash));
    assert_eq!(real_decode.stop_hash, Default::default());

    assert_eq!(serialize(&real_decode), Ok(from_sat));
  }

  #[test]
  fn getheaders_message_test() {
    let from_sat = "72110100014a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b0000000000000000000000000000000000000000000000000000000000000000".from_hex().unwrap();
    let genhash = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".from_hex().unwrap();

    let decode: IoResult<GetHeadersMessage> = deserialize(from_sat.clone());
    assert!(decode.is_ok());
    let real_decode = decode.unwrap();
    assert_eq!(real_decode.version, 70002);
    assert_eq!(real_decode.locator_hashes.len(), 1);
    assert_eq!(serialize(&real_decode.locator_hashes[0]), Ok(genhash));
    assert_eq!(real_decode.stop_hash, Default::default());

    assert_eq!(serialize(&real_decode), Ok(from_sat));
  }
}

