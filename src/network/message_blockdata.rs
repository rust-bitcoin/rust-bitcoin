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

use std::io::{IoResult, IoError, InvalidInput};
#[cfg(test)]
use serialize::hex::FromHex;
#[cfg(test)]
use util::hash::zero_hash;

use network::constants;
use network::serialize::{Serializable, SerializeIter};
use util::hash::Sha256dHash;

#[deriving(Clone, PartialEq, Show)]
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
#[deriving(Show)]
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
#[deriving(Show)]
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
#[deriving(Clone, Show)]
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

impl_serializable!(GetBlocksMessage, version, locator_hashes, stop_hash)

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

impl_serializable!(GetHeadersMessage, version, locator_hashes, stop_hash)

impl Serializable for Inventory {
  fn serialize(&self) -> Vec<u8> {
    let int_type: u32 = match self.inv_type {
      InvError => 0, 
      InvTransaction => 1,
      InvBlock => 2
    };
    let mut rv = vec!();
    rv.extend(int_type.serialize().move_iter());
    rv.extend(self.hash.serialize().move_iter());
    rv
  }

  fn deserialize<I: Iterator<u8>>(mut iter: I) -> IoResult<Inventory> {
    let int_type: u32 = try!(Serializable::deserialize(iter.by_ref()));
    Ok(Inventory {
      inv_type: match int_type {
        0 => InvError,
        1 => InvTransaction,
        2 => InvBlock,
        _ => { return Err(IoError {
          kind: InvalidInput,
          desc: "bad inventory type field",
          detail: None
        })}
      },
      hash: try!(Serializable::deserialize(iter.by_ref()))
    })
  }
}

#[test]
fn getblocks_message_test() {
  let from_sat = "72110100014a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b0000000000000000000000000000000000000000000000000000000000000000".from_hex().unwrap();
  let genhash = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".from_hex().unwrap();

  let decode: IoResult<GetBlocksMessage> = Serializable::deserialize(from_sat.iter().map(|n| *n));
  assert!(decode.is_ok());
  let real_decode = decode.unwrap();
  assert_eq!(real_decode.version, 70002);
  assert_eq!(real_decode.locator_hashes.len(), 1);
  assert_eq!(real_decode.locator_hashes[0].as_slice(), genhash.as_slice());
  assert_eq!(real_decode.stop_hash.as_slice(), zero_hash().as_slice());

  let reserialize = real_decode.serialize();
  assert_eq!(reserialize.as_slice(), from_sat.as_slice());
}

#[test]
fn getheaders_message_test() {
  let from_sat = "72110100014a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b0000000000000000000000000000000000000000000000000000000000000000".from_hex().unwrap();
  let genhash = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".from_hex().unwrap();

  let decode: IoResult<GetHeadersMessage> = Serializable::deserialize(from_sat.iter().map(|n| *n));
  assert!(decode.is_ok());
  let real_decode = decode.unwrap();
  assert_eq!(real_decode.version, 70002);
  assert_eq!(real_decode.locator_hashes.len(), 1);
  assert_eq!(real_decode.locator_hashes[0].as_slice(), genhash.as_slice());
  assert_eq!(real_decode.stop_hash.as_slice(), zero_hash().as_slice());

  let reserialize = real_decode.serialize();
  assert_eq!(reserialize.as_slice(), from_sat.as_slice());
}

