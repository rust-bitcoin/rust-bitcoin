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

//! # Network constants
//!
//! This module provides various constants relating to the Bitcoin network
//! protocol, such as protocol versioning and magic header bytes.
//!

use std::io::{IoResult, InvalidInput, standard_error};

use network::serialize::Serializable;
use util::misc::prepend_err;

/// The cryptocurrency to operate on
#[deriving(PartialEq, Eq, Clone, Show)]
pub enum Network {
  /// Classic Bitcoin
  Bitcoin,
  /// Bitcoin's testnet
  BitcoinTestnet,
}

pub static PROTOCOL_VERSION: u32    = 70001;
pub static SERVICES: u64            = 0;
pub static USER_AGENT: &'static str = "bitcoin-rust v0.1";

/// Return the network magic bytes, which should be encoded little-endian
/// at the start of every message
pub fn magic(network: Network) -> u32 {
  match network {
    Bitcoin => 0xD9B4BEF9,
    BitcoinTestnet => 0x0709110B
    // Note: any new entries here must be added to `deserialize` below
  }
}

// This affects the representation of the `Network` in text files
impl Serializable for Network {
  fn serialize(&self) -> Vec<u8> {
    magic(*self).serialize()
  }

  fn deserialize<I: Iterator<u8>>(iter: I) -> IoResult<Network> {
    let magic: u32 = try!(prepend_err("magic", Serializable::deserialize(iter)));
    match magic {
      0xD9B4BEF9 => Ok(Bitcoin),
      0x0709110B => Ok(BitcoinTestnet),
      _ => Err(standard_error(InvalidInput))
    }
  }
}

