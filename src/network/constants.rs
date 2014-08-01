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

use network::encodable::{ConsensusDecodable, ConsensusEncodable};
use network::serialize::{SimpleEncoder, SimpleDecoder};

/// The cryptocurrency to operate on
#[deriving(Encodable, Decodable, PartialEq, Eq, Clone, Show, Hash)]
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

impl<S:SimpleEncoder<E>, E> ConsensusEncodable<S, E> for Network {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), E> {
    magic(*self).consensus_encode(s)
  }
}

impl<D:SimpleDecoder<E>, E> ConsensusDecodable<D, E> for Network {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<Network, E> {
    let magic: u32 = try!(ConsensusDecodable::consensus_decode(d));
    match magic {
      0xD9B4BEF9 => Ok(Bitcoin),
      0x0709110B => Ok(BitcoinTestnet),
      x => Err(d.error(format!("Unknown network (magic {:x})", x).as_slice()))
    }
  }
}

