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

user_enum!(
  #[deriving(PartialEq, Eq, Clone, Hash)]
  #[doc="The cryptocurrency to act on"]
  pub enum Network {
    #[doc="Classic Bitcoin"]
    Bitcoin <-> "bitcoin",
    #[doc="Bitcoin's testnet"]
    BitcoinTestnet <-> "testnet"
  }
)

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

#[cfg(test)]
mod tests {
  use super::{Network, Bitcoin, BitcoinTestnet};

  use network::serialize::{deserialize, serialize};

  #[test]
  fn serialize_test() {
    assert_eq!(serialize(&Bitcoin).unwrap(), vec![0xf9, 0xbe, 0xb4, 0xd9]);
    assert_eq!(serialize(&BitcoinTestnet).unwrap(), vec![0x0b, 0x11, 0x09, 0x07]);

    assert_eq!(deserialize(vec![0xf9, 0xbe, 0xb4, 0xd9]), Ok(Bitcoin));
    assert_eq!(deserialize(vec![0x0b, 0x11, 0x09, 0x07]), Ok(BitcoinTestnet));

    let bad: Result<Network, _> = deserialize(Vec::from_slice("fakenet".as_bytes()));
    assert!(bad.is_err());
  }
}

