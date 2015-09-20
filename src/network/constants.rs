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

user_enum! {
    #[derive(Copy, PartialEq, Eq, Clone, Hash)]
    #[doc="The cryptocurrency to act on"]
    pub enum Network {
        #[doc="Classic Bitcoin"]
        Bitcoin <-> "bitcoin",
        #[doc="Bitcoin's testnet"]
        Testnet <-> "testnet"
    }
}

/// Version of the protocol as appearing in network message headers
pub const PROTOCOL_VERSION: u32    = 70001;
/// Bitfield of services provided by this node
pub const SERVICES: u64            = 0;
/// User agent as it appears in the version message
pub const USER_AGENT: &'static str = "bitcoin-rust v0.1";

/// Return the network magic bytes, which should be encoded little-endian
/// at the start of every message
pub fn magic(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 0xD9B4BEF9,
        Network::Testnet => 0x0709110B
        // Note: any new entries here must be added to `consensus_decode` below
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for Network {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
        magic(*self).consensus_encode(s)
    }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for Network {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<Network, D::Error> {
        let magic: u32 = try!(ConsensusDecodable::consensus_decode(d));
        match magic {
            0xD9B4BEF9 => Ok(Network::Bitcoin),
            0x0709110B => Ok(Network::Testnet),
            x => Err(d.error(format!("Unknown network (magic {:x})", x)))
        }
    }
}

#[cfg(test)]
mod tests {
  use super::Network;
  use network::serialize::{deserialize, serialize};

  #[test]
  fn serialize_test() {
    assert_eq!(serialize(&Network::Bitcoin).unwrap(), vec![0xf9, 0xbe, 0xb4, 0xd9]);
    assert_eq!(serialize(&Network::Testnet).unwrap(), vec![0x0b, 0x11, 0x09, 0x07]);

    assert_eq!(deserialize(&[0xf9, 0xbe, 0xb4, 0xd9]).ok(), Some(Network::Bitcoin));
    assert_eq!(deserialize(&[0x0b, 0x11, 0x09, 0x07]).ok(), Some(Network::Testnet));

    let bad: Result<Network, _> = deserialize("fakenet".as_bytes());
    assert!(bad.is_err());
  }
}

