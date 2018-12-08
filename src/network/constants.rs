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

//! Network constants
//!
//! This module provides various constants relating to the Bitcoin network
//! protocol, such as protocol versioning and magic header bytes.
//!
//! The [`Network`][1] type implements the [`Decodable`][2] and
//! [`Encodable`][3] traits and encodes the magic bytes of the given
//! network
//!
//! [1]: enum.Network.html
//! [2]: ../../consensus/encode/trait.Decodable.html
//! [3]: ../../consensus/encode/trait.Encodable.html
//!
//! # Example: encoding a network's magic bytes
//!
//! ```rust
//! use bitcoin::Network;
//! use bitcoin::consensus::encode::serialize;
//!
//! let network = Network::bitcoin();
//! let bytes = serialize(&network);
//!
//! assert_eq!(&bytes[..], &[0xF9, 0xBE, 0xB4, 0xD9]);
//! ```

use bitcoin_constants::{BitcoinNetworks, Network, SupportedNetworks};
use consensus::encode::{Decodable, Encodable};
use consensus::encode::{self, Encoder, Decoder};

/// Version of the protocol as appearing in network message headers
pub const PROTOCOL_VERSION: u32 = 70001;
/// Bitfield of services provided by this node
pub const SERVICES: u64 = 0;
/// User agent as it appears in the version message
pub const USER_AGENT: &'static str = "bitcoin-rust v0.1";


impl<S: Encoder> Encodable<S> for Network {
    /// Encodes the magic bytes of `Network`.
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.magic().consensus_encode(s)
    }
}

impl<D: Decoder> Decodable<D> for Network {
    /// Decodes the magic bytes of `Network`.
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<Network, encode::Error> {
        u32::consensus_decode(d)
            .and_then(|m| BitcoinNetworks::networks_iter()
                .find(|network| network.magic() == m)
                .map_or_else(
                    || Err(encode::Error::UnknownNetworkMagic(m)),
                    |network| Ok(network)
                )
            )
    }
}

#[cfg(test)]
mod tests {
  use bitcoin_constants::Network;
  use consensus::encode::{deserialize, serialize};

  #[test]
  fn serialize_test() {
    assert_eq!(serialize(&Network::bitcoin()), vec![0xf9, 0xbe, 0xb4, 0xd9]);
    assert_eq!(serialize(&Network::bitcoin_testnet()), vec![0x0b, 0x11, 0x09, 0x07]);
    assert_eq!(serialize(&Network::bitcoin_regtest()), vec![0xfa, 0xbf, 0xb5, 0xda]);

    assert_eq!(deserialize(&[0xf9, 0xbe, 0xb4, 0xd9]).ok(), Some(Network::bitcoin()));
    assert_eq!(deserialize(&[0x0b, 0x11, 0x09, 0x07]).ok(), Some(Network::bitcoin_testnet()));
    assert_eq!(deserialize(&[0xfa, 0xbf, 0xb5, 0xda]).ok(), Some(Network::bitcoin_regtest()));

    let bad: Result<Network, _> = deserialize("fakenet".as_bytes());
    assert!(bad.is_err());
  }
}

