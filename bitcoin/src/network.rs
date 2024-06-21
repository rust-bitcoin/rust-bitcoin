// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network.
//!
//! The term "network" is overloaded, here [`Network`] refers to the specific
//! Bitcoin network we are operating on e.g., signet, regtest. The terms
//! "network" and "chain" are often used interchangeably for this concept.
//!
//! # Example: encoding a network's magic bytes
//!
//! ```rust
//! use bitcoin::{Network, NetworkExt};
//! use bitcoin::consensus::encode::serialize;
//!
//! let network = Network::Bitcoin;
//! let bytes = serialize(&network.magic());
//!
//! assert_eq!(&bytes[..], &[0xF9, 0xBE, 0xB4, 0xD9]);
//! ```

/// Re-export everything from the [`primitives::network`] module.
#[doc(inline)]
pub use primitives::network::*;

use crate::p2p::Magic;

/// Trait to extend the `Network` primitive type.
pub trait NetworkExt {
    /// Creates a `Network` from the magic bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::p2p::Magic;
    /// use bitcoin::{Network, NetworkExt};
    ///
    /// assert_eq!(Ok(Network::Bitcoin), Network::try_from(Magic::from_bytes([0xF9, 0xBE, 0xB4, 0xD9])));
    /// assert_eq!(None, Network::from_magic(Magic::from_bytes([0xFF, 0xFF, 0xFF, 0xFF])));
    /// ```
    fn from_magic(magic: Magic) -> Option<Network>;

    /// Return the network magic bytes, which should be encoded little-endian
    /// at the start of every message
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::p2p::Magic;
    /// use bitcoin::{Network, NetworkExt};
    ///
    /// let network = Network::Bitcoin;
    /// assert_eq!(network.magic(), Magic::from_bytes([0xF9, 0xBE, 0xB4, 0xD9]));
    /// ```
    fn magic(self) -> Magic;
}

impl NetworkExt for Network {
    fn from_magic(magic: Magic) -> Option<Network> { Network::try_from(magic).ok() }
    fn magic(self) -> Magic { Magic::from(self) }
}

#[cfg(test)]
mod tests {
    use super::{Network, NetworkExt};
    use crate::consensus::encode::{deserialize, serialize};
    use crate::p2p::ServiceFlags;

    #[test]
    fn serialize_test() {
        assert_eq!(serialize(&Network::Bitcoin.magic()), &[0xf9, 0xbe, 0xb4, 0xd9]);
        assert_eq!(serialize(&Network::Testnet.magic()), &[0x0b, 0x11, 0x09, 0x07]);
        assert_eq!(serialize(&Network::Signet.magic()), &[0x0a, 0x03, 0xcf, 0x40]);
        assert_eq!(serialize(&Network::Regtest.magic()), &[0xfa, 0xbf, 0xb5, 0xda]);

        assert_eq!(deserialize(&[0xf9, 0xbe, 0xb4, 0xd9]).ok(), Some(Network::Bitcoin.magic()));
        assert_eq!(deserialize(&[0x0b, 0x11, 0x09, 0x07]).ok(), Some(Network::Testnet.magic()));
        assert_eq!(deserialize(&[0x0a, 0x03, 0xcf, 0x40]).ok(), Some(Network::Signet.magic()));
        assert_eq!(deserialize(&[0xfa, 0xbf, 0xb5, 0xda]).ok(), Some(Network::Regtest.magic()));
    }

    #[test]
    fn service_flags_test() {
        let all = [
            ServiceFlags::NETWORK,
            ServiceFlags::GETUTXO,
            ServiceFlags::BLOOM,
            ServiceFlags::WITNESS,
            ServiceFlags::COMPACT_FILTERS,
            ServiceFlags::NETWORK_LIMITED,
            ServiceFlags::P2P_V2,
        ];

        let mut flags = ServiceFlags::NONE;
        for f in all.iter() {
            assert!(!flags.has(*f));
        }

        flags |= ServiceFlags::WITNESS;
        assert_eq!(flags, ServiceFlags::WITNESS);

        let mut flags2 = flags | ServiceFlags::GETUTXO;
        for f in all.iter() {
            assert_eq!(flags2.has(*f), *f == ServiceFlags::WITNESS || *f == ServiceFlags::GETUTXO);
        }

        flags2 ^= ServiceFlags::WITNESS;
        assert_eq!(flags2, ServiceFlags::GETUTXO);

        flags2 |= ServiceFlags::COMPACT_FILTERS;
        flags2 ^= ServiceFlags::GETUTXO;
        assert_eq!(flags2, ServiceFlags::COMPACT_FILTERS);

        // Test formatting.
        assert_eq!("ServiceFlags(NONE)", ServiceFlags::NONE.to_string());
        assert_eq!("ServiceFlags(WITNESS)", ServiceFlags::WITNESS.to_string());
        let flag = ServiceFlags::WITNESS | ServiceFlags::BLOOM | ServiceFlags::NETWORK;
        assert_eq!("ServiceFlags(NETWORK|BLOOM|WITNESS)", flag.to_string());
        let flag = ServiceFlags::WITNESS | 0xf0.into();
        assert_eq!("ServiceFlags(WITNESS|COMPACT_FILTERS|0xb0)", flag.to_string());
    }
}
