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

use crate::p2p::Magic;
/// Re-export everything from the [`primitives::network`] module.
#[doc(inline)]
pub use crate::primitives::network::*;

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
    fn string_test() {
        assert_eq!(Network::Bitcoin.to_string(), "bitcoin");
        assert_eq!(Network::Testnet.to_string(), "testnet");
        assert_eq!(Network::Regtest.to_string(), "regtest");
        assert_eq!(Network::Signet.to_string(), "signet");

        assert_eq!("bitcoin".parse::<Network>().unwrap(), Network::Bitcoin);
        assert_eq!("testnet".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!("regtest".parse::<Network>().unwrap(), Network::Regtest);
        assert_eq!("signet".parse::<Network>().unwrap(), Network::Signet);
        assert!("fakenet".parse::<Network>().is_err());
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

    #[test]
    #[cfg(feature = "serde")]
    fn serde_roundtrip() {
        use Network::*;
        let tests = vec![
            (Bitcoin, "bitcoin"),
            (Testnet, "testnet"),
            (Signet, "signet"),
            (Regtest, "regtest"),
        ];

        for tc in tests {
            let network = tc.0;

            let want = format!("\"{}\"", tc.1);
            let got = serde_json::to_string(&tc.0).expect("failed to serialize network");
            assert_eq!(got, want);

            let back: Network = serde_json::from_str(&got).expect("failed to deserialize network");
            assert_eq!(back, network);
        }
    }

    #[test]
    fn from_to_core_arg() {
        let expected_pairs = [
            (Network::Bitcoin, "main"),
            (Network::Testnet, "test"),
            (Network::Regtest, "regtest"),
            (Network::Signet, "signet"),
        ];

        for (net, core_arg) in &expected_pairs {
            assert_eq!(Network::from_core_arg(core_arg), Ok(*net));
            assert_eq!(net.to_core_arg(), *core_arg);
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_core_arg() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        #[serde(crate = "actual_serde")]
        struct T {
            #[serde(with = "crate::network::as_core_arg")]
            pub network: Network,
        }

        serde_test::assert_tokens(
            &T { network: Network::Bitcoin },
            &[
                serde_test::Token::Struct { name: "T", len: 1 },
                serde_test::Token::Str("network"),
                serde_test::Token::Str("main"),
                serde_test::Token::StructEnd,
            ],
        );
    }
}
