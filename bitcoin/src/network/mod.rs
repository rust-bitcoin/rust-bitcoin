// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network.
//!
//! The term "network" is overloaded, here [`Network`] refers to the specific
//! Bitcoin network we are operating on e.g., signet, regtest. The terms
//! "network" and "chain" are often used interchangeably for this concept.

pub mod params;

use core::fmt;

use crate::constants::ChainHash;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::params::Params;
#[doc(inline)]
pub use network::{Network, NetworkKind, ParseNetworkError, TestnetVersion};

/// Trait to extend the [`Network`] type.
pub trait NetworkExt {
    /// Return the network's chain hash (genesis block hash).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::network::{Network, NetworkExt as _};
    /// use bitcoin::constants::ChainHash;
    ///
    /// let network = Network::Bitcoin;
    /// assert_eq!(network.chain_hash(), ChainHash::BITCOIN);
    /// ```
    fn chain_hash(self) -> ChainHash;

    /// Constructs a new `Network` from the chain hash (genesis block hash).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::network::{Network, NetworkExt as _};
    /// use bitcoin::constants::ChainHash;
    ///
    /// assert_eq!(Ok(Network::Bitcoin), Network::try_from(ChainHash::BITCOIN));
    /// ```
    fn from_chain_hash(chain_hash: ChainHash) -> Option<Self>
    where
        Self: Sized;
}

/// Returns the associated network parameters.
#[allow(unreachable_patterns)]
pub fn params(network: Network) -> &'static Params {
    match network {
        Network::Bitcoin => &Params::BITCOIN,
        Network::Testnet(TestnetVersion::V3) => &Params::TESTNET3,
        Network::Testnet(TestnetVersion::V4) => &Params::TESTNET4,
        Network::Testnet(_) => &Params::TESTNET4, // unreachable in network 0.1.0
        Network::Signet => &Params::SIGNET,
        Network::Regtest => &Params::REGTEST,
    }
}

impl NetworkExt for Network {
    fn chain_hash(self) -> ChainHash { ChainHash::using_genesis_block_const(self) }

    fn from_chain_hash(chain_hash: ChainHash) -> Option<Self> { Self::try_from(chain_hash).ok() }
}

#[cfg(feature = "serde")]
pub mod as_core_arg {
    //! Module for serialization/deserialization of network variants into/from Bitcoin Core values
    #![allow(missing_docs)]

    use crate::Network;

    pub fn serialize<S>(network: &Network, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(network.to_core_arg())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Network, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NetworkVisitor;

        impl serde::de::Visitor<'_> for NetworkVisitor {
            type Value = Network;

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                Network::from_core_arg(s).map_err(|_| {
                    E::invalid_value(
                        serde::de::Unexpected::Str(s),
                        &"bitcoin network encoded as a string (either main, test, testnet4, signet or regtest)",
                    )
                })
            }

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(
                    formatter,
                    "bitcoin network encoded as a string (either main, test, testnet4, signet or regtest)"
                )
            }
        }

        deserializer.deserialize_str(NetworkVisitor)
    }
}

/// Error in parsing network from chain hash.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownChainHashError(ChainHash);

impl fmt::Display for UnknownChainHashError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unknown chain hash: {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownChainHashError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

impl TryFrom<ChainHash> for Network {
    type Error = UnknownChainHashError;

    fn try_from(chain_hash: ChainHash) -> Result<Self, Self::Error> {
        match chain_hash {
            // Note: any new network entries must be matched against here.
            ChainHash::BITCOIN => Ok(Self::Bitcoin),
            ChainHash::TESTNET3 => Ok(Self::Testnet(TestnetVersion::V3)),
            ChainHash::TESTNET4 => Ok(Self::Testnet(TestnetVersion::V4)),
            ChainHash::SIGNET => Ok(Self::Signet),
            ChainHash::REGTEST => Ok(Self::Regtest),
            _ => Err(UnknownChainHashError(chain_hash)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Network, TestnetVersion};

    #[test]
    fn string() {
        assert_eq!(Network::Bitcoin.to_string(), "bitcoin");
        assert_eq!(Network::Testnet(TestnetVersion::V3).to_string(), "testnet");
        assert_eq!(Network::Testnet(TestnetVersion::V4).to_string(), "testnet4");
        assert_eq!(Network::Regtest.to_string(), "regtest");
        assert_eq!(Network::Signet.to_string(), "signet");

        assert_eq!("bitcoin".parse::<Network>().unwrap(), Network::Bitcoin);
        assert_eq!("testnet".parse::<Network>().unwrap(), Network::Testnet(TestnetVersion::V3));
        assert_eq!("testnet4".parse::<Network>().unwrap(), Network::Testnet(TestnetVersion::V4));
        assert_eq!("regtest".parse::<Network>().unwrap(), Network::Regtest);
        assert_eq!("signet".parse::<Network>().unwrap(), Network::Signet);
        assert!("fakenet".parse::<Network>().is_err());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_roundtrip() {
        use Network::*;
        let tests = vec![
            (Bitcoin, "bitcoin"),
            (Testnet(TestnetVersion::V3), "testnet"),
            (Testnet(TestnetVersion::V4), "testnet4"),
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
            (Network::Testnet(TestnetVersion::V3), "test"),
            (Network::Testnet(TestnetVersion::V4), "testnet4"),
            (Network::Regtest, "regtest"),
            (Network::Signet, "signet"),
        ];

        for (net, core_arg) in &expected_pairs {
            assert_eq!(Network::from_core_arg(core_arg), Ok(*net));
            assert_eq!(net.to_core_arg(), *core_arg);
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_as_core_arg() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
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
