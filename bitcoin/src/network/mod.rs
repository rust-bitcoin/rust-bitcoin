// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network.
//!
//! The term "network" is overloaded, here [`Network`] refers to the specific
//! Bitcoin network we are operating on e.g., signet, regtest. The terms
//! "network" and "chain" are often used interchangeably for this concept.

pub mod params;

use core::fmt;
use core::str::FromStr;

use internals::write_err;
#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

use crate::constants::ChainHash;
use crate::prelude::{String, ToOwned};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::params::Params;

/// What kind of network we are on.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkKind {
    /// The Bitcoin mainnet network.
    Main,
    /// Some kind of testnet network.
    Test,
}

// We explicitly do not provide `is_testnet`, using `!network.is_mainnet()` is less
// ambiguous due to confusion caused by signet/testnet/regtest.
impl NetworkKind {
    /// Returns true if this is real mainnet bitcoin.
    pub fn is_mainnet(&self) -> bool { *self == NetworkKind::Main }
}

impl From<Network> for NetworkKind {
    fn from(n: Network) -> Self {
        use Network::*;

        match n {
            Bitcoin => NetworkKind::Main,
            Testnet(_) | Signet | Regtest => NetworkKind::Test,
        }
    }
}

/// The testnet version to act on.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
#[non_exhaustive]
pub enum TestnetVersion {
    /// Testnet version 3.
    V3,
    /// Testnet version 4.
    V4,
}

/// The cryptocurrency network to act on.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
#[non_exhaustive]
pub enum Network {
    /// Mainnet Bitcoin.
    Bitcoin,
    /// Bitcoin's testnet network.
    Testnet(TestnetVersion),
    /// Bitcoin's signet network.
    Signet,
    /// Bitcoin's regtest network.
    Regtest,
}

#[cfg(feature = "serde")]
impl Serialize for Network {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_display_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Network {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NetworkVisitor;

        impl Visitor<'_> for NetworkVisitor {
            type Value = Network;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid network identifier")
            }

            fn visit_str<E>(self, value: &str) -> Result<Network, E>
            where
                E: serde::de::Error,
            {
                Network::from_str(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(NetworkVisitor)
    }
}

impl Network {
    /// Converts a `Network` to its equivalent `bitcoind -chain` argument name.
    ///
    /// ```bash
    /// $ bitcoin-23.0/bin/bitcoind --help | grep -C 3 '\-chain=<chain>'
    /// Chain selection options:
    ///
    /// -chain=<chain>
    /// Use the chain <chain> (default: main). Allowed values: main, test, signet, regtest
    /// ```
    pub fn to_core_arg(self) -> &'static str {
        match self {
            Network::Bitcoin => "main",
            // For user-side compatibility, testnet3 is retained as test
            Network::Testnet(TestnetVersion::V3) => "test",
            Network::Testnet(TestnetVersion::V4) => "testnet4",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        }
    }

    /// Converts a `bitcoind -chain` argument name to its equivalent `Network`.
    ///
    /// ```bash
    /// $ bitcoin-23.0/bin/bitcoind --help | grep -C 3 '\-chain=<chain>'
    /// Chain selection options:
    ///
    /// -chain=<chain>
    /// Use the chain <chain> (default: main). Allowed values: main, test, signet, regtest
    /// ```
    pub fn from_core_arg(core_arg: &str) -> Result<Self, ParseNetworkError> {
        use Network::*;

        let network = match core_arg {
            "main" => Bitcoin,
            "test" => Testnet(TestnetVersion::V3),
            "testnet4" => Testnet(TestnetVersion::V4),
            "signet" => Signet,
            "regtest" => Regtest,
            _ => return Err(ParseNetworkError(core_arg.to_owned())),
        };
        Ok(network)
    }

    /// Return the network's chain hash (genesis block hash).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::Network;
    /// use bitcoin::constants::ChainHash;
    ///
    /// let network = Network::Bitcoin;
    /// assert_eq!(network.chain_hash(), ChainHash::BITCOIN);
    /// ```
    pub fn chain_hash(self) -> ChainHash { ChainHash::using_genesis_block_const(self) }

    /// Constructs a new `Network` from the chain hash (genesis block hash).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::Network;
    /// use bitcoin::constants::ChainHash;
    ///
    /// assert_eq!(Ok(Network::Bitcoin), Network::try_from(ChainHash::BITCOIN));
    /// ```
    pub fn from_chain_hash(chain_hash: ChainHash) -> Option<Network> {
        Network::try_from(chain_hash).ok()
    }

    /// Returns the associated network parameters.
    pub const fn params(self) -> &'static Params {
        match self {
            Network::Bitcoin => &Params::BITCOIN,
            Network::Testnet(TestnetVersion::V3) => &Params::TESTNET3,
            Network::Testnet(TestnetVersion::V4) => &Params::TESTNET4,
            Network::Signet => &Params::SIGNET,
            Network::Regtest => &Params::REGTEST,
        }
    }

    /// Returns a string representation of the `Network` enum variant.
    /// This is useful for displaying the network type as a string.
    const fn as_display_str(self) -> &'static str {
        match self {
            Network::Bitcoin => "bitcoin",
            Network::Testnet(TestnetVersion::V3) => "testnet",
            Network::Testnet(TestnetVersion::V4) => "testnet4",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        }
    }
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

/// An error in parsing network string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseNetworkError(String);

impl fmt::Display for ParseNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write_err!(f, "failed to parse {} as network", self.0; self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseNetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

impl FromStr for Network {
    type Err = ParseNetworkError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bitcoin" => Ok(Network::Bitcoin),
            // For user-side compatibility, testnet3 is retained as testnet
            "testnet" => Ok(Network::Testnet(TestnetVersion::V3)),
            "testnet4" => Ok(Network::Testnet(TestnetVersion::V4)),
            "signet" => Ok(Network::Signet),
            "regtest" => Ok(Network::Regtest),
            _ => Err(ParseNetworkError(s.to_owned())),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self.as_display_str())
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
            ChainHash::BITCOIN => Ok(Network::Bitcoin),
            ChainHash::TESTNET3 => Ok(Network::Testnet(TestnetVersion::V3)),
            ChainHash::TESTNET4 => Ok(Network::Testnet(TestnetVersion::V4)),
            ChainHash::SIGNET => Ok(Network::Signet),
            ChainHash::REGTEST => Ok(Network::Regtest),
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
