// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network.
//!
//! The term "network" is overloaded, here [`Network`] refers to the specific
//! Bitcoin network we are operating on e.g., signet, regtest. The terms
//! "network" and "chain" are often used interchangeably for this concept.

use core::fmt;
use core::fmt::Display;
use core::str::FromStr;

use internals::write_err;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::constants::ChainHash;
use crate::params::Params;
use crate::prelude::*;

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
            Testnet | Signet | Regtest => NetworkKind::Test,
        }
    }
}

/// The cryptocurrency network to act on.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[non_exhaustive]
pub enum Network {
    /// Mainnet Bitcoin.
    Bitcoin,
    /// Bitcoin's testnet network.
    Testnet,
    /// Bitcoin's signet network.
    Signet,
    /// Bitcoin's regtest network.
    Regtest,
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
            Network::Testnet => "test",
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
            "test" => Testnet,
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
    /// use bitcoin_primitives::Network;
    /// use bitcoin_primitives::constants::ChainHash;
    ///
    /// let network = Network::Bitcoin;
    /// assert_eq!(network.chain_hash(), ChainHash::BITCOIN);
    /// ```
    pub fn chain_hash(self) -> ChainHash { ChainHash::using_genesis_block_const(self) }

    /// Creates a `Network` from the chain hash (genesis block hash).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin_primitives::Network;
    /// use bitcoin_primitives::constants::ChainHash;
    ///
    /// assert_eq!(Ok(Network::Bitcoin), Network::try_from(ChainHash::BITCOIN));
    /// ```
    pub fn from_chain_hash(chain_hash: ChainHash) -> Option<Network> {
        Network::try_from(chain_hash).ok()
    }

    /// Returns the associated network parameters.
    pub const fn params(self) -> &'static Params {
        const PARAMS: [Params; 4] = [
            Params::new(Network::Bitcoin),
            Params::new(Network::Testnet),
            Params::new(Network::Signet),
            Params::new(Network::Regtest),
        ];
        &PARAMS[self as usize]
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

        impl<'de> serde::de::Visitor<'de> for NetworkVisitor {
            type Value = Network;

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                Network::from_core_arg(s).map_err(|_| {
                    E::invalid_value(
                        serde::de::Unexpected::Str(s),
                        &"bitcoin network encoded as a string (either main, test, signet or regtest)",
                    )
                })
            }

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(
                    formatter,
                    "bitcoin network encoded as a string (either main, test, signet or regtest)"
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
        use Network::*;

        let network = match s {
            "bitcoin" => Bitcoin,
            "testnet" => Testnet,
            "signet" => Signet,
            "regtest" => Regtest,
            _ => return Err(ParseNetworkError(s.to_owned())),
        };
        Ok(network)
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use Network::*;

        let s = match *self {
            Bitcoin => "bitcoin",
            Testnet => "testnet",
            Signet => "signet",
            Regtest => "regtest",
        };
        write!(f, "{}", s)
    }
}

/// Error in parsing network from chain hash.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownChainHashError(ChainHash);

impl Display for UnknownChainHashError {
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
            ChainHash::TESTNET => Ok(Network::Testnet),
            ChainHash::SIGNET => Ok(Network::Signet),
            ChainHash::REGTEST => Ok(Network::Regtest),
            _ => Err(UnknownChainHashError(chain_hash)),
        }
    }
}
