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
