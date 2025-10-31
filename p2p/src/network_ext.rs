// SPDX-License-Identifier: CC0-1.0

//! This module implements an extension trait for [`Network`]
//! with getter methods for the default P2P port and default
//! network [`Magic`] bytes.

use bitcoin::{Network, TestnetVersion};

use crate::Magic;

/// Trait that extends [`Network`] by adding getter methods for the default P2P ports and [`Magic`] bytes.
pub trait NetworkExt {
    /// The default P2P port for a given [`Network`].
    fn default_p2p_port(self) -> u16;

    /// The default network [`Magic`] for a given [`Network`].
    fn default_network_magic(self) -> Magic;
}

impl NetworkExt for Network {
    /// The default P2P port for a given [`Network`].
    ///
    /// Note: All [`TestnetVersion`] variants >4 are treated as [`TestnetVersion::V4`].
    /// This function will be updated as new test networks are defined.
    fn default_p2p_port(self) -> u16 {
        match &self {
            Self::Bitcoin => 8333,
            Self::Signet => 38333,
            Self::Testnet(TestnetVersion::V3) => 18333,
            Self::Testnet(TestnetVersion::V4) => 48333,
            Self::Testnet(_) => 48333,
            Self::Regtest => 18444,
        }
    }

    /// The default network [`Magic`] for a given [`Network`].
    ///
    /// Note: All [`TestnetVersion`] variants >4 are treated as [`TestnetVersion::V4`].
    /// This function will be updated as new test networks are defined.
    fn default_network_magic(self) -> Magic {
        match &self {
            Self::Bitcoin => Magic::BITCOIN,
            Self::Signet => Magic::SIGNET,
            Self::Testnet(TestnetVersion::V3) => Magic::TESTNET3,
            Self::Testnet(TestnetVersion::V4) => Magic::TESTNET4,
            Self::Testnet(_) => Magic::TESTNET4,
            Self::Regtest => Magic::REGTEST,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn default_p2p_port() {
        let networks = [
            Network::Bitcoin,
            Network::Signet,
            Network::Testnet(TestnetVersion::V3),
            Network::Testnet(TestnetVersion::V4),
            Network::Regtest,
        ];

        let p2p_ports = vec![8333, 38333, 18333, 48333, 18444];

        for (network, p2p_port) in networks.iter().zip(p2p_ports) {
            assert_eq!(network.default_p2p_port(), p2p_port);
        }
    }

    #[test]
    fn default_network_magic() {
        let networks = [
            Network::Bitcoin,
            Network::Signet,
            Network::Testnet(TestnetVersion::V3),
            Network::Testnet(TestnetVersion::V4),
            Network::Regtest,
        ];

        let network_magics =
            vec![Magic::BITCOIN, Magic::SIGNET, Magic::TESTNET3, Magic::TESTNET4, Magic::REGTEST];

        for (network, network_magic) in networks.iter().zip(network_magics) {
            assert_eq!(network.default_network_magic(), network_magic);
        }
    }
}
