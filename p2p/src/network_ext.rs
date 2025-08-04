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
            Network::Bitcoin => 8333,
            Network::Signet => 38333,
            Network::Testnet(TestnetVersion::V3) => 18333,
            Network::Testnet(TestnetVersion::V4) => 48333,
            Network::Testnet(_) => 48333,
            Network::Regtest => 18444,
        }
    }

    /// The default network [`Magic`] for a given [`Network`].
    ///
    /// Note: All [`TestnetVersion`] variants >4 are treated as [`TestnetVersion::V4`].
    /// This function will be updated as new test networks are defined.
    fn default_network_magic(self) -> Magic {
        match &self {
            Network::Bitcoin => Magic::BITCOIN,
            Network::Signet => Magic::SIGNET,
            Network::Testnet(TestnetVersion::V3) => Magic::TESTNET3,
            Network::Testnet(TestnetVersion::V4) => Magic::TESTNET4,
            Network::Testnet(_) => Magic::TESTNET4,
            Network::Regtest => Magic::REGTEST,
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
