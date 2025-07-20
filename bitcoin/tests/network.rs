//! Tests what a user can do when pattern matching on `Network` and associated types.

use bitcoin::network::{Network, NetworkKind, TestnetVersion};

#[test]
fn can_match_exhaustively_on_network() {
    // Returns true if `n` is mainnet.
    fn is_mainnet(n: Network) -> bool { matches!(n, Network::Bitcoin) }

    assert!(is_mainnet(Network::Bitcoin));
}

#[test]
fn can_match_exhaustively_on_testnet() {
    // Returns true if `n` is any testnet.
    fn is_testnet(n: Network) -> bool { matches!(n, Network::Testnet(_)) }

    assert!(is_testnet(Network::Testnet(TestnetVersion::V3)));
}

#[test]
fn can_use_network_kind() {
    // Returns true if `n` is any mainnet.
    fn is_mainnet(n: Network) -> bool { NetworkKind::from(n).is_mainnet() }

    // Returns true if `n` is a any testnet.
    fn is_testnet(n: Network) -> bool { !NetworkKind::from(n).is_mainnet() }

    assert!(is_mainnet(Network::Bitcoin));
    assert!(!is_testnet(Network::Bitcoin));

    assert!(is_testnet(Network::Testnet(TestnetVersion::V3)));
    assert!(!is_mainnet(Network::Testnet(TestnetVersion::V3)));
}

#[test]
fn can_not_match_exaustively_on_testnet_version() {
    // Returns true if `n` is testnet version 3.
    fn is_testnet_v3(n: Network) -> bool {
        match n {
            Network::Testnet(TestnetVersion::V3) => true,
            Network::Testnet(TestnetVersion::V4) => false,
            // Catchall because of `non_exhaustive` attribute.
            Network::Testnet(_) => false,
            _ => false,
        }
    }

    assert!(is_testnet_v3(Network::Testnet(TestnetVersion::V3)));
}

#[test]
fn can_match_on_testnet_version_3_only() {
    // Returns true if `n` is testnet version 3.
    fn is_testnet_v3(n: Network) -> bool {
        match n {
            Network::Testnet(TestnetVersion::V3) => true,
            // Catchall because its logically correct to do so.
            Network::Testnet(_) => false,
            _ => false,
        }
    }

    assert!(is_testnet_v3(Network::Testnet(TestnetVersion::V3)));
}
