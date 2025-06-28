//! Tests that an external user can match on `Network` but not on `TestnetVersion`.

use bitcoin::network::{Network, TestnetVersion};

#[test]
fn can_match_exhaustively_on_network() {
    // Some function that matches on network.
    fn is_mainnet(n: Network) -> bool {
        matches!(n, Network::Bitcoin)
    }

    let n = Network::Bitcoin;
    assert!(is_mainnet(n));
}

#[test]
fn can_match_on_testnet() {
    // Returns true if `n` is any testnet.
    fn is_testnet(n: Network) -> bool {
        matches!(n, Network::Testnet(_))
    }

    let n = Network::Testnet(TestnetVersion::V3);
    assert!(is_testnet(n));
}

#[test]
fn can_match_exoastively_on_testnet_version() {
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

    let n = Network::Testnet(TestnetVersion::V3);
    assert!(is_testnet_v3(n));
}

#[test]
fn can_match_exaustively_on_testnet_version_3_only() {
    // Returns true if `n` is testnet version 3.
    fn is_testnet_v3(n: Network) -> bool {
        match n {
            Network::Testnet(TestnetVersion::V3) => true,
            // Catchall because its logically correct to do so.
            Network::Testnet(_) => false,
            _ => false,
        }
    }

    let n = Network::Testnet(TestnetVersion::V3);
    assert!(is_testnet_v3(n));
}
