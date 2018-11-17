// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Bitcoin Keys
//!
//! Structures and methods representing the public/secret data associated with
//! its proposed use
//!

use std::fmt;

use secp256k1::{self, Secp256k1};

use consensus::encode;
use network::constants::Network;
use util::base58;
use util::key;

/// Format the private key to WIF format.
pub fn write(fmt: &mut fmt::Write, pk: &key::PrivateKey, network: Network) -> fmt::Result {
    let mut ret = [0; 34];
    ret[0] = match network {
        Network::Bitcoin => 128,
        Network::Testnet | Network::Regtest => 239,
    };
    ret[1..33].copy_from_slice(&pk.key[..]);
    ret[33] = 1;
    fmt.write_str(&base58::check_encode_slice(&ret[..]))
}

/// Format the private key to WIF format for use with uncompressed addresses.
pub fn write_uncompressed(
    fmt: &mut fmt::Write,
    pk: &key::PrivateKey,
    network: Network,
) -> fmt::Result {
    let mut ret = [0; 34];
    ret[0] = match network {
        Network::Bitcoin => 128,
        Network::Testnet | Network::Regtest => 239,
    };
    ret[1..33].copy_from_slice(&pk.key[..]);
    fmt.write_str(&base58::check_encode_slice(&ret[..33]))
}

/// Get WIF encoding of this private key.
pub fn encode(pk: &key::PrivateKey, network: Network) -> String {
    let mut buf = String::new();
    write(&mut buf, &pk, network).unwrap();
    buf.shrink_to_fit();
    buf
}

/// Get WIF encoding of this private key for use with uncompressed addresses.
pub fn encode_uncompressed(pk: &key::PrivateKey, network: Network) -> String {
    let mut buf = String::new();
    write_uncompressed(&mut buf, &pk, network).unwrap();
    buf.shrink_to_fit();
    buf
}

/// Parse WIF encoded private key.  Returns a tuple containing the private key,
/// the network the key is intended to be used with and whether the public key should be
/// compressed when creating an address with this key.
pub fn decode(wif: &str) -> Result<(key::PrivateKey, Network, bool), encode::Error> {
    let data = base58::from_check(wif)?;

    let compressed = match data.len() {
        33 => false,
        34 => true,
        _ => {
            return Err(encode::Error::Base58(base58::Error::InvalidLength(data.len())));
        }
    };

    let network = match data[0] {
        128 => Network::Bitcoin,
        239 => Network::Testnet,
        x => {
            return Err(encode::Error::Base58(base58::Error::InvalidVersion(vec![x])));
        }
    };

    let secp = Secp256k1::without_caps();
    let key = secp256k1::SecretKey::from_slice(&secp, &data[1..33])
        .map_err(|_| base58::Error::Other("Secret key out of range".to_owned()))?;

    let pk = key::PrivateKey {
        key: key,
    };
    Ok((pk, network, compressed))
}

#[cfg(test)]
mod tests {
    use network::constants::Network::Bitcoin;
    use network::constants::Network::Testnet;

    #[test]
    fn test_wif() {
        // testnet compressed
        let (sk, network, compressed) =
            super::decode("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
        assert_eq!(network, Testnet);
        assert_eq!(compressed, true);
        assert_eq!(
            super::encode(&sk, network),
            "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy"
        );

        // mainnet uncompressed
        let (sk, network, compressed) =
            super::decode("5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3").unwrap();
        assert_eq!(network, Bitcoin);
        assert_eq!(compressed, false);
        assert_eq!(
            super::encode_uncompressed(&sk, network),
            "5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3"
        );
    }
}
