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

use consensus::encode;
use network::constants::Network;
use secp256k1::{self, Secp256k1};
use std::fmt;
use std::io;
use util::base58;

/// A Bitcoin ECDSA public key
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey {
    /// The actual ECDSA key
    pub key: secp256k1::PublicKey,
}

impl PublicKey {
    /// Write the public key into a writer in compressed form.
    pub fn write_into<W: io::Write>(&self, writer: &mut W) {
        let write_res: io::Result<()> = writer.write_all(&self.key.serialize());
        debug_assert!(write_res.is_ok());
    }

    /// Write the public key into a writer in uncompressed form.
    pub fn write_into_uncompressed<W: io::Write>(&self, writer: &mut W) {
        let write_res: io::Result<()> = writer.write_all(&self.key.serialize_uncompressed());
        debug_assert!(write_res.is_ok());
    }

    /// Serialize the public key in compressed form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf);
        buf
    }

    /// Serialize the public key in uncompressed form.
    pub fn to_bytes_uncompressed(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into_uncompressed(&mut buf);
        buf
    }

    /// Deserialize a public key from a slice.  Also returns whether the public key was compressed.
    pub fn from_slice<C>(secp: &Secp256k1<C>, data: &[u8]) -> Result<(PublicKey, bool), encode::Error> {
        let key: secp256k1::PublicKey = secp256k1::PublicKey::from_slice(&secp, data)
            .map_err(|_| base58::Error::Other("Public key out of range".to_owned()))?;

        let compressed: bool = match data.len() {
            33 => true,
            65 => false,
            _ =>  { return Err(base58::Error::InvalidLength(data.len()).into()); },
        };
        let pk = PublicKey {
            key: key,
        };
        Ok((pk, compressed))
    }

    /// Computes the public key as supposed to be used with this secret
    pub fn from_private_key<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        sk: &PrivateKey,
    ) -> PublicKey {
        sk.public_key(secp)
    }
}

#[derive(Clone, PartialEq, Eq)]
/// A Bitcoin ECDSA private key
pub struct PrivateKey {
    /// The actual ECDSA key
    pub key: secp256k1::SecretKey,
}

impl PrivateKey {
    /// Computes the public key as supposed to be used with this secret
    pub fn public_key<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> PublicKey {
        PublicKey {
            key: secp256k1::PublicKey::from_secret_key(secp, &self.key),
        }
    }

    /// Write the private key into a writer.
    pub fn write_into<W: io::Write>(&self, writer: &mut W) {
        let write_res: io::Result<()> = writer.write_all(&self.key[..]);
        debug_assert!(write_res.is_ok());
    }

    /// Serialize the private key.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf);
        buf
    }

    /// Format the private key to WIF format.
    pub fn fmt_wif(&self, fmt: &mut fmt::Write, network: Network, compressed: bool) -> fmt::Result {
        let mut ret = [0; 34];
        ret[0] = match network {
            Network::Bitcoin => 128,
            Network::Testnet | Network::Regtest => 239,
        };
        ret[1..33].copy_from_slice(&self.key[..]);
        let privkey = if compressed {
            ret[33] = 1;
            base58::check_encode_slice(&ret[..])
        } else {
            base58::check_encode_slice(&ret[..33])
        };
        fmt.write_str(&privkey)
    }

    /// Get WIF encoding of this private key.
    pub fn to_wif(&self, network: Network, compressed: bool) -> String {
        let mut buf = String::new();
        self.fmt_wif(&mut buf, network, compressed).unwrap();
        buf.shrink_to_fit();
        buf
    }

    /// Parse WIF encoded private key.  Returns a tuple containing the private key,
    /// the network the key is intended to be used with and whether the public key should be
    /// compressed when creating an address with this key.
    pub fn from_wif(wif: &str) -> Result<(PrivateKey, Network, bool), encode::Error> {
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

        let pk = PrivateKey {
            key: key,
        };
        Ok((pk, network, compressed))
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[private key data]")
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[private key data]")
    }
}

#[cfg(test)]
mod tests {
    use super::PrivateKey;
    use network::constants::Network::Bitcoin;
    use network::constants::Network::Testnet;
    use secp256k1::Secp256k1;
    use util::address::Address;

    #[test]
    fn test_key_derivation() {
        // testnet compressed
        let (sk, network, compressed) =
            PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
        assert_eq!(network, Testnet);
        assert_eq!(compressed, true);
        assert_eq!(
            &sk.to_wif(network, compressed),
            "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy"
        );

        let secp = Secp256k1::new();
        let pk = Address::p2pkh(&sk.public_key(&secp), network, compressed);
        assert_eq!(&pk.to_string(), "mqwpxxvfv3QbM8PU8uBx2jaNt9btQqvQNx");

        // mainnet uncompressed
        let (sk, network, compressed) =
            PrivateKey::from_wif("5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3").unwrap();
        assert_eq!(network, Bitcoin);
        assert_eq!(compressed, false);
        assert_eq!(
            &sk.to_wif(network, compressed),
            "5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3"
        );
    }
}
