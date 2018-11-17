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
use secp256k1::{self, Secp256k1};
use std::fmt;
use std::io;
use util::base58;

/// A Bitcoin ECDSA public key
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey {
    /// The actual ECDSA key
    pub key: secp256k1::PublicKey,
    /// Wether or not this key is supposed to be used
    /// in compressed or uncompressed form.
    pub compressed: bool,
}

impl PublicKey {
    /// Write the public key into a writer.
    pub fn write_into<W: io::Write>(&self, writer: &mut W) {
        let write_res: io::Result<()> = if self.compressed {
            writer.write_all(&self.key.serialize())
        } else {
            writer.write_all(&self.key.serialize_uncompressed())
        };
        debug_assert!(write_res.is_ok());
    }

    /// Serialize the public key.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf);
        buf
    }

    /// Deserialize a public key from a slice.  Also returns whether the public key was compressed.
    pub fn from_slice<C>(secp: &Secp256k1<C>, data: &[u8]) -> Result<PublicKey, encode::Error> {
        let key: secp256k1::PublicKey = secp256k1::PublicKey::from_slice(&secp, data)
            .map_err(|_| base58::Error::Other("Public key out of range".to_owned()))?;

        let compressed: bool = match data.len() {
            33 => true,
            65 => false,
            _ =>  { return Err(base58::Error::InvalidLength(data.len()).into()); },
        };

        Ok(PublicKey {
            key: key,
            compressed: compressed,
        })
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
            compressed: true,
        }
    }

    /// Computes the public key as supposed to be used with this secret
    pub fn public_key_uncompressed<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> PublicKey {
        PublicKey {
            key: secp256k1::PublicKey::from_secret_key(secp, &self.key),
            compressed: false,
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
    use network::constants::Network::Bitcoin;
    use network::constants::Network::Testnet;
    use secp256k1::Secp256k1;
    use util::address::Address;
    use util::wif;

    #[test]
    fn test_key_derivation() {
        // testnet compressed
        let (sk, network, compressed) =
            wif::decode("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
        assert_eq!(network, Testnet);
        assert_eq!(compressed, true);

        let secp = Secp256k1::new();
        let pk = Address::p2pkh(&sk.public_key(&secp), network);
        assert_eq!(&pk.to_string(), "mqwpxxvfv3QbM8PU8uBx2jaNt9btQqvQNx");

        // mainnet uncompressed
        let (sk, network, compressed) =
            wif::decode("5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3").unwrap();
        assert_eq!(network, Bitcoin);
        assert_eq!(compressed, false);

        let secp = Secp256k1::new();
        let pk = Address::p2pkh(&sk.public_key_uncompressed(&secp), network);
        assert_eq!(&pk.to_string(), "1GhQvF6dL8xa6wBxLnWmHcQsurx9RxiMc8");
    }
}
