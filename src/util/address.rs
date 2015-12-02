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

//! # Addresses
//! Support for ordinary base58 Bitcoin addresses and private keys
//!

use secp256k1::{self, Secp256k1};
use secp256k1::key::{PublicKey, SecretKey};

use blockdata::script;
use blockdata::opcodes;
use network::constants::Network;
use util::hash::Hash160;
use util::base58::{self, FromBase58, ToBase58};

/// The method used to produce an address
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Type {
    /// Standard pay-to-pkhash address
    PubkeyHash,
    /// New-fangled P2SH address
    ScriptHash
}

/// An address-related error
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Private key did not represent a valid ECDSA secret key
    Secp(secp256k1::Error)
}

#[derive(Clone, PartialEq, Eq)]
/// A Bitcoin address
pub struct Address {
    /// The type of the address
    pub ty: Type,
    /// The network on which this address is usable
    pub network: Network,
    /// The pubkeyhash that this address encodes
    pub hash: Hash160
}

impl Address {
    /// Creates an address from a public key
    #[inline]
    pub fn from_key(network: Network, pk: &PublicKey, compressed: bool) -> Address {
        let secp = Secp256k1::without_caps();
        Address {
            ty: Type::PubkeyHash,
            network: network,
            hash: Hash160::from_data(&pk.serialize_vec(&secp, compressed)[..])
        }
    }

    /// Creates a P2SH address from a script
    #[inline]
    pub fn from_script(network: Network, script: &script::Script) -> Address {
        Address {
            ty: Type::ScriptHash,
            network: network,
            hash: Hash160::from_data(&script[..])
        }
    }

    /// Generates a script pubkey spending to this address
    #[inline]
    pub fn script_pubkey(&self) -> script::Script {
        match self.ty {
            Type::PubkeyHash => {
                script::Builder::new()
                    .push_opcode(opcodes::All::OP_DUP)
                    .push_opcode(opcodes::All::OP_HASH160)
                    .push_slice(&self.hash[..])
                    .push_opcode(opcodes::All::OP_EQUALVERIFY)
                    .push_opcode(opcodes::All::OP_CHECKSIG)
            }
            Type::ScriptHash => {
                script::Builder::new()
                    .push_opcode(opcodes::All::OP_HASH160)
                    .push_slice(&self.hash[..])
                    .push_opcode(opcodes::All::OP_EQUAL)
            }
        }.into_script()
    }
}

impl ToBase58 for Address {
    fn base58_layout(&self) -> Vec<u8> {
        let mut ret = vec![
            match (self.network, self.ty) {
                (Network::Bitcoin, Type::PubkeyHash) => 0,
                (Network::Bitcoin, Type::ScriptHash) => 5,
                (Network::Testnet, Type::PubkeyHash) => 111,
                (Network::Testnet, Type::ScriptHash) => 196
            }
        ];
        ret.extend(self.hash[..].iter().cloned());
        ret
    }
}

impl FromBase58 for Address {
    fn from_base58_layout(data: Vec<u8>) -> Result<Address, base58::Error> {
        if data.len() != 21 {
            return Err(base58::Error::InvalidLength(data.len()));
        }

        let (network, ty) = match data[0] {
            0   => (Network::Bitcoin, Type::PubkeyHash),
            5   => (Network::Bitcoin, Type::ScriptHash),
            111 => (Network::Testnet, Type::PubkeyHash),
            196 => (Network::Testnet, Type::ScriptHash),
            x   => { return Err(base58::Error::InvalidVersion(vec![x])); }
        };

        Ok(Address {
            ty: ty,
            network: network,
            hash: Hash160::from(&data[1..])
        })
    }
}

impl ::std::fmt::Debug for Address {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.to_base58check())
    }
}

#[derive(Clone, PartialEq, Eq)]
/// A Bitcoin ECDSA private key
pub struct Privkey {
    /// Whether this private key represents a compressed address
    pub compressed: bool,
    /// The network on which this key should be used
    pub network: Network,
    /// The actual ECDSA key
    pub key: SecretKey
}

impl Privkey {
    /// Creates an address from a public key
    #[inline]
    pub fn from_key(network: Network, sk: SecretKey, compressed: bool) -> Privkey {
        Privkey {
            compressed: compressed,
            network: network,
            key: sk
        }
    }

    /// Converts a private key to an address
    #[inline]
    pub fn to_address(&self, secp: &Secp256k1) -> Result<Address, Error> {
        let key = try!(PublicKey::from_secret_key(secp, &self.key).map_err(Error::Secp));
        Ok(Address::from_key(self.network, &key, self.compressed))
    }

    /// Accessor for the underlying secp key
    #[inline]
    pub fn secret_key(&self) -> &SecretKey {
        &self.key
    }

    /// Accessor for the underlying secp key that consumes the privkey
    #[inline]
    pub fn into_secret_key(self) -> SecretKey {
        self.key
    }

    /// Accessor for the network type
    #[inline]
    pub fn network(&self) -> Network {
        self.network
    }

    /// Accessor for the compressed flag
    #[inline]
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }
}

impl ToBase58 for Privkey {
    fn base58_layout(&self) -> Vec<u8> {
        let mut ret = vec![
            match self.network {
                Network::Bitcoin => 128,
                Network::Testnet => 239
            }
        ];
        ret.extend(&self.key[..]);
        if self.compressed { ret.push(1); }
        ret
    }
}

impl FromBase58 for Privkey {
    fn from_base58_layout(data: Vec<u8>) -> Result<Privkey, base58::Error> {
        let compressed = match data.len() {
            33 => false,
            34 => true,
            _ => { return Err(base58::Error::InvalidLength(data.len())); }
        };

        let network = match data[0] {
            128 => Network::Bitcoin,
            239 => Network::Testnet,
            x   => { return Err(base58::Error::InvalidVersion(vec![x])); }
        };

        let secp = Secp256k1::without_caps();
        let key = try!(SecretKey::from_slice(&secp, &data[1..33])
                           .map_err(|_| base58::Error::Other("Secret key out of range".to_owned())));

        Ok(Privkey {
            compressed: compressed,
            network: network,
            key: key
        })
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::Secp256k1;
    use secp256k1::key::PublicKey;
    use serialize::hex::FromHex;

    use blockdata::script::Script;
    use network::constants::Network::{Bitcoin, Testnet};
    use util::hash::Hash160;
    use util::base58::{FromBase58, ToBase58};
    use super::*;

    macro_rules! hex (($hex:expr) => ($hex.from_hex().unwrap()));
    macro_rules! hex_key (($secp:expr, $hex:expr) => (PublicKey::from_slice($secp, &hex!($hex)).unwrap()));
    macro_rules! hex_script (($hex:expr) => (Script::from(hex!($hex))));

    #[test]
    fn test_p2pkh_address_58() {
        let addr = Address {
            ty: Type::PubkeyHash,
            network: Bitcoin,
            hash: Hash160::from(&"162c5ea71c0b23f5b9022ef047c4a86470a5b070".from_hex().unwrap()[..])
        };

        assert_eq!(addr.script_pubkey(), hex_script!("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac"));
        assert_eq!(&addr.to_base58check(), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
        assert_eq!(FromBase58::from_base58check("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM"), Ok(addr));
    }

    #[test]
    fn test_p2pkh_from_key() {
        let secp = Secp256k1::without_caps();

        let key = hex_key!(&secp, "048d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b6042a0431ded2478b5c9cf2d81c124a5e57347a3c63ef0e7716cf54d613ba183");
        let addr = Address::from_key(Bitcoin, &key, false);
        assert_eq!(&addr.to_base58check(), "1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY");

        let key = hex_key!(&secp, &"03df154ebfcf29d29cc10d5c2565018bce2d9edbab267c31d2caf44a63056cf99f");
        let addr = Address::from_key(Testnet, &key, true);
        assert_eq!(&addr.to_base58check(), "mqkhEMH6NCeYjFybv7pvFC22MFeaNT9AQC");
    }

    #[test]
    fn test_p2sh_address_58() {
        let addr = Address {
            ty: Type::ScriptHash,
            network: Bitcoin,
            hash: Hash160::from(&"162c5ea71c0b23f5b9022ef047c4a86470a5b070".from_hex().unwrap()[..])
        };

        assert_eq!(addr.script_pubkey(), hex_script!("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087"));
        assert_eq!(&addr.to_base58check(), "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k");
        assert_eq!(FromBase58::from_base58check("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k"), Ok(addr));
    }

    #[test]
    fn test_p2sh_parse() {
        let script = hex_script!("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae");
        let addr = Address::from_script(Testnet, &script);

        assert_eq!(&addr.to_base58check(), "2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr");
        assert_eq!(FromBase58::from_base58check("2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr"), Ok(addr));
    }

    #[test]
    fn test_key_derivation() {
        // testnet compressed
        let sk: Privkey = FromBase58::from_base58check("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
        assert_eq!(sk.network(), Testnet);
        assert_eq!(sk.is_compressed(), true);
        assert_eq!(&sk.to_base58check(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");

        let secp = Secp256k1::new();
        let pk = sk.to_address(&secp).unwrap();
        assert_eq!(&pk.to_base58check(), "mqwpxxvfv3QbM8PU8uBx2jaNt9btQqvQNx");

        // mainnet uncompressed
        let sk: Privkey = FromBase58::from_base58check("5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3").unwrap();
        assert_eq!(sk.network(), Bitcoin);
        assert_eq!(sk.is_compressed(), false);
        assert_eq!(&sk.to_base58check(), "5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3");

        let secp = Secp256k1::new();
        let pk = sk.to_address(&secp).unwrap();
        assert_eq!(&pk.to_base58check(), "1GhQvF6dL8xa6wBxLnWmHcQsurx9RxiMc8");
    }
}

