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
//! Keys used in Bitcoin that can be roundtrip (de)serialized.
//!

use std::fmt::{self, Write};
use std::{io, ops, error};
use std::str::FromStr;

use secp256k1::{self, Secp256k1, schnorrsig};
use secp256k1::constants::{
    SCHNORRSIG_PUBLIC_KEY_SIZE,
    PUBLIC_KEY_SIZE as ECDSA_PUBLIC_KEY_SIZE,
    UNCOMPRESSED_PUBLIC_KEY_SIZE
};
use network::constants::Network;
use hashes::{Hash, hash160};
use hash_types::{PubkeyHash, WPubkeyHash};
use util::base58;

/// A key-related error.
#[derive(Debug)]
pub enum Error {
    /// Base58 encoding error
    Base58(base58::Error),
    /// secp256k1-related error
    Secp256k1(secp256k1::Error),
    /// invalid public key data length
    InvalidLength(usize)
}


impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Base58(ref e) => write!(f, "base58 error: {}", e),
            Error::Secp256k1(ref e) => write!(f, "secp256k1 error: {}", e),
            Error::InvalidLength(len) => write!(f, "invalid key data length: {}", len),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Base58(ref e) => Some(e),
            Error::Secp256k1(ref e) => Some(e),
            _ => None,
        }
    }
}

#[doc(hidden)]
impl From<base58::Error> for Error {
    fn from(e: base58::Error) -> Error {
        Error::Base58(e)
    }
}

#[doc(hidden)]
impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Secp256k1(e)
    }
}

/// Trait with common key functions which should be implemented bu different
/// types of private an public key structures
pub trait Key: Clone + Eq + Ord + fmt::Display + FromStr {
    /// Write the key into a writer
    fn write_into<W: io::Write>(&self, writer: W) -> Result<(), io::Error>;

    /// Reads the key from a reader
    ///
    /// This internally reads the first byte before reading the rest, so
    /// use of a `BufReader` is recommended.
    fn read_from<R: io::Read>(reader: R) -> Result<Self, io::Error> where Self: Sized;

    /// Serialize the key as a vec of bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Deserialize a public key from a slice
    fn from_slice(data: &[u8]) -> Result<Self, Error>;
}

impl Key for schnorrsig::PublicKey {
    fn write_into<W: io::Write>(&self, mut writer: W) -> Result<(), io::Error> {
        Ok(writer.write_all(&self.serialize())?)
    }

    fn read_from<R: io::Read>(mut reader: R) -> Result<Self, io::Error> where Self: Sized {
        let mut slice = [0u8; SCHNORRSIG_PUBLIC_KEY_SIZE];
        reader.read_exact(&mut slice)?;
        Self::from_slice(&slice).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }

    fn from_slice(data: &[u8]) -> Result<schnorrsig::PublicKey, Error> {
        Ok(schnorrsig::PublicKey::from_slice(data)?)
    }
}

/// Universal bitcoin public key type representing either ECDSA-compatible key
/// or Schnorr signature-compatible key.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PublicKey {
    /// ECDSA-compatible public key used in Bitcoin scripts and in P(W)PKH
    /// types of `scriptPubkey`
    Ecdsa(EcdsaPublicKey),

    /// Schnorr signature-compatible key that can be used in witness v1
    /// `scriptPubkey` and inside Tapscript
    Schnorr(schnorrsig::PublicKey),
}

impl From<EcdsaPublicKey> for PublicKey {
    fn from(key: EcdsaPublicKey) -> PublicKey {
        PublicKey::Ecdsa(key)
    }
}

impl From<schnorrsig::PublicKey> for PublicKey {
    fn from(key: schnorrsig::PublicKey) -> Self {
        PublicKey::Schnorr(key)
    }
}

impl PublicKey {
    /// Creates a new bitcoin public key from a Schnorr key pair
    #[inline]
    pub fn from_keypair<C: secp256k1::Signing>(secp: &Secp256k1<C>, keypair: &schnorrsig::KeyPair) -> PublicKey {
        PublicKey::Schnorr(schnorrsig::PublicKey::from_keypair(secp, keypair))
    }

    /// Returns `true` if an underlying public key is a Schnorr public key
    #[inline]
    pub fn is_schnorr(self) -> bool {
        match self {
            PublicKey::Ecdsa(_) => false,
            PublicKey::Schnorr(_) => true,
        }
    }

    /// Returns `true` if an underlying public key is a ECDSA public key
    #[inline]
    pub fn is_ecdsa(self) -> bool {
        match self {
            PublicKey::Ecdsa(_) => true,
            PublicKey::Schnorr(_) => false,
        }
    }


    /// Returns `true` if an underlying public key is a compressed ECDSA public key
    #[inline]
    pub fn is_ecdsa_comressed(self) -> bool {
        match self {
            PublicKey::Ecdsa(key) => key.compressed,
            PublicKey::Schnorr(_) => false,
        }
    }

    /// Unwraps underlying key data into an optional containing Schnorr public key, if any
    #[inline]
    pub fn schnorr_key(self) -> Option<schnorrsig::PublicKey> {
        match self {
            PublicKey::Ecdsa(_) => None,
            PublicKey::Schnorr(key) => Some(key),
        }
    }

    /// Unwraps underlying key data into an optional containing ECDSA public key, if any
    #[inline]
    pub fn ecdsa_key(self) -> Option<EcdsaPublicKey> {
        match self {
            PublicKey::Ecdsa(key) => Some(key),
            PublicKey::Schnorr(_) => None,
        }
    }

    /// Unwraps underlying key data into an optional containing ECDSA public key, if any
    #[inline]
    pub fn ecdsa_compressed_key(self) -> Option<EcdsaPublicKey> {
        match self {
            PublicKey::Ecdsa(key) => Some(key),
            PublicKey::Schnorr(_) => None,
        }
    }
}

impl Key for PublicKey {
    fn write_into<W: io::Write>(&self, mut writer: W) -> Result<(), io::Error> {
        match self {
            PublicKey::Ecdsa(key) => key.write_into(&mut writer),
            PublicKey::Schnorr(key) => key.write_into(&mut writer),
        }
    }

    /// If the key starts with `02`, `03` or `04` byte it makes the key ambigous, since it may
    /// represent both a valid Secp and Taproot-encoded key. Thus, in case both representations
    /// result in a valid keys the function will fail with [`std::io::ErrorKind::InvalidData`]
    /// error wrapped into a [`std::io::Error`].
    ///
    /// There is a BIP-340 PR and discussion on how this can be prevented in a more standard way:
    /// <https://github.com/bitcoin/bips/pull/1060>
    fn read_from<R: io::Read>(mut reader: R) -> Result<Self, io::Error> where Self: Sized {

        let mut bytes = [0; UNCOMPRESSED_PUBLIC_KEY_SIZE];

        reader.read_exact(&mut bytes[0..SCHNORRSIG_PUBLIC_KEY_SIZE])?;
        let maybe_schnorr_key = schnorrsig::PublicKey::from_slice(&bytes[0..SCHNORRSIG_PUBLIC_KEY_SIZE]);

        let len = { // Required by 1.29 borrow checker
            let (len, remaining_bytes) = if bytes[0] == 4 {
                (UNCOMPRESSED_PUBLIC_KEY_SIZE, &mut bytes[SCHNORRSIG_PUBLIC_KEY_SIZE..UNCOMPRESSED_PUBLIC_KEY_SIZE])
            } else if bytes[0] == 2 || bytes[0] == 3 {
                (ECDSA_PUBLIC_KEY_SIZE, &mut bytes[SCHNORRSIG_PUBLIC_KEY_SIZE..ECDSA_PUBLIC_KEY_SIZE])
            } else {
                (0, &mut bytes[0..0])
            };

            reader.read_exact(&mut remaining_bytes[..])?;
            len
        };

        let maybe_ecdsa_key = EcdsaPublicKey::from_slice(&bytes[..len]);

        match (maybe_schnorr_key, maybe_ecdsa_key) {
            (Ok(_), Ok(_)) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ambiguous key data which may represent both Taproot- and Secp-serialized public key. \
                Use concrete type for deserialization"
            )),
            (Err(_), Ok(key)) => Ok(PublicKey::Ecdsa(key)),
            (Ok(key), Err(_)) => Ok(PublicKey::Schnorr(key)),
            (Err(_), Err(e)) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        match self {
            PublicKey::Ecdsa(key) => key.to_bytes(),
            PublicKey::Schnorr(key) => key.to_bytes(),
        }
    }

    fn from_slice(data: &[u8]) -> Result<Self, Error> {
        Ok(match data.len() {
            ECDSA_PUBLIC_KEY_SIZE => PublicKey::Ecdsa(EcdsaPublicKey::with_compressed(secp256k1::PublicKey::from_slice(data)?)),
            UNCOMPRESSED_PUBLIC_KEY_SIZE => PublicKey::Ecdsa(EcdsaPublicKey {
                compressed: true,
                key: secp256k1::PublicKey::from_slice(data)?
            }),
            SCHNORRSIG_PUBLIC_KEY_SIZE => PublicKey::Schnorr(schnorrsig::PublicKey::from_slice(&data)?),
            len => return Err(Error::InvalidLength(len)),
        })
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublicKey::Ecdsa(key) => fmt::Display::fmt(key, f),
            PublicKey::Schnorr(key) => fmt::Display::fmt(key, f),
        }
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() == SCHNORRSIG_PUBLIC_KEY_SIZE * 2 {
            Ok(PublicKey::Schnorr(s.parse()?))
        } else {
            Ok(PublicKey::Ecdsa(s.parse()?))
        }
    }
}

/// A Bitcoin ECDSA public key
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EcdsaPublicKey {
    /// Whether this public key should be serialized as compressed
    pub compressed: bool,
    /// The actual ECDSA key
    pub key: secp256k1::PublicKey,
}

impl EcdsaPublicKey {
    /// Returns a compressed bitcoin representation of [`secp256k1::PublicKey`]
    #[inline]
    pub fn with_compressed(key: secp256k1::PublicKey) -> EcdsaPublicKey {
        EcdsaPublicKey {
            compressed: true,
            key
        }
    }

    /// Returns optional representation of the key filled with key data only if the key is compressed
    #[inline]
    pub fn compressed(self) -> Option<EcdsaPublicKey> {
        if self.compressed {
            Some(self)
        } else {
            None
        }
    }


    /// Returns optional representation of the key filled with key data only if the key is compressed
    #[inline]
    pub fn force_compressed(mut self) -> EcdsaPublicKey {
        self.compressed = true;
        self
    }

    /// Returns bitcoin 160-bit hash of the public key
    #[inline]
    pub fn pubkey_hash(&self) -> PubkeyHash {
        if self.compressed {
            PubkeyHash::hash(&self.key.serialize())
        } else {
            PubkeyHash::hash(&self.key.serialize_uncompressed())
        }
    }

    /// Returns bitcoin 160-bit hash of the public key for witness program
    #[inline]
    pub fn wpubkey_hash(&self) -> Option<WPubkeyHash> {
        if self.compressed {
            Some(WPubkeyHash::from_inner(
                hash160::Hash::hash(&self.key.serialize()).into_inner()
            ))
        } else {
            // We can't create witness pubkey hashes for an uncompressed
            // public keys
            None
        }
    }

    /// Computes the public key as supposed to be used with this secret
    #[inline]
    pub fn from_private_key<C: secp256k1::Signing>(secp: &Secp256k1<C>, sk: &PrivateKey) -> EcdsaPublicKey {
        sk.public_key(secp)
    }
}

impl Key for EcdsaPublicKey {
    /// Write the public key into a writer
    fn write_into<W: io::Write>(&self, mut writer: W) -> Result<(), io::Error> {
        if self.compressed {
            writer.write_all(&self.key.serialize())
        } else {
            writer.write_all(&self.key.serialize_uncompressed())
        }
    }

    /// Read the public key from a reader
    ///
    /// This internally reads the first byte before reading the rest, so
    /// use of a `BufReader` is recommended.
    fn read_from<R: io::Read>(mut reader: R) -> Result<Self, io::Error> where Self: Sized {
        let mut bytes = [0; UNCOMPRESSED_PUBLIC_KEY_SIZE];

        reader.read_exact(&mut bytes[0..1])?;
        let bytes = if bytes[0] < 4 {
            &mut bytes[..ECDSA_PUBLIC_KEY_SIZE]
        } else {
            &mut bytes[..UNCOMPRESSED_PUBLIC_KEY_SIZE]
        };

        reader.read_exact(&mut bytes[1..])?;
        Self::from_slice(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Serialize the public key to bytes
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf).expect("vecs don't error");
        buf
    }

    /// Deserialize a public key from a slice
    fn from_slice(data: &[u8]) -> Result<EcdsaPublicKey, Error> {
        let compressed: bool = match data.len() {
            ECDSA_PUBLIC_KEY_SIZE => true,
            UNCOMPRESSED_PUBLIC_KEY_SIZE => false,
            len =>  { return Err(Error::InvalidLength(len)); },
        };

        Ok(EcdsaPublicKey {
            compressed: compressed,
            key: secp256k1::PublicKey::from_slice(data)?,
        })
    }
}

impl fmt::Display for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.compressed {
            for ch in &self.key.serialize()[..] {
                write!(f, "{:02x}", ch)?;
            }
        } else {
            for ch in &self.key.serialize_uncompressed()[..] {
                write!(f, "{:02x}", ch)?;
            }
        }
        Ok(())
    }
}

impl FromStr for EcdsaPublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<EcdsaPublicKey, Error> {
        let key = secp256k1::PublicKey::from_str(s)?;
        Ok(EcdsaPublicKey {
            key: key,
            compressed: s.len() == 66
        })
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
/// A Bitcoin ECDSA private key
pub struct PrivateKey {
    /// Whether this private key should be serialized as compressed
    pub compressed: bool,
    /// The network on which this key should be used
    pub network: Network,
    /// The actual ECDSA key
    pub key: secp256k1::SecretKey,
}

impl PrivateKey {
    /// Creates a public key from this private key
    pub fn public_key<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> EcdsaPublicKey {
        EcdsaPublicKey {
            compressed: self.compressed,
            key: secp256k1::PublicKey::from_secret_key(secp, &self.key)
        }
    }

    /// Serialize the private key to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key[..].to_vec()
    }

    /// Format the private key to WIF format.
    pub fn fmt_wif(&self, fmt: &mut dyn fmt::Write) -> fmt::Result {
        let mut ret = [0; 34];
        ret[0] = match self.network {
            Network::Bitcoin => 128,
            Network::Testnet | Network::Signet | Network::Regtest => 239,
        };
        ret[1..33].copy_from_slice(&self.key[..]);
        let privkey = if self.compressed {
            ret[33] = 1;
            base58::check_encode_slice(&ret[..])
        } else {
            base58::check_encode_slice(&ret[..33])
        };
        fmt.write_str(&privkey)
    }

    /// Get WIF encoding of this private key.
    pub fn to_wif(&self) -> String {
        let mut buf = String::new();
        buf.write_fmt(format_args!("{}", self)).unwrap();
        buf.shrink_to_fit();
        buf
    }

    /// Parse WIF encoded private key.
    pub fn from_wif(wif: &str) -> Result<PrivateKey, Error> {
        let data = base58::from_check(wif)?;

        let compressed = match data.len() {
            33 => false,
            34 => true,
            _ => { return Err(Error::Base58(base58::Error::InvalidLength(data.len()))); }
        };

        let network = match data[0] {
            128 => Network::Bitcoin,
            239 => Network::Testnet,
            x   => { return Err(Error::Base58(base58::Error::InvalidVersion(vec![x]))); }
        };

        Ok(PrivateKey {
            compressed: compressed,
            network: network,
            key: secp256k1::SecretKey::from_slice(&data[1..33])?,
        })
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_wif(f)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[private key data]")
    }
}

impl FromStr for PrivateKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<PrivateKey, Error> {
        PrivateKey::from_wif(s)
    }
}

impl ops::Index<ops::RangeFull> for PrivateKey {
    type Output = [u8];
    fn index(&self, _: ops::RangeFull) -> &[u8] {
        &self.key[..]
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for PrivateKey {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for PrivateKey {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<PrivateKey, D::Error> {
        struct WifVisitor;

        impl<'de> ::serde::de::Visitor<'de> for WifVisitor {
            type Value = PrivateKey;

            fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                formatter.write_str("an ASCII WIF string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: ::serde::de::Error,
            {
                if let Ok(s) = ::std::str::from_utf8(v) {
                    PrivateKey::from_str(s).map_err(E::custom)
                } else {
                    Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: ::serde::de::Error,
            {
                PrivateKey::from_str(v).map_err(E::custom)
            }
        }

        d.deserialize_str(WifVisitor)
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for PublicKey {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            PublicKey::Ecdsa(key) => key.serialize(s),
            PublicKey::Schnorr(key) => ::serde::Serialize::serialize(key, s),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl<'de> ::serde::de::Visitor<'de> for HexVisitor {
                type Value = PublicKey;

                fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    formatter.write_str("an ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                    where
                        E: ::serde::de::Error,
                {
                    if let Ok(hex) = ::std::str::from_utf8(v) {
                        PublicKey::from_str(hex).map_err(E::custom)
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: ::serde::de::Error,
                {
                    PublicKey::from_str(v).map_err(E::custom)
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl<'de> ::serde::de::Visitor<'de> for BytesVisitor {
                type Value = PublicKey;

                fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                    where
                        E: ::serde::de::Error,
                {
                    PublicKey::from_slice(v).map_err(E::custom)
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for EcdsaPublicKey {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            if self.compressed {
                s.serialize_bytes(&self.key.serialize()[..])
            } else {
                s.serialize_bytes(&self.key.serialize_uncompressed()[..])
            }
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for EcdsaPublicKey {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<EcdsaPublicKey, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl<'de> ::serde::de::Visitor<'de> for HexVisitor {
                type Value = EcdsaPublicKey;

                fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    formatter.write_str("an ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    if let Ok(hex) = ::std::str::from_utf8(v) {
                        EcdsaPublicKey::from_str(hex).map_err(E::custom)
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    EcdsaPublicKey::from_str(v).map_err(E::custom)
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl<'de> ::serde::de::Visitor<'de> for BytesVisitor {
                type Value = EcdsaPublicKey;

                fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    EcdsaPublicKey::from_slice(v).map_err(E::custom)
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PrivateKey, EcdsaPublicKey, Key, PublicKey};
    use super::{UNCOMPRESSED_PUBLIC_KEY_SIZE, SCHNORRSIG_PUBLIC_KEY_SIZE, ECDSA_PUBLIC_KEY_SIZE};
    use secp256k1::Secp256k1;
    use std::io;
    use std::str::FromStr;
    use hashes::hex::ToHex;
    use network::constants::Network::Testnet;
    use network::constants::Network::Bitcoin;
    use util::address::Address;

    #[test]
    fn test_key_derivation() {
        // testnet compressed
        let sk = PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
        assert_eq!(sk.network, Testnet);
        assert_eq!(sk.compressed, true);
        assert_eq!(&sk.to_wif(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");

        let secp = Secp256k1::new();
        let pk = Address::p2pkh(&sk.public_key(&secp), sk.network);
        assert_eq!(&pk.to_string(), "mqwpxxvfv3QbM8PU8uBx2jaNt9btQqvQNx");

        // test string conversion
        assert_eq!(&sk.to_string(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");
        let sk_str =
            PrivateKey::from_str("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
        assert_eq!(&sk.to_wif(), &sk_str.to_wif());

        // mainnet uncompressed
        let sk = PrivateKey::from_wif("5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3").unwrap();
        assert_eq!(sk.network, Bitcoin);
        assert_eq!(sk.compressed, false);
        assert_eq!(&sk.to_wif(), "5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3");

        let secp = Secp256k1::new();
        let mut pk = sk.public_key(&secp);
        assert_eq!(pk.compressed, false);
        assert_eq!(&pk.to_string(), "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133");
        assert_eq!(pk, EcdsaPublicKey::from_str("042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133").unwrap());
        let addr = Address::p2pkh(&pk, sk.network);
        assert_eq!(&addr.to_string(), "1GhQvF6dL8xa6wBxLnWmHcQsurx9RxiMc8");
        pk.compressed = true;
        assert_eq!(&pk.to_string(), "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af");
        assert_eq!(pk, EcdsaPublicKey::from_str("032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af").unwrap());
    }

    #[test]
    fn test_pubkey_hash() {
        let pk = EcdsaPublicKey::from_str("032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af").unwrap();
        let upk = EcdsaPublicKey::from_str("042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133").unwrap();
        assert_eq!(pk.pubkey_hash().to_hex(), "9511aa27ef39bbfa4e4f3dd15f4d66ea57f475b4");
        assert_eq!(upk.pubkey_hash().to_hex(), "ac2e7daf42d2c97418fd9f78af2de552bb9c6a7a");
    }

    #[test]
    fn test_wpubkey_hash() {
        let pk = EcdsaPublicKey::from_str("032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af").unwrap();
        let upk = EcdsaPublicKey::from_str("042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133").unwrap();
        assert_eq!(pk.wpubkey_hash().unwrap().to_hex(), "9511aa27ef39bbfa4e4f3dd15f4d66ea57f475b4");
        assert_eq!(upk.wpubkey_hash(), None);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_key_serde() {
        use serde_test::{Configure, Token, assert_tokens};

        static KEY_WIF: &'static str = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";
        static PK_STR: &'static str = "039b6347398505f5ec93826dc61c19f47c66c0283ee9be980e29ce325a0f4679ef";
        static PK_STR_U: &'static str = "\
            04\
            9b6347398505f5ec93826dc61c19f47c66c0283ee9be980e29ce325a0f4679ef\
            87288ed73ce47fc4f5c79d19ebfa57da7cff3aff6e819e4ee971d86b5e61875d\
        ";
        static PK_STR_S: &'static str = "d69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9";
        static PK_BYTES: [u8; 33] = [
            0x03,
            0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec,
            0x93, 0x82, 0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c,
            0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0x0e,
            0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
        ];
        static PK_BYTES_S: [u8; 32] = [
            0xD6, 0x9C, 0x35, 0x09, 0xBB, 0x99, 0xE4, 0x12,
            0xE6, 0x8B, 0x0F, 0xE8, 0x54, 0x4E, 0x72, 0x83,
            0x7D, 0xFA, 0x30, 0x74, 0x6D, 0x8B, 0xE2, 0xAA,
            0x65, 0x97, 0x5F, 0x29, 0xD2, 0x2D, 0xC7, 0xB9
        ];
        static PK_BYTES_U: [u8; 65] = [
            0x04,
            0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec,
            0x93, 0x82, 0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c,
            0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0x0e,
            0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
            0x87, 0x28, 0x8e, 0xd7, 0x3c, 0xe4, 0x7f, 0xc4,
            0xf5, 0xc7, 0x9d, 0x19, 0xeb, 0xfa, 0x57, 0xda,
            0x7c, 0xff, 0x3a, 0xff, 0x6e, 0x81, 0x9e, 0x4e,
            0xe9, 0x71, 0xd8, 0x6b, 0x5e, 0x61, 0x87, 0x5d,
        ];

        let s = Secp256k1::new();
        let sk = PrivateKey::from_str(&KEY_WIF).unwrap();
        let pk = EcdsaPublicKey::from_private_key(&s, &sk);
        let pk_u = EcdsaPublicKey {
            key: pk.key,
            compressed: false,
        };
        let pk_s = PublicKey::from_slice(&PK_BYTES_S).unwrap();

        assert_tokens(&sk, &[Token::BorrowedStr(KEY_WIF)]);
        assert_tokens(&pk.compact(), &[Token::BorrowedBytes(&PK_BYTES[..])]);
        assert_tokens(&pk.readable(), &[Token::BorrowedStr(PK_STR)]);
        assert_tokens(&pk_u.compact(), &[Token::BorrowedBytes(&PK_BYTES_U[..])]);
        assert_tokens(&pk_u.readable(), &[Token::BorrowedStr(PK_STR_U)]);
        assert_tokens(&pk_s.compact(), &[Token::BorrowedBytes(&PK_BYTES_S[..])]);
        assert_tokens(&pk_s.readable(), &[Token::BorrowedStr(PK_STR_S)]);
    }

    fn ecdsa_random_key(mut seed: u8) -> EcdsaPublicKey {
        loop {
            let mut data = [0; UNCOMPRESSED_PUBLIC_KEY_SIZE];
            for byte in &mut data[..] {
                *byte = seed;
                // totally a rng
                seed = seed.wrapping_mul(41).wrapping_add(43);
            }
            if data[0] % 3 == 0 {
                data[0] = 4;
                if let Ok(key) = EcdsaPublicKey::from_slice(&data[..]) {
                    return key;
                }
            } else {
                data[0] = 2 + (data[0] >> 7);
                if let Ok(key) = EcdsaPublicKey::from_slice(&data[..ECDSA_PUBLIC_KEY_SIZE]) {
                    return key;
                }
            }
        }
    }

    fn schnorr_random_key(mut seed: u8) -> PublicKey {
        loop {
            let mut data = [0; SCHNORRSIG_PUBLIC_KEY_SIZE];
            for byte in &mut data[..] {
                *byte = seed;
                // totally a rng
                seed = seed.wrapping_mul(41).wrapping_add(43);
            }
            if [2, 3, 4].contains(&data[0]) {
                continue;
            }
            if let Ok(key) = PublicKey::from_slice(&data[..SCHNORRSIG_PUBLIC_KEY_SIZE]) {
                return key;
            }
        }
    }

    #[test]
    fn ecdsa_pubkey_read_write() {
        const N_KEYS: usize = 20;
        let ecdsa_keys: Vec<_> = (0..N_KEYS).map(|i| ecdsa_random_key(i as u8)).collect();

        let mut v = vec![];
        for k in &ecdsa_keys {
            k.write_into(&mut v).expect("writing into vec");
        }

        let mut dec_keys = vec![];
        let mut cursor = io::Cursor::new(&v);
        for _ in 0..N_KEYS {
            println!("{}", cursor.position());
            dec_keys.push(EcdsaPublicKey::read_from(&mut cursor).expect("reading from vec"));
        }

        assert_eq!(ecdsa_keys, dec_keys);

        // sanity checks
        assert!(PublicKey::read_from(&mut cursor).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[0; ECDSA_PUBLIC_KEY_SIZE][..])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[2; SCHNORRSIG_PUBLIC_KEY_SIZE][..])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[0; UNCOMPRESSED_PUBLIC_KEY_SIZE][..])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[4; UNCOMPRESSED_PUBLIC_KEY_SIZE - 1][..])).is_err());
    }


    #[test]
    fn schnorr_pubkey_read_write() {
        const N_KEYS: usize = 20;
        let schnorr_keys: Vec<_> = (0..N_KEYS).map(|i| schnorr_random_key(i as u8)).collect();

        let mut v = vec![];
        for k in &schnorr_keys {
            k.write_into(&mut v).expect("writing into vec");
        }

        let mut dec_keys = vec![];
        let mut cursor = io::Cursor::new(&v);
        for _ in 0..N_KEYS {
            println!("{}", cursor.position());
            dec_keys.push(PublicKey::read_from(&mut cursor).expect("reading from vec"));
        }

        assert_eq!(schnorr_keys, dec_keys);

        // sanity checks
        assert!(PublicKey::read_from(&mut cursor).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[0; ECDSA_PUBLIC_KEY_SIZE][..])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[2; SCHNORRSIG_PUBLIC_KEY_SIZE][..])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[0; UNCOMPRESSED_PUBLIC_KEY_SIZE][..])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[4; UNCOMPRESSED_PUBLIC_KEY_SIZE - 1][..])).is_err());
    }
}
