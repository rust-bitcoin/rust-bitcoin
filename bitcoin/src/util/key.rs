// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin keys.
//!
//! This module provides keys used in Bitcoin that can be roundtrip
//! (de)serialized.

use crate::prelude::*;

use core::{ops, str::FromStr};
use core::fmt::{self, Write};

pub use secp256k1::{self, Secp256k1, XOnlyPublicKey, KeyPair};

use crate::io;
use crate::network::constants::Network;
use crate::hashes::{Hash, hash160, hex, hex::FromHex};
use crate::hash_types::{PubkeyHash, WPubkeyHash};
use crate::util::base58;
use crate::internal_macros::write_err;

/// A key-related error.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Base58 encoding error
    Base58(base58::Error),
    /// secp256k1-related error
    Secp256k1(secp256k1::Error),
    /// Invalid key prefix error
    InvalidKeyPrefix(u8),
    /// Hex decoding error
    Hex(hex::Error)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Base58(ref e) => write_err!(f, "key base58 error"; e),
            Error::Secp256k1(ref e) => write_err!(f, "key secp256k1 error"; e),
            Error::InvalidKeyPrefix(ref b) => write!(f, "key prefix invalid: {}", b),
            Error::Hex(ref e) => write_err!(f, "key hex decoding error"; e)
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            Base58(e) => Some(e),
            Secp256k1(e) => Some(e),
            InvalidKeyPrefix(_) => None,
            Hex(e) => Some(e),
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

#[doc(hidden)]
impl From<hex::Error> for Error {
    fn from(e: hex::Error) -> Self {
        Error::Hex(e)
    }
}


/// A Bitcoin ECDSA public key
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey {
    /// Whether this public key should be serialized as compressed
    pub compressed: bool,
    /// The actual ECDSA key
    pub inner: secp256k1::PublicKey,
}

impl PublicKey {
    /// Constructs compressed ECDSA public key from the provided generic Secp256k1 public key
    pub fn new(key: secp256k1::PublicKey) -> PublicKey {
        PublicKey {
            compressed: true,
            inner: key,
        }
    }

    /// Constructs uncompressed (legacy) ECDSA public key from the provided generic Secp256k1
    /// public key
    pub fn new_uncompressed(key: secp256k1::PublicKey) -> PublicKey {
        PublicKey {
            compressed: false,
            inner: key,
        }
    }

    /// Returns bitcoin 160-bit hash of the public key
    pub fn pubkey_hash(&self) -> PubkeyHash {
        if self.compressed {
            PubkeyHash::hash(&self.inner.serialize())
        } else {
            PubkeyHash::hash(&self.inner.serialize_uncompressed())
        }
    }

    /// Returns bitcoin 160-bit hash of the public key for witness program
    pub fn wpubkey_hash(&self) -> Option<WPubkeyHash> {
        if self.compressed {
            Some(WPubkeyHash::from_inner(
                hash160::Hash::hash(&self.inner.serialize()).into_inner()
            ))
        } else {
            // We can't create witness pubkey hashes for an uncompressed
            // public keys
            None
        }
    }

    /// Write the public key into a writer
    pub fn write_into<W: io::Write>(&self, mut writer: W) -> Result<(), io::Error> {
        if self.compressed {
            writer.write_all(&self.inner.serialize())
        } else {
            writer.write_all(&self.inner.serialize_uncompressed())
        }
    }

    /// Read the public key from a reader
    ///
    /// This internally reads the first byte before reading the rest, so
    /// use of a `BufReader` is recommended.
    pub fn read_from<R: io::Read>(mut reader: R) -> Result<Self, io::Error> {
        let mut bytes = [0; 65];

        reader.read_exact(&mut bytes[0..1])?;
        let bytes = if bytes[0] < 4 { &mut bytes[..33] } else { &mut bytes[..65] };

        reader.read_exact(&mut bytes[1..])?;
        Self::from_slice(bytes).map_err(|e| {
            // Need a static string for core2
            #[cfg(feature = "std")]
            let reason = e;
            #[cfg(not(feature = "std"))]
            let reason = match e {
                Error::Base58(_) => "base58 error",
                Error::Secp256k1(_) => "secp256k1 error",
                Error::InvalidKeyPrefix(_) => "invalid key prefix",
                Error::Hex(_) => "hex decoding error"
            };
            io::Error::new(io::ErrorKind::InvalidData, reason)
        })
    }

    /// Serialize the public key to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf).expect("vecs don't error");
        buf
    }

    /// Serialize the public key into a `SortKey`.
    ///
    /// `SortKey` is not too useful by itself, but it can be used to sort a
    /// `[PublicKey]` slice using `sort_unstable_by_key`, `sort_by_cached_key`,
    /// `sort_by_key`, or any of the other `*_by_key` methods on slice.
    /// Pass the method into the sort method directly. (ie. `PublicKey::to_sort_key`)
    ///
    /// This method of sorting is in line with Bitcoin Core's implementation of
    /// sorting keys for output descriptors such as `sortedmulti()`.
    ///
    /// If every `PublicKey` in the slice is `compressed == true` then this will sort
    /// the keys in a
    /// [BIP67](https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki)
    /// compliant way.
    ///
    /// # Example: Using with `sort_unstable_by_key`
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use bitcoin::PublicKey;
    ///
    /// let pk = |s| PublicKey::from_str(s).unwrap();
    ///
    /// let mut unsorted = [
    ///     pk("04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc38e98ac269ffe028345c31ac8d0a365f29c8f7e7cfccac72f84e1acd02bc554f35"),
    ///     pk("038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354"),
    ///     pk("028bde91b10013e08949a318018fedbd896534a549a278e220169ee2a36517c7aa"),
    ///     pk("04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc3816753d96001fd7cba3ce5372f5c9a0d63708183033538d07b1e532fc43aaacfa"),
    ///     pk("032b8324c93575034047a52e9bca05a46d8347046b91a032eff07d5de8d3f2730b"),
    ///     pk("045d753414fa292ea5b8f56e39cfb6a0287b2546231a5cb05c4b14ab4b463d171f5128148985b23eccb1e2905374873b1f09b9487f47afa6b1f2b0083ac8b4f7e8"),
    ///     pk("0234dd69c56c36a41230d573d68adeae0030c9bc0bf26f24d3e1b64c604d293c68"),
    /// ];
    /// let sorted = [
    ///     // These first 4 keys are in a BIP67 compatible sorted order
    ///     // (since they are compressed)
    ///     pk("0234dd69c56c36a41230d573d68adeae0030c9bc0bf26f24d3e1b64c604d293c68"),
    ///     pk("028bde91b10013e08949a318018fedbd896534a549a278e220169ee2a36517c7aa"),
    ///     pk("032b8324c93575034047a52e9bca05a46d8347046b91a032eff07d5de8d3f2730b"),
    ///     pk("038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354"),
    ///     // Uncompressed keys are not BIP67 compliant, but are sorted
    ///     // after compressed keys in Bitcoin Core using `sortedmulti()`
    ///     pk("045d753414fa292ea5b8f56e39cfb6a0287b2546231a5cb05c4b14ab4b463d171f5128148985b23eccb1e2905374873b1f09b9487f47afa6b1f2b0083ac8b4f7e8"),
    ///     pk("04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc3816753d96001fd7cba3ce5372f5c9a0d63708183033538d07b1e532fc43aaacfa"),
    ///     pk("04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc38e98ac269ffe028345c31ac8d0a365f29c8f7e7cfccac72f84e1acd02bc554f35"),
    /// ];
    ///
    /// unsorted.sort_unstable_by_key(PublicKey::to_sort_key);
    ///
    /// assert_eq!(unsorted, sorted);
    /// ```
    pub fn to_sort_key(&self) -> SortKey {
        if self.compressed {
            let bytes = self.inner.serialize();
            let mut res = [0; 32];
            res[..].copy_from_slice(&bytes[1..33]);
            SortKey(bytes[0], res, [0; 32])
        } else {
            let bytes = self.inner.serialize_uncompressed();
            let mut res_left = [0; 32];
            let mut res_right = [0; 32];
            res_left[..].copy_from_slice(&bytes[1..33]);
            res_right[..].copy_from_slice(&bytes[33..65]);
            SortKey(bytes[0], res_left, res_right)
        }
    }

    /// Deserialize a public key from a slice
    pub fn from_slice(data: &[u8]) -> Result<PublicKey, Error> {
        let compressed = match data.len() {
            33 => true,
            65 => false,
            len =>  {
                return Err(base58::Error::InvalidLength(len).into());
            },
        };

        if !compressed && data[0] != 0x04 {
            return Err(Error::InvalidKeyPrefix(data[0]))
        }

        Ok(PublicKey {
            compressed,
            inner: secp256k1::PublicKey::from_slice(data)?,
        })
    }

    /// Computes the public key as supposed to be used with this secret
    pub fn from_private_key<C: secp256k1::Signing>(secp: &Secp256k1<C>, sk: &PrivateKey) -> PublicKey {
        sk.public_key(secp)
    }
}

/// An opaque return type for PublicKey::to_sort_key
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct SortKey(u8, [u8; 32], [u8; 32]);

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.compressed {
            for ch in &self.inner.serialize()[..] {
                write!(f, "{:02x}", ch)?;
            }
        } else {
            for ch in &self.inner.serialize_uncompressed()[..] {
                write!(f, "{:02x}", ch)?;
            }
        }
        Ok(())
    }
}

impl FromStr for PublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<PublicKey, Error> {
        match s.len() {
            66 => PublicKey::from_slice(&<[u8; 33]>::from_hex(s)?),
            130 => PublicKey::from_slice(&<[u8; 65]>::from_hex(s)?),
            len => Err(Error::Hex(hex::Error::InvalidLength(66, len))),
        }
    }
}

/// A Bitcoin ECDSA private key
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct PrivateKey {
    /// Whether this private key should be serialized as compressed
    pub compressed: bool,
    /// The network on which this key should be used
    pub network: Network,
    /// The actual ECDSA key
    pub inner: secp256k1::SecretKey,
}

impl PrivateKey {
    /// Constructs compressed ECDSA private key from the provided generic Secp256k1 private key
    /// and the specified network
    pub fn new(key: secp256k1::SecretKey, network: Network) -> PrivateKey {
        PrivateKey {
            compressed: true,
            network,
            inner: key,
        }
    }

    /// Constructs uncompressed (legacy) ECDSA private key from the provided generic Secp256k1
    /// private key and the specified network
    pub fn new_uncompressed(key: secp256k1::SecretKey, network: Network) -> PrivateKey {
        PrivateKey {
            compressed: false,
            network,
            inner: key,
        }
    }

    /// Creates a public key from this private key
    pub fn public_key<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> PublicKey {
        PublicKey {
            compressed: self.compressed,
            inner: secp256k1::PublicKey::from_secret_key(secp, &self.inner)
        }
    }

    /// Serialize the private key to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner[..].to_vec()
    }

    /// Deserialize a private key from a slice
    pub fn from_slice(data: &[u8], network: Network) -> Result<PrivateKey, Error> {
        Ok(PrivateKey::new(secp256k1::SecretKey::from_slice(data)?, network))
    }

    /// Format the private key to WIF format.
    pub fn fmt_wif(&self, fmt: &mut dyn fmt::Write) -> fmt::Result {
        let mut ret = [0; 34];
        ret[0] = match self.network {
            Network::Bitcoin => 128,
            Network::Testnet | Network::Signet | Network::Regtest => 239,
        };
        ret[1..33].copy_from_slice(&self.inner[..]);
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
            _ => {
                return Err(Error::Base58(base58::Error::InvalidLength(data.len())));
            }
        };

        let network = match data[0] {
            128 => Network::Bitcoin,
            239 => Network::Testnet,
            x   => {
                return Err(Error::Base58(base58::Error::InvalidAddressVersion(x)));
            }
        };

        Ok(PrivateKey {
            compressed,
            network,
            inner: secp256k1::SecretKey::from_slice(&data[1..33])?,
        })
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_wif(f)
    }
}

#[cfg(not(feature = "std"))]
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
        &self.inner[..]
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl serde::Serialize for PrivateKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> serde::Deserialize<'de> for PrivateKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<PrivateKey, D::Error> {
        struct WifVisitor;

        impl<'de> serde::de::Visitor<'de> for WifVisitor {
            type Value = PrivateKey;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("an ASCII WIF string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if let Ok(s) = core::str::from_utf8(v) {
                    PrivateKey::from_str(s).map_err(E::custom)
                } else {
                    Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                PrivateKey::from_str(v).map_err(E::custom)
            }
        }

        d.deserialize_str(WifVisitor)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[allow(clippy::collapsible_else_if)] // Aids readability.
impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            if self.compressed {
                s.serialize_bytes(&self.inner.serialize()[..])
            } else {
                s.serialize_bytes(&self.inner.serialize_uncompressed()[..])
            }
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl<'de> serde::de::Visitor<'de> for HexVisitor {
                type Value = PublicKey;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("an ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    if let Ok(hex) = core::str::from_utf8(v) {
                        PublicKey::from_str(hex).map_err(E::custom)
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    PublicKey::from_str(v).map_err(E::custom)
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl<'de> serde::de::Visitor<'de> for BytesVisitor {
                type Value = PublicKey;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    PublicKey::from_slice(v).map_err(E::custom)
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::io;
    use super::{PrivateKey, PublicKey, SortKey};
    use secp256k1::Secp256k1;
    use std::str::FromStr;
    use crate::hashes::hex::{FromHex, ToHex};
    use crate::network::constants::Network::Testnet;
    use crate::network::constants::Network::Bitcoin;
    use crate::util::address::Address;

    #[test]
    fn test_key_derivation() {
        // testnet compressed
        let sk = PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
        assert_eq!(sk.network, Testnet);
        assert!(sk.compressed);
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
        assert!(!sk.compressed);
        assert_eq!(&sk.to_wif(), "5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3");

        let secp = Secp256k1::new();
        let mut pk = sk.public_key(&secp);
        assert!(!pk.compressed);
        assert_eq!(&pk.to_string(), "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133");
        assert_eq!(pk, PublicKey::from_str("042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133").unwrap());
        let addr = Address::p2pkh(&pk, sk.network);
        assert_eq!(&addr.to_string(), "1GhQvF6dL8xa6wBxLnWmHcQsurx9RxiMc8");
        pk.compressed = true;
        assert_eq!(&pk.to_string(), "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af");
        assert_eq!(pk, PublicKey::from_str("032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af").unwrap());
    }

    #[test]
    fn test_pubkey_hash() {
        let pk = PublicKey::from_str("032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af").unwrap();
        let upk = PublicKey::from_str("042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133").unwrap();
        assert_eq!(pk.pubkey_hash().to_hex(), "9511aa27ef39bbfa4e4f3dd15f4d66ea57f475b4");
        assert_eq!(upk.pubkey_hash().to_hex(), "ac2e7daf42d2c97418fd9f78af2de552bb9c6a7a");
    }

    #[test]
    fn test_wpubkey_hash() {
        let pk = PublicKey::from_str("032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af").unwrap();
        let upk = PublicKey::from_str("042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133").unwrap();
        assert_eq!(pk.wpubkey_hash().unwrap().to_hex(), "9511aa27ef39bbfa4e4f3dd15f4d66ea57f475b4");
        assert_eq!(upk.wpubkey_hash(), None);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_key_serde() {
        use serde_test::{Configure, Token, assert_tokens};

        static KEY_WIF: &str = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";
        static PK_STR: &str = "039b6347398505f5ec93826dc61c19f47c66c0283ee9be980e29ce325a0f4679ef";
        static PK_STR_U: &str = "\
            04\
            9b6347398505f5ec93826dc61c19f47c66c0283ee9be980e29ce325a0f4679ef\
            87288ed73ce47fc4f5c79d19ebfa57da7cff3aff6e819e4ee971d86b5e61875d\
        ";
        static PK_BYTES: [u8; 33] = [
            0x03,
            0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec,
            0x93, 0x82, 0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c,
            0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0x0e,
            0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
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
        let sk = PrivateKey::from_str(KEY_WIF).unwrap();
        let pk = PublicKey::from_private_key(&s, &sk);
        let pk_u = PublicKey {
            inner: pk.inner,
            compressed: false,
        };

        assert_tokens(&sk, &[Token::BorrowedStr(KEY_WIF)]);
        assert_tokens(&pk.compact(), &[Token::BorrowedBytes(&PK_BYTES[..])]);
        assert_tokens(&pk.readable(), &[Token::BorrowedStr(PK_STR)]);
        assert_tokens(&pk_u.compact(), &[Token::BorrowedBytes(&PK_BYTES_U[..])]);
        assert_tokens(&pk_u.readable(), &[Token::BorrowedStr(PK_STR_U)]);
    }

    fn random_key(mut seed: u8) -> PublicKey {
        loop {
            let mut data = [0; 65];
            for byte in &mut data[..] {
                *byte = seed;
                // totally a rng
                seed = seed.wrapping_mul(41).wrapping_add(43);
            }
            if data[0] % 2 == 0 {
                data[0] = 4;
                if let Ok(key) = PublicKey::from_slice(&data[..]) {
                    return key;
                }
            } else {
                data[0] = 2 + (data[0] >> 7);
                if let Ok(key) = PublicKey::from_slice(&data[..33]) {
                    return key;
                }
            }
        }
    }

    #[test]
    fn pubkey_read_write() {
        const N_KEYS: usize = 20;
        let keys: Vec<_> = (0..N_KEYS).map(|i| random_key(i as u8)).collect();

        let mut v = vec![];
        for k in &keys {
            k.write_into(&mut v).expect("writing into vec");
        }

        let mut dec_keys = vec![];
        let mut cursor = io::Cursor::new(&v);
        for _ in 0..N_KEYS {
            dec_keys.push(PublicKey::read_from(&mut cursor).expect("reading from vec"));
        }

        assert_eq!(keys, dec_keys);

        // sanity checks
        assert!(PublicKey::read_from(&mut cursor).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[0; 33][..])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[2; 32][..])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[0; 65][..])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[4; 64][..])).is_err());
    }

    #[test]
    fn pubkey_to_sort_key() {
        let key1 = PublicKey::from_str("02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8").unwrap();
        let key2 = PublicKey {
            inner: key1.inner,
            compressed: false,
        };
        let expected1 = SortKey(
            2,
            <[u8; 32]>::from_hex(
                "ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
            ).unwrap(),
            [0_u8; 32],
        );
        let expected2 = SortKey(
            4,
            <[u8; 32]>::from_hex(
                "ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
            ).unwrap(),
            <[u8; 32]>::from_hex(
                "1794e7f3d5e420641a3bc690067df5541470c966cbca8c694bf39aa16d836918",
            ).unwrap(),
        );
        assert_eq!(key1.to_sort_key(), expected1);
        assert_eq!(key2.to_sort_key(), expected2);
    }

    #[test]
    fn pubkey_sort() {
        struct Vector {
            input: Vec<PublicKey>,
            expect: Vec<PublicKey>,
        }
        let fmt = |v: Vec<_>| v.into_iter()
            .map(|s| PublicKey::from_str(s).unwrap())
            .collect::<Vec<_>>();
        let vectors = vec![
            // Start BIP67 vectors
            // Vector 1
            Vector {
                input: fmt(vec![
                    "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
                    "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f",
                ]),
                expect: fmt(vec![
                    "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f",
                    "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
                ]),
            },
            // Vector 2 (Already sorted, no action required)
            Vector {
                input: fmt(vec![
                    "02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0",
                    "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77",
                    "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404",
                ]),
                expect: fmt(vec![
                    "02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0",
                    "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77",
                    "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404",
                ]),
            },
            // Vector 3
            Vector {
                input: fmt(vec![
                    "030000000000000000000000000000000000004141414141414141414141414141",
                    "020000000000000000000000000000000000004141414141414141414141414141",
                    "020000000000000000000000000000000000004141414141414141414141414140",
                    "030000000000000000000000000000000000004141414141414141414141414140",
                ]),
                expect: fmt(vec![
                    "020000000000000000000000000000000000004141414141414141414141414140",
                    "020000000000000000000000000000000000004141414141414141414141414141",
                    "030000000000000000000000000000000000004141414141414141414141414140",
                    "030000000000000000000000000000000000004141414141414141414141414141",
                ]),
            },
            // Vector 4: (from bitcore)
            Vector {
                input: fmt(vec![
                    "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
                    "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9",
                    "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18",
                ]),
                expect: fmt(vec![
                    "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18",
                    "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
                    "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9",
                ]),
            },
            // Non-BIP67 vectors
            Vector {
                input: fmt(vec![
                    "02c690d642c1310f3a1ababad94e3930e4023c930ea472e7f37f660fe485263b88",
                    "0234dd69c56c36a41230d573d68adeae0030c9bc0bf26f24d3e1b64c604d293c68",
                    "041a181bd0e79974bd7ca552e09fc42ba9c3d5dbb3753741d6f0ab3015dbfd9a22d6b001a32f5f51ac6f2c0f35e73a6a62f59e848fa854d3d21f3f231594eeaa46",
                    "032b8324c93575034047a52e9bca05a46d8347046b91a032eff07d5de8d3f2730b",
                    "04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc3816753d96001fd7cba3ce5372f5c9a0d63708183033538d07b1e532fc43aaacfa",
                    "028e1c947c8c0b8ed021088b8e981491ac7af2b8fabebea1abdb448424c8ed75b7",
                    "045d753414fa292ea5b8f56e39cfb6a0287b2546231a5cb05c4b14ab4b463d171f5128148985b23eccb1e2905374873b1f09b9487f47afa6b1f2b0083ac8b4f7e8",
                    "03004a8a3d242d7957c0b60fb7208d386fa6a0193aabd1f3f095ffd0ac097e447b",
                    "04eb0db2d71ccbb0edd8fb35092cbcae2f7fa1f06d4c170804bf52007924b569a8d2d6f6bc8fd2b3caa3253fa1bb674443743bf7fb9f94f9c0b0831a252894cfa8",
                    "04516cde23e14f2319423b7a4a7ae48b1dadceb5e9c123198d417d10895684c42eb05e210f90ccbc72448803a22312e3f122ff2939956ccef4f7316f836295ddd5",
                    "038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354",
                    "04c6bec3b07586a4b085a78cbb97e9bab6f1d3c9ebf299b65dec85213c5eacd44487de86017183120bb7ea3b6c6660c5037615fe1add2a73f800cbeeae22c60438",
                    "03e1a1cfa9eaff604ae237b7af31ffe4c01be22eb96f3da0e62c5850dd4b4386c1",
                    "028d3a2d9f1b1c5c75845944f93bc183ba23aecde53f1978b8aa1b77661be6114f",
                    "028bde91b10013e08949a318018fedbd896534a549a278e220169ee2a36517c7aa",
                    "04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc38e98ac269ffe028345c31ac8d0a365f29c8f7e7cfccac72f84e1acd02bc554f35",
                ]),
                expect: fmt(vec![
                    "0234dd69c56c36a41230d573d68adeae0030c9bc0bf26f24d3e1b64c604d293c68",
                    "028bde91b10013e08949a318018fedbd896534a549a278e220169ee2a36517c7aa",
                    "028d3a2d9f1b1c5c75845944f93bc183ba23aecde53f1978b8aa1b77661be6114f",
                    "028e1c947c8c0b8ed021088b8e981491ac7af2b8fabebea1abdb448424c8ed75b7",
                    "02c690d642c1310f3a1ababad94e3930e4023c930ea472e7f37f660fe485263b88",
                    "03004a8a3d242d7957c0b60fb7208d386fa6a0193aabd1f3f095ffd0ac097e447b",
                    "032b8324c93575034047a52e9bca05a46d8347046b91a032eff07d5de8d3f2730b",
                    "038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354",
                    "03e1a1cfa9eaff604ae237b7af31ffe4c01be22eb96f3da0e62c5850dd4b4386c1",
                    "041a181bd0e79974bd7ca552e09fc42ba9c3d5dbb3753741d6f0ab3015dbfd9a22d6b001a32f5f51ac6f2c0f35e73a6a62f59e848fa854d3d21f3f231594eeaa46",
                    "04516cde23e14f2319423b7a4a7ae48b1dadceb5e9c123198d417d10895684c42eb05e210f90ccbc72448803a22312e3f122ff2939956ccef4f7316f836295ddd5",
                    "045d753414fa292ea5b8f56e39cfb6a0287b2546231a5cb05c4b14ab4b463d171f5128148985b23eccb1e2905374873b1f09b9487f47afa6b1f2b0083ac8b4f7e8",
                    // These two pubkeys are mirrored. This helps verify the sort past the x value.
                    "04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc3816753d96001fd7cba3ce5372f5c9a0d63708183033538d07b1e532fc43aaacfa",
                    "04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc38e98ac269ffe028345c31ac8d0a365f29c8f7e7cfccac72f84e1acd02bc554f35",
                    "04c6bec3b07586a4b085a78cbb97e9bab6f1d3c9ebf299b65dec85213c5eacd44487de86017183120bb7ea3b6c6660c5037615fe1add2a73f800cbeeae22c60438",
                    "04eb0db2d71ccbb0edd8fb35092cbcae2f7fa1f06d4c170804bf52007924b569a8d2d6f6bc8fd2b3caa3253fa1bb674443743bf7fb9f94f9c0b0831a252894cfa8",
                ]),
            },
        ];
        for mut vector in vectors {
            vector.input.sort_by_cached_key(PublicKey::to_sort_key);
            assert_eq!(vector.input, vector.expect);
        }
    }
}
