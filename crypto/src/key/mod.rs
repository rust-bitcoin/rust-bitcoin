// SPDX-License-Identifier: CC0-1.0

//! Bitcoin keys.
//!
//! This module provides keys used in Bitcoin that can be roundtrip
//! (de)serialized.

pub mod bare;

//use core::fmt::{self, Write as _};
#[cfg(feature = "hex")]
#[cfg(feature = "basic-key-ops")]
use core::str::FromStr;
use core::fmt;

#[cfg(feature = "hashes")]
use hashes::hash160;
#[cfg(feature = "hex")]
use hex::{DisplayHex, FromHex, HexToArrayError};
use internals::array_vec::ArrayVec;
use internals::write_err;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "rand-std")]
pub use secp256k1::rand;

/// Parity of a SECP256K1 public key Y coordinate.
///
/// For each valid value of the X coordinate there are two possible points with different parity.
/// Distinguishing them is sometimes needed so we have this enum to represent the possible values.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Parity {
    /// Even parity.
    ///
    /// The least significant bit of the Y coordinate is 0.
    Even = 0,

    /// Odd parity.
    ///
    /// The least significant bit of the Y coordinate is 1.
    Odd = 1,
}

impl Parity {
    /// Converts the parity to its corresponding bit.
    ///
    /// Returns 0 for even parity and 1 for odd parity.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

pub use bare::XOnlyPublicKey;

/// A Bitcoin ECDSA public key.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey {
    /// Whether this public key should be serialized as compressed.
    pub compressed: bool,
    /// The actual ECDSA key.
    pub inner: bare::PublicKey,
}

impl PublicKey {
    /// Constructs compressed ECDSA public key from the provided generic Secp256k1 public key.
    pub fn new(key: impl Into<bare::PublicKey>) -> PublicKey {
        PublicKey { compressed: true, inner: key.into() }
    }

    /// Constructs uncompressed (legacy) ECDSA public key from the provided generic Secp256k1
    /// public key.
    pub fn new_uncompressed(key: impl Into<bare::PublicKey>) -> PublicKey {
        PublicKey { compressed: false, inner: key.into() }
    }
}

#[cfg(feature = "basic-key-ops")]
impl PublicKey {
    fn with_serialized<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        if self.compressed {
            f(&self.inner.serialize())
        } else {
            f(&self.inner.serialize_uncompressed())
        }
    }

    /// Serializes the public key.
    pub fn serialize(&self) -> SerializedPublicKey {
        self.with_serialized(|bytes| {
            let mut buf = ArrayVec::new();
            buf.extend_from_slice(bytes);
            SerializedPublicKey(buf)
        })
    }

    /// Returns bitcoin 160-bit hash of the public key.
    #[cfg(feature = "hashes")]
    pub fn pubkey_hash(&self) -> PubkeyHash {
        PubkeyHash(self.with_serialized(hash160::Hash::hash))
    }

    /// Returns bitcoin 160-bit hash of the public key for witness program
    #[cfg(feature = "hashes")]
    pub fn wpubkey_hash(&self) -> Result<WPubkeyHash, UncompressedPublicKeyError> {
        if self.compressed {
            Ok(WPubkeyHash::from_byte_array(
                hash160::Hash::hash(&self.inner.serialize()).to_byte_array(),
            ))
        } else {
            Err(UncompressedPublicKeyError)
        }
    }

    /// Serializes the public key to bytes.
    #[cfg(feature = "alloc")]
    pub fn to_bytes(self) -> Vec<u8> {
        self.with_serialized(|bytes| bytes.to_vec())
    }

    /// Serializes the public key into a `SortKey`.
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
    /// unsorted.sort_unstable_by_key(|k| PublicKey::to_sort_key(*k));
    ///
    /// assert_eq!(unsorted, sorted);
    /// ```
    pub fn to_sort_key(self) -> SortKey {
        if self.compressed {
            let buf = ArrayVec::from_slice(&self.inner.serialize());
            SortKey(buf)
        } else {
            let buf = ArrayVec::from_slice(&self.inner.serialize_uncompressed());
            SortKey(buf)
        }
    }

    /// Deserializes a public key from a slice.
    pub fn from_slice(data: &[u8]) -> Result<PublicKey, FromSliceError> {
        let compressed = match data.len() {
            33 => true,
            65 => false,
            len => {
                return Err(FromSliceError::InvalidLength(len));
            }
        };

        if !compressed && data[0] != 0x04 {
            return Err(FromSliceError::InvalidKeyPrefix(data[0]));
        }

        Ok(PublicKey { compressed, inner: bare::PublicKey::deserialize(data)? })
    }
}

impl From<bare::PublicKey> for PublicKey {
    fn from(pk: bare::PublicKey) -> PublicKey { PublicKey::new(pk) }
}

#[cfg(feature = "basic-key-ops")]
impl From<PublicKey> for XOnlyPublicKey {
    fn from(pk: PublicKey) -> XOnlyPublicKey { pk.inner.into() }
}

/// An opaque return type for PublicKey::to_sort_key.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct SortKey(ArrayVec<u8, 65>);

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hex")]
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.with_serialized(|bytes| fmt::Display::fmt(&bytes.as_hex(), f))
    }
}

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hex")]
impl FromStr for PublicKey {
    type Err = ParsePublicKeyError;
    fn from_str(s: &str) -> Result<PublicKey, ParsePublicKeyError> {
        use HexToArrayError::*;

        match s.len() {
            66 => {
                let bytes = <[u8; 33]>::from_hex(s).map_err(|e| match e {
                    InvalidChar(e) => ParsePublicKeyError::InvalidChar(e.invalid_char()),
                    InvalidLength(_) => unreachable!("length checked already"),
                })?;
                Ok(PublicKey::from_slice(&bytes)?)
            }
            130 => {
                let bytes = <[u8; 65]>::from_hex(s).map_err(|e| match e {
                    InvalidChar(e) => ParsePublicKeyError::InvalidChar(e.invalid_char()),
                    InvalidLength(_) => unreachable!("length checked already"),
                })?;
                Ok(PublicKey::from_slice(&bytes)?)
            }
            len => Err(ParsePublicKeyError::InvalidHexLength(len)),
        }
    }
}

#[cfg(feature = "hashes")]
hashes::hash_newtype! {
    /// A hash of a public key.
    pub struct PubkeyHash(hash160::Hash);
    /// SegWit version of a public key hash.
    pub struct WPubkeyHash(hash160::Hash);
}

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hashes")]
impl From<PublicKey> for PubkeyHash {
    fn from(key: PublicKey) -> PubkeyHash { key.pubkey_hash() }
}

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hashes")]
impl From<&PublicKey> for PubkeyHash {
    fn from(key: &PublicKey) -> PubkeyHash { key.pubkey_hash() }
}

/// An always-compressed Bitcoin ECDSA public key.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompressedPublicKey(pub bare::PublicKey);

#[cfg(feature = "basic-key-ops")]
impl CompressedPublicKey {
    /// Serializes the public key to a byte array.
    pub fn serialize(&self) -> [u8; 33] {
        self.0.serialize()
    }

    /// Returns bitcoin 160-bit hash of the public key.
    #[cfg(feature = "hashes")]
    pub fn pubkey_hash(&self) -> PubkeyHash { PubkeyHash(hash160::Hash::hash(&self.to_bytes())) }

    /// Returns bitcoin 160-bit hash of the public key for witness program.
    #[cfg(feature = "hashes")]
    pub fn wpubkey_hash(&self) -> WPubkeyHash {
        WPubkeyHash::from_byte_array(hash160::Hash::hash(&self.to_bytes()).to_byte_array())
    }

    /// Serializes the public key.
    ///
    /// As the type name suggests, the key is serialzied in compressed format.
    ///
    /// Note that this can be used as a sort key to get BIP67-compliant sorting.
    /// That's why this type doesn't have the `to_sort_key` method - it would duplicate this one.
    pub fn to_bytes(&self) -> [u8; 33] { self.0.serialize() }

    /// Deserializes a public key from a slice.
    #[cfg(feature = "basic-key-ops")]
    pub fn from_slice(data: &[u8]) -> Result<Self, bare::PublicKeyDeserError> {
        bare::PublicKey::deserialize(data).map(CompressedPublicKey)
    }
}

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hex")]
impl fmt::Display for CompressedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.to_bytes().as_hex(), f)
    }
}

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hex")]
impl FromStr for CompressedPublicKey {
    type Err = ParseCompressedPublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CompressedPublicKey::from_slice(&<[u8; 33]>::from_hex(s)?).map_err(Into::into)
    }
}

#[cfg(feature = "basic-key-ops")]
impl TryFrom<PublicKey> for CompressedPublicKey {
    type Error = UncompressedPublicKeyError;

    fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
        if value.compressed {
            Ok(CompressedPublicKey(value.inner))
        } else {
            Err(UncompressedPublicKeyError)
        }
    }
}

#[cfg(feature = "basic-key-ops")]
impl From<CompressedPublicKey> for PublicKey {
    fn from(value: CompressedPublicKey) -> Self { PublicKey::new(value.0) }
}

#[cfg(feature = "basic-key-ops")]
impl From<CompressedPublicKey> for XOnlyPublicKey {
    fn from(pk: CompressedPublicKey) -> Self { pk.0.into() }
}

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hashes")]
impl From<CompressedPublicKey> for PubkeyHash {
    fn from(key: CompressedPublicKey) -> Self { key.pubkey_hash() }
}

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hashes")]
impl From<&CompressedPublicKey> for PubkeyHash {
    fn from(key: &CompressedPublicKey) -> Self { key.pubkey_hash() }
}

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hashes")]
impl From<CompressedPublicKey> for WPubkeyHash {
    fn from(key: CompressedPublicKey) -> Self { key.wpubkey_hash() }
}

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hashes")]
impl From<&CompressedPublicKey> for WPubkeyHash {
    fn from(key: &CompressedPublicKey) -> Self { key.wpubkey_hash() }
}

#[cfg(feature = "serde")]
#[cfg(feature = "basic-key-ops")]
#[allow(clippy::collapsible_else_if)] // Aids readability.
impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            self.with_serialized(|bytes| s.serialize_bytes(bytes))
        }
    }
}

#[cfg(feature = "serde")]
#[cfg(feature = "basic-key-ops")]
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        if d.is_human_readable() {
            #[cfg(feature = "hex")]
            struct HexVisitor;

            #[cfg(feature = "hex")]
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
            #[cfg(feature = "hex")]
            {
                d.deserialize_str(HexVisitor)
            }
            #[cfg(not(feature = "hex"))]
            {
                D::Error::custom("serializing keys into human-readable formats is unsupported without the `hex` feature")
            }
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

#[cfg(feature = "serde")]
#[cfg(feature = "basic-key-ops")]
impl serde::Serialize for CompressedPublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.to_bytes())
        }
    }
}

#[cfg(feature = "serde")]
#[cfg(feature = "basic-key-ops")]
impl<'de> serde::Deserialize<'de> for CompressedPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            #[cfg(feature = "hex")]
            struct HexVisitor;

            #[cfg(feature = "hex")]
            impl<'de> serde::de::Visitor<'de> for HexVisitor {
                type Value = CompressedPublicKey;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("a 66 digits long ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    if let Ok(hex) = core::str::from_utf8(v) {
                        CompressedPublicKey::from_str(hex).map_err(E::custom)
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    CompressedPublicKey::from_str(v).map_err(E::custom)
                }
            }
            #[cfg(feature = "hex")]
            {
                d.deserialize_str(HexVisitor)
            }
            #[cfg(not(feature = "hex"))]
            {
                D::Error::custom("deserializing keys from human-readable formats is unsupported without the `hex` feature")
            }
        } else {
            struct BytesVisitor;

            impl<'de> serde::de::Visitor<'de> for BytesVisitor {
                type Value = CompressedPublicKey;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    CompressedPublicKey::from_slice(v).map_err(E::custom)
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}
/// Untweaked BIP-340 X-coord-only public key.
pub type UntweakedPublicKey = XOnlyPublicKey;

/// Tweaked BIP-340 X-coord-only public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct TweakedPublicKey(XOnlyPublicKey);

impl TweakedPublicKey {
    /// Creates a new [`TweakedPublicKey`] from a [`XOnlyPublicKey`]. No tweak is applied, consider
    /// calling `tap_tweak` on an [`UntweakedPublicKey`] instead of using this constructor.
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    #[inline]
    pub fn dangerous_assume_tweaked(key: XOnlyPublicKey) -> TweakedPublicKey {
        TweakedPublicKey(key)
    }

    /// Returns the underlying public key.
    pub fn to_inner(self) -> XOnlyPublicKey { self.0 }

    /// Serializes the key as a byte-encoded pair of values. In compressed form
    /// the y-coordinate is represented by only a single bit, as x determines
    /// it up to one bit.
    #[inline]
    pub fn serialize(&self) -> [u8; 32] { self.0.serialize() }
}

impl From<TweakedPublicKey> for XOnlyPublicKey {
    #[inline]
    fn from(pair: TweakedPublicKey) -> Self { pair.0 }
}

#[cfg(feature = "hex")]
impl fmt::LowerHex for TweakedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
}

#[cfg(feature = "hex")]
impl fmt::Display for TweakedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

/// Error returned while generating key from slice.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg(feature = "basic-key-ops")]
pub enum FromSliceError {
    /// Invalid key prefix error.
    InvalidKeyPrefix(u8),
    /// A Secp256k1 error.
    Secp256k1(bare::PublicKeyDeserError),
    /// Invalid Length of the slice.
    InvalidLength(usize),
}

#[cfg(feature = "basic-key-ops")]
internals::impl_from_infallible!(FromSliceError);

#[cfg(feature = "basic-key-ops")]
impl fmt::Display for FromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use FromSliceError::*;

        match self {
            Secp256k1(e) => write_err!(f, "secp256k1"; e),
            InvalidKeyPrefix(b) => write!(f, "key prefix invalid: {}", b),
            InvalidLength(got) => write!(f, "slice length should be 33 or 65 bytes, got: {}", got),
        }
    }
}

#[cfg(feature = "std")]
#[cfg(feature = "basic-key-ops")]
impl std::error::Error for FromSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use FromSliceError::*;

        match *self {
            Secp256k1(ref e) => Some(e),
            InvalidKeyPrefix(_) | InvalidLength(_) => None,
        }
    }
}

#[cfg(feature = "basic-key-ops")]
impl From<bare::PublicKeyDeserError> for FromSliceError {
    fn from(e: bare::PublicKeyDeserError) -> Self { Self::Secp256k1(e) }
}

/// Error returned while constructing public key from string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hex")]
pub enum ParsePublicKeyError {
    /// Error originated while parsing string.
    Encoding(FromSliceError),
    /// Hex decoding error.
    InvalidChar(u8),
    /// `PublicKey` hex should be 66 or 130 digits long.
    InvalidHexLength(usize),
}

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hex")]
internals::impl_from_infallible!(ParsePublicKeyError);

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hex")]
impl fmt::Display for ParsePublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParsePublicKeyError::*;
        match self {
            Encoding(e) => write_err!(f, "string error"; e),
            InvalidChar(char) => write!(f, "hex error {}", char),
            InvalidHexLength(got) =>
                write!(f, "pubkey string should be 66 or 130 digits long, got: {}", got),
        }
    }
}

#[cfg(feature = "std")]
#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hex")]
impl std::error::Error for ParsePublicKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParsePublicKeyError::*;

        match self {
            Encoding(e) => Some(e),
            InvalidChar(_) | InvalidHexLength(_) => None,
        }
    }
}

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hex")]
impl From<FromSliceError> for ParsePublicKeyError {
    fn from(e: FromSliceError) -> Self { Self::Encoding(e) }
}

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hex")]
impl From<bare::PublicKeyDeserError> for ParsePublicKeyError {
    fn from(e: bare::PublicKeyDeserError) -> Self { Self::Encoding(FromSliceError::Secp256k1(e)) }
}

/// Error returned when parsing a [`CompressedPublicKey`] from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hex")]
pub enum ParseCompressedPublicKeyError {
    /// Secp256k1 Error.
    Secp256k1(bare::PublicKeyDeserError),
    /// hex to array conversion error.
    Hex(hex::HexToArrayError),
}

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hex")]
internals::impl_from_infallible!(ParseCompressedPublicKeyError);

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hex")]
impl fmt::Display for ParseCompressedPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseCompressedPublicKeyError::*;
        match self {
            Secp256k1(e) => write_err!(f, "secp256k1 error"; e),
            Hex(e) => write_err!(f, "invalid hex"; e),
        }
    }
}

#[cfg(feature = "std")]
#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hex")]
impl std::error::Error for ParseCompressedPublicKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseCompressedPublicKeyError::*;

        match self {
            Secp256k1(e) => Some(e),
            Hex(e) => Some(e),
        }
    }
}

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hex")]
impl From<bare::PublicKeyDeserError> for ParseCompressedPublicKeyError {
    fn from(e: bare::PublicKeyDeserError) -> Self { Self::Secp256k1(e) }
}

#[cfg(feature = "basic-key-ops")]
#[cfg(feature = "hex")]
impl From<hex::HexToArrayError> for ParseCompressedPublicKeyError {
    fn from(e: hex::HexToArrayError) -> Self { Self::Hex(e) }
}

/// Segwit public keys must always be compressed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UncompressedPublicKeyError;

impl fmt::Display for UncompressedPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("segwit public keys must always be compressed")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UncompressedPublicKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Decoded base58 data was an invalid length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidBase58PayloadLengthError {
    /// The base58 payload length we got after decoding WIF string.
    pub(crate) length: usize,
}

impl InvalidBase58PayloadLengthError {
    /// Returns the invalid payload length.
    pub fn invalid_base58_payload_length(&self) -> usize { self.length }
}

impl fmt::Display for InvalidBase58PayloadLengthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "decoded base58 data was an invalid length: {} (expected 33 or 34)", self.length)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidBase58PayloadLengthError {}

/// Invalid address version in decoded base58 data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidAddressVersionError {
    /// The invalid version.
    pub(crate) invalid: u8,
}

impl InvalidAddressVersionError {
    /// Returns the invalid version.
    pub fn invalid_address_version(&self) -> u8 { self.invalid }
}

impl fmt::Display for InvalidAddressVersionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid address version in decoded base58 data {}", self.invalid)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidAddressVersionError {}

/// The serialized represenation of `PublicKey`.
pub struct SerializedPublicKey(ArrayVec<u8, 65>);

// TODO: more traits
impl core::ops::Deref for SerializedPublicKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
