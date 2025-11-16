// SPDX-License-Identifier: CC0-1.0

//! Bitcoin keys.
//!
//! This module provides keys used in Bitcoin that can be roundtrip
//! (de)serialized.

use core::convert::Infallible;
use core::fmt::{self, Write as _};
use core::ops;
use core::str::FromStr;

use hashes::hash160;
use hex::{FromHex, HexToArrayError};
use internals::array::ArrayExt;
use internals::array_vec::ArrayVec;
use internals::{impl_to_hex_from_lower_hex, write_err};
use io::{Read, Write};

use crate::crypto::ecdsa;
use crate::internal_macros::impl_asref_push_bytes;
use crate::network::NetworkKind;
use crate::prelude::{DisplayHex, String, Vec};
use crate::script::{self, WitnessScriptBuf};
use crate::taproot::{TapNodeHash, TapTweakHash};

#[rustfmt::skip]                // Keep public re-exports separate.
pub use secp256k1::{constants, Keypair, Parity, Secp256k1, Verification};
#[cfg(feature = "rand-std")]
pub use secp256k1::rand;
pub use serialized_x_only::SerializedXOnlyPublicKey;

/// A Bitcoin Schnorr X-only public key used for BIP-0340 signatures.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct XOnlyPublicKey(secp256k1::XOnlyPublicKey);

impl XOnlyPublicKey {
    /// Constructs a new x-only public key from the provided generic secp256k1 x-only public key.
    pub fn new(key: impl Into<secp256k1::XOnlyPublicKey>) -> Self { Self(key.into()) }

    /// Constructs an x-only public key from a keypair.
    ///
    /// Returns the x-only public key and the parity of the full public key.
    #[inline]
    pub fn from_keypair(keypair: &Keypair) -> (Self, Parity) {
        let (xonly, parity) = secp256k1::XOnlyPublicKey::from_keypair(keypair);
        (Self::new(xonly), parity)
    }

    /// Constructs an x-only public key from a 32-byte x-coordinate.
    ///
    /// Returns an error if the provided bytes don't represent a valid secp256k1 point x-coordinate.
    #[inline]
    pub fn from_byte_array(
        data: &[u8; constants::SCHNORR_PUBLIC_KEY_SIZE],
    ) -> Result<Self, ParseXOnlyPublicKeyError> {
        secp256k1::XOnlyPublicKey::from_byte_array(data)
            .map(Self::new)
            .map_err(|_| ParseXOnlyPublicKeyError::InvalidXCoordinate)
    }

    /// Returns the inner secp256k1 x-only public key.
    #[inline]
    pub fn into_inner(self) -> secp256k1::XOnlyPublicKey { self.0 }

    /// Serializes the x-only public key as a byte-encoded x coordinate value (32 bytes).
    #[inline]
    pub fn serialize(&self) -> [u8; constants::SCHNORR_PUBLIC_KEY_SIZE] { self.0.serialize() }

    /// Converts this x-only public key to a full public key given the parity.
    #[inline]
    pub fn public_key(&self, parity: Parity) -> PublicKey { self.0.public_key(parity).into() }

    /// Verifies that a tweak produced by [`XOnlyPublicKey::add_tweak`] was computed correctly.
    ///
    /// Should be called on the original untweaked key. Takes the tweaked key and output parity from
    /// [`XOnlyPublicKey::add_tweak`] as input.
    #[inline]
    pub fn tweak_add_check<V: Verification>(
        &self,
        secp: &Secp256k1<V>,
        tweaked_key: &Self,
        tweaked_parity: Parity,
        tweak: secp256k1::Scalar,
    ) -> bool {
        self.0.tweak_add_check(secp, &tweaked_key.0, tweaked_parity, tweak)
    }

    /// Tweaks an [`XOnlyPublicKey`] by adding the generator multiplied with the given tweak to it.
    ///
    /// # Returns
    ///
    /// The newly tweaked key plus an opaque type representing the parity of the tweaked key, this
    /// should be provided to `tweak_add_check` which can be used to verify a tweak more efficiently
    /// than regenerating it and checking equality.
    ///
    /// # Errors
    ///
    /// If the resulting key would be invalid.
    #[inline]
    pub fn add_tweak<V: Verification>(
        &self,
        secp: &Secp256k1<V>,
        tweak: &secp256k1::Scalar,
    ) -> Result<(Self, Parity), TweakXOnlyPublicKeyError> {
        match self.0.add_tweak(secp, tweak) {
            Ok((xonly, parity)) => Ok((Self(xonly), parity)),
            Err(secp256k1::Error::InvalidTweak) => Err(TweakXOnlyPublicKeyError::BadTweak),
            Err(secp256k1::Error::InvalidParityValue(_)) =>
                Err(TweakXOnlyPublicKeyError::ParityError),
            Err(_) => Err(TweakXOnlyPublicKeyError::ResultKeyInvalid),
        }
    }
}

impl FromStr for XOnlyPublicKey {
    type Err = ParseXOnlyPublicKeyError;
    fn from_str(s: &str) -> Result<Self, ParseXOnlyPublicKeyError> {
        secp256k1::XOnlyPublicKey::from_str(s)
            .map(Self::from)
            .map_err(|_| ParseXOnlyPublicKeyError::InvalidXCoordinate)
    }
}

impl From<secp256k1::XOnlyPublicKey> for XOnlyPublicKey {
    fn from(pk: secp256k1::XOnlyPublicKey) -> Self { Self::new(pk) }
}

impl From<secp256k1::PublicKey> for XOnlyPublicKey {
    fn from(pk: secp256k1::PublicKey) -> Self { Self::new(pk) }
}

impl fmt::LowerHex for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
}
// Allocate for serialized size
impl_to_hex_from_lower_hex!(XOnlyPublicKey, |_| constants::SCHNORR_PUBLIC_KEY_SIZE * 2);

impl fmt::Display for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

/// A Bitcoin ECDSA public key.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey {
    /// Whether this public key should be serialized as compressed.
    pub compressed: bool,
    /// The actual ECDSA key.
    pub inner: secp256k1::PublicKey,
}

impl PublicKey {
    /// Constructs a new compressed ECDSA public key from the provided generic secp256k1 public key.
    pub fn new(key: impl Into<secp256k1::PublicKey>) -> Self {
        Self { compressed: true, inner: key.into() }
    }

    /// Constructs a new uncompressed (legacy) ECDSA public key from the provided generic secp256k1
    /// public key.
    pub fn new_uncompressed(key: impl Into<secp256k1::PublicKey>) -> Self {
        Self { compressed: false, inner: key.into() }
    }

    fn with_serialized<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        if self.compressed {
            f(&self.inner.serialize())
        } else {
            f(&self.inner.serialize_uncompressed())
        }
    }

    /// Returns bitcoin 160-bit hash of the public key.
    pub fn pubkey_hash(&self) -> PubkeyHash {
        PubkeyHash(self.with_serialized(hash160::Hash::hash))
    }

    /// Returns bitcoin 160-bit hash of the public key for witness program
    pub fn wpubkey_hash(&self) -> Result<WPubkeyHash, UncompressedPublicKeyError> {
        if self.compressed {
            Ok(WPubkeyHash::from_byte_array(
                hash160::Hash::hash(&self.inner.serialize()).to_byte_array(),
            ))
        } else {
            Err(UncompressedPublicKeyError)
        }
    }

    /// Returns the script code used to spend a P2WPKH input.
    ///
    /// While the type returned is [`WitnessScriptBuf`], this is **not** a witness script and
    /// should not be used as one. It is a special template defined in BIP 143 which is used
    /// in place of a witness script for purposes of sighash computation.
    pub fn p2wpkh_script_code(&self) -> Result<WitnessScriptBuf, UncompressedPublicKeyError> {
        let key = CompressedPublicKey::try_from(*self)?;
        Ok(key.p2wpkh_script_code())
    }

    /// Writes the public key into a writer.
    pub fn write_into<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
        self.with_serialized(|bytes| writer.write_all(bytes))
    }

    /// Reads the public key from a reader.
    ///
    /// This internally reads the first byte before reading the rest, so
    /// use of a `BufReader` is recommended.
    pub fn read_from<R: Read + ?Sized>(reader: &mut R) -> Result<Self, io::Error> {
        let mut bytes = [0; 65];

        reader.read_exact(&mut bytes[0..1])?;
        let bytes = if bytes[0] < 4 { &mut bytes[..33] } else { &mut bytes[..65] };

        reader.read_exact(&mut bytes[1..])?;
        Self::from_slice(bytes).map_err(|e| {
            // Need a static string for no-std io
            #[cfg(feature = "std")]
            let reason = e;
            #[cfg(not(feature = "std"))]
            let reason = match e {
                FromSliceError::Secp256k1(_) => "secp256k1 error",
                FromSliceError::InvalidKeyPrefix(_) => "invalid key prefix",
                FromSliceError::InvalidLength(_) => "invalid length",
            };
            io::Error::new(io::ErrorKind::InvalidData, reason)
        })
    }

    /// Serializes the public key to bytes.
    #[deprecated(since = "TBD", note = "use to_vec instead")]
    pub fn to_bytes(self) -> Vec<u8> { self.to_vec() }

    /// Serializes the public key to bytes.
    pub fn to_vec(self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf).expect("vecs don't error");
        buf
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
    /// [BIP-0067](https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki)
    /// compliant way.
    ///
    /// # Example: Using with `sort_unstable_by_key`
    ///
    /// ```rust
    /// use bitcoin::PublicKey;
    ///
    /// let pk = |s: &str| s.parse::<PublicKey>().unwrap();
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
    ///     // These first 4 keys are in a BIP-0067 compatible sorted order
    ///     // (since they are compressed)
    ///     pk("0234dd69c56c36a41230d573d68adeae0030c9bc0bf26f24d3e1b64c604d293c68"),
    ///     pk("028bde91b10013e08949a318018fedbd896534a549a278e220169ee2a36517c7aa"),
    ///     pk("032b8324c93575034047a52e9bca05a46d8347046b91a032eff07d5de8d3f2730b"),
    ///     pk("038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354"),
    ///     // Uncompressed keys are not BIP-0067 compliant, but are sorted
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
    pub fn from_slice(data: &[u8]) -> Result<Self, FromSliceError> {
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

        Ok(Self { compressed, inner: secp256k1::PublicKey::from_slice(data)? })
    }

    /// Computes the public key as supposed to be used with this secret.
    pub fn from_private_key<C: secp256k1::Signing>(secp: &Secp256k1<C>, sk: PrivateKey) -> Self {
        sk.public_key(secp)
    }

    /// Checks that `sig` is a valid ECDSA signature for `msg` using this public key.
    pub fn verify<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        msg: secp256k1::Message,
        sig: ecdsa::Signature,
    ) -> Result<(), secp256k1::Error> {
        secp.verify_ecdsa(&msg, &sig.signature, &self.inner)
    }
}

impl From<secp256k1::PublicKey> for PublicKey {
    fn from(pk: secp256k1::PublicKey) -> Self { Self::new(pk) }
}

impl From<PublicKey> for XOnlyPublicKey {
    fn from(pk: PublicKey) -> Self { Self::new(pk.inner) }
}

/// An opaque return type for PublicKey::to_sort_key.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct SortKey(ArrayVec<u8, 65>);

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.with_serialized(|bytes| fmt::Display::fmt(&bytes.as_hex(), f))
    }
}

impl FromStr for PublicKey {
    type Err = ParsePublicKeyError;
    fn from_str(s: &str) -> Result<Self, ParsePublicKeyError> {
        use HexToArrayError::*;

        match s.len() {
            66 => {
                let bytes = <[u8; 33]>::from_hex(s).map_err(|e| match e {
                    InvalidChar(e) => ParsePublicKeyError::InvalidChar(e),
                    InvalidLength(_) => unreachable!("length checked already"),
                })?;
                Ok(Self::from_slice(&bytes)?)
            }
            130 => {
                let bytes = <[u8; 65]>::from_hex(s).map_err(|e| match e {
                    InvalidChar(e) => ParsePublicKeyError::InvalidChar(e),
                    InvalidLength(_) => unreachable!("length checked already"),
                })?;
                Ok(Self::from_slice(&bytes)?)
            }
            len => Err(ParsePublicKeyError::InvalidHexLength(len)),
        }
    }
}

hashes::hash_newtype! {
    /// A hash of a public key.
    pub struct PubkeyHash(hash160::Hash);
    /// SegWit version of a public key hash.
    pub struct WPubkeyHash(hash160::Hash);
}

hashes::impl_hex_for_newtype!(PubkeyHash, WPubkeyHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(PubkeyHash, WPubkeyHash);

impl_asref_push_bytes!(PubkeyHash, WPubkeyHash);

impl From<PublicKey> for PubkeyHash {
    fn from(key: PublicKey) -> Self { key.pubkey_hash() }
}

impl From<&PublicKey> for PubkeyHash {
    fn from(key: &PublicKey) -> Self { key.pubkey_hash() }
}

/// An always-compressed Bitcoin ECDSA public key.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompressedPublicKey(pub secp256k1::PublicKey);

impl CompressedPublicKey {
    /// Returns bitcoin 160-bit hash of the public key.
    pub fn pubkey_hash(&self) -> PubkeyHash { PubkeyHash(hash160::Hash::hash(&self.to_bytes())) }

    /// Returns bitcoin 160-bit hash of the public key for witness program.
    pub fn wpubkey_hash(&self) -> WPubkeyHash {
        WPubkeyHash::from_byte_array(hash160::Hash::hash(&self.to_bytes()).to_byte_array())
    }

    /// Returns the script code used to spend a P2WPKH input.
    ///
    /// While the type returned is [`WitnessScriptBuf`], this is **not** a witness script and
    /// should not be used as one. It is a special template defined in BIP 143 which is used
    /// in place of a witness script for purposes of sighash computation.
    pub fn p2wpkh_script_code(&self) -> WitnessScriptBuf {
        script::p2wpkh_script_code(self.wpubkey_hash())
    }

    /// Writes the public key into a writer.
    pub fn write_into<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
        writer.write_all(&self.to_bytes())
    }

    /// Reads the public key from a reader.
    ///
    /// This internally reads the first byte before reading the rest, so
    /// use of a `BufReader` is recommended.
    pub fn read_from<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, io::Error> {
        let mut bytes = [0; 33];

        reader.read_exact(&mut bytes)?;
        #[allow(unused_variables)] // e when std not enabled
        Self::from_slice(&bytes).map_err(|e| {
            // Need a static string for no-std io
            #[cfg(feature = "std")]
            let reason = e;
            #[cfg(not(feature = "std"))]
            let reason = "secp256k1 error";
            io::Error::new(io::ErrorKind::InvalidData, reason)
        })
    }

    /// Serializes the public key.
    ///
    /// As the type name suggests, the key is serialized in compressed format.
    ///
    /// Note that this can be used as a sort key to get BIP-0067-compliant sorting.
    /// That's why this type doesn't have the `to_sort_key` method - it would duplicate this one.
    pub fn to_bytes(self) -> [u8; 33] { self.0.serialize() }

    /// Deserializes a public key from a slice.
    pub fn from_slice(data: &[u8]) -> Result<Self, secp256k1::Error> {
        secp256k1::PublicKey::from_slice(data).map(CompressedPublicKey)
    }

    /// Computes the public key as supposed to be used with this secret.
    pub fn from_private_key<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        sk: PrivateKey,
    ) -> Result<Self, UncompressedPublicKeyError> {
        sk.public_key(secp).try_into()
    }

    /// Checks that `sig` is a valid ECDSA signature for `msg` using this public key.
    pub fn verify<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        msg: secp256k1::Message,
        sig: ecdsa::Signature,
    ) -> Result<(), secp256k1::Error> {
        Ok(secp.verify_ecdsa(&msg, &sig.signature, &self.0)?)
    }
}

impl fmt::Display for CompressedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.to_bytes().as_hex(), f)
    }
}

impl fmt::Debug for CompressedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!("CompressedPublicKey({})", self))
    }
}

impl FromStr for CompressedPublicKey {
    type Err = ParseCompressedPublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_slice(&<[u8; 33]>::from_hex(s)?).map_err(Into::into)
    }
}

impl TryFrom<PublicKey> for CompressedPublicKey {
    type Error = UncompressedPublicKeyError;

    fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
        if value.compressed {
            Ok(Self(value.inner))
        } else {
            Err(UncompressedPublicKeyError)
        }
    }
}

impl From<CompressedPublicKey> for PublicKey {
    fn from(value: CompressedPublicKey) -> Self { Self::new(value.0) }
}

impl From<CompressedPublicKey> for XOnlyPublicKey {
    fn from(pk: CompressedPublicKey) -> Self { pk.0.into() }
}

impl From<CompressedPublicKey> for PubkeyHash {
    fn from(key: CompressedPublicKey) -> Self { key.pubkey_hash() }
}

impl From<&CompressedPublicKey> for PubkeyHash {
    fn from(key: &CompressedPublicKey) -> Self { key.pubkey_hash() }
}

impl From<CompressedPublicKey> for WPubkeyHash {
    fn from(key: CompressedPublicKey) -> Self { key.wpubkey_hash() }
}

impl From<&CompressedPublicKey> for WPubkeyHash {
    fn from(key: &CompressedPublicKey) -> Self { key.wpubkey_hash() }
}

/// A Bitcoin ECDSA private key.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PrivateKey {
    /// Whether this private key should be serialized as compressed.
    pub compressed: bool,
    /// The network kind on which this key should be used.
    pub network: NetworkKind,
    /// The actual ECDSA key.
    pub inner: secp256k1::SecretKey,
}

impl PrivateKey {
    /// Constructs a new compressed ECDSA private key using the secp256k1 algorithm and
    /// a secure random number generator.
    #[cfg(feature = "rand-std")]
    pub fn generate(network: impl Into<NetworkKind>) -> Self {
        let secret_key = secp256k1::SecretKey::new(&mut rand::thread_rng());
        Self::new(secret_key, network.into())
    }
    /// Constructs a new compressed ECDSA private key from the provided generic secp256k1 private key
    /// and the specified network.
    pub fn new(key: secp256k1::SecretKey, network: impl Into<NetworkKind>) -> Self {
        Self { compressed: true, network: network.into(), inner: key }
    }

    /// Constructs a new uncompressed (legacy) ECDSA private key from the provided generic secp256k1
    /// private key and the specified network.
    pub fn new_uncompressed(key: secp256k1::SecretKey, network: impl Into<NetworkKind>) -> Self {
        Self { compressed: false, network: network.into(), inner: key }
    }

    /// Constructs a new public key from this private key.
    pub fn public_key<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> PublicKey {
        PublicKey {
            compressed: self.compressed,
            inner: secp256k1::PublicKey::from_secret_key(secp, &self.inner),
        }
    }

    /// Serializes the private key to bytes.
    #[deprecated(since = "TBD", note = "use to_vec instead")]
    pub fn to_bytes(self) -> Vec<u8> { self.to_vec() }

    /// Serializes the private key to bytes.
    pub fn to_vec(self) -> Vec<u8> { self.inner[..].to_vec() }

    /// Deserializes a private key from a byte array.
    pub fn from_byte_array(
        data: [u8; 32],
        network: impl Into<NetworkKind>,
    ) -> Result<Self, secp256k1::Error> {
        Ok(Self::new(secp256k1::SecretKey::from_byte_array(&data)?, network))
    }

    /// Deserializes a private key from a slice.
    #[deprecated(since = "TBD", note = "use from_byte_array instead")]
    pub fn from_slice(
        data: &[u8],
        network: impl Into<NetworkKind>,
    ) -> Result<Self, secp256k1::Error> {
        let array = data.try_into().map_err(|_| secp256k1::Error::InvalidSecretKey)?;
        Self::from_byte_array(array, network)
    }

    /// Formats the private key to WIF format.
    #[rustfmt::skip]
    pub fn fmt_wif(&self, fmt: &mut dyn fmt::Write) -> fmt::Result {
        let mut ret = [0; 34];
        ret[0] = if self.network.is_mainnet() { 128 } else { 239 };

        ret[1..33].copy_from_slice(&self.inner[..]);
        let privkey = if self.compressed {
            ret[33] = 1;
            base58::encode_check(&ret[..])
        } else {
            base58::encode_check(&ret[..33])
        };
        fmt.write_str(&privkey)
    }

    /// Gets the WIF encoding of this private key.
    pub fn to_wif(self) -> String {
        let mut buf = String::new();
        buf.write_fmt(format_args!("{}", self)).unwrap();
        buf.shrink_to_fit();
        buf
    }

    /// Parses the WIF encoded private key.
    pub fn from_wif(wif: &str) -> Result<Self, FromWifError> {
        let data = base58::decode_check(wif)?;

        let (compressed, data) = if let Ok(data) = <&[u8; 33]>::try_from(&*data) {
            (false, data)
        } else if let Ok(data) = <&[u8; 34]>::try_from(&*data) {
            let (compressed_flag, data) = data.split_last::<33>();
            if *compressed_flag != 1 {
                return Err(InvalidWifCompressionFlagError { invalid: *compressed_flag }.into());
            }
            (true, data)
        } else {
            return Err(InvalidBase58PayloadLengthError { length: data.len() }.into());
        };

        let (network, key) = data.split_first();
        let network = match *network {
            128 => NetworkKind::Main,
            239 => NetworkKind::Test,
            invalid => {
                return Err(InvalidAddressVersionError { invalid }.into());
            }
        };

        Ok(Self { compressed, network, inner: secp256k1::SecretKey::from_byte_array(key)? })
    }

    /// Returns a new private key with the negated secret value.
    ///
    /// The resulting key corresponds to the same x-only public key (identical x-coordinate)
    /// but with the opposite y-coordinate parity. This is useful for ensuring compatibility
    /// with specific public key formats and BIP-0340 requirements.
    #[inline]
    pub fn negate(&self) -> Self {
        Self { compressed: self.compressed, network: self.network, inner: self.inner.negate() }
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { self.fmt_wif(f) }
}

impl FromStr for PrivateKey {
    type Err = FromWifError;
    fn from_str(s: &str) -> Result<Self, FromWifError> { Self::from_wif(s) }
}

impl ops::Index<ops::RangeFull> for PrivateKey {
    type Output = [u8];
    fn index(&self, _: ops::RangeFull) -> &[u8] { &self.inner[..] }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PrivateKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PrivateKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct WifVisitor;

        impl serde::de::Visitor<'_> for WifVisitor {
            type Value = PrivateKey;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("an ASCII WIF string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if let Ok(s) = core::str::from_utf8(v) {
                    s.parse::<PrivateKey>().map_err(E::custom)
                } else {
                    Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.parse::<PrivateKey>().map_err(E::custom)
            }
        }

        d.deserialize_str(WifVisitor)
    }
}

#[cfg(feature = "serde")]
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
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl serde::de::Visitor<'_> for HexVisitor {
                type Value = PublicKey;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("an ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    if let Ok(hex) = core::str::from_utf8(v) {
                        hex.parse::<PublicKey>().map_err(E::custom)
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    v.parse::<PublicKey>().map_err(E::custom)
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl serde::de::Visitor<'_> for BytesVisitor {
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
impl<'de> serde::Deserialize<'de> for CompressedPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl serde::de::Visitor<'_> for HexVisitor {
                type Value = CompressedPublicKey;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("a 66 digits long ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    if let Ok(hex) = core::str::from_utf8(v) {
                        hex.parse::<CompressedPublicKey>().map_err(E::custom)
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    v.parse::<CompressedPublicKey>().map_err(E::custom)
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl serde::de::Visitor<'_> for BytesVisitor {
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
/// Untweaked BIP-0340 X-coord-only public key.
pub type UntweakedPublicKey = XOnlyPublicKey;

/// Tweaked BIP-0340 X-coord-only public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct TweakedPublicKey(XOnlyPublicKey);

impl fmt::LowerHex for TweakedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
}
// Allocate for serialized size
impl_to_hex_from_lower_hex!(TweakedPublicKey, |_| constants::SCHNORR_PUBLIC_KEY_SIZE * 2);

impl fmt::Display for TweakedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

/// Untweaked BIP-0340 key pair.
pub type UntweakedKeypair = Keypair;

/// Tweaked BIP-0340 key pair.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "rand-std")] {
/// # use bitcoin::key::{Keypair, TweakedKeypair, TweakedPublicKey};
/// # use bitcoin::secp256k1::{rand, Secp256k1};
/// # let secp = Secp256k1::new();
/// # let keypair = TweakedKeypair::dangerous_assume_tweaked(Keypair::new(&secp, &mut rand::thread_rng()));
/// // There are various conversion methods available to get a tweaked pubkey from a tweaked keypair.
/// let (_pk, _parity) = keypair.public_parts();
/// let _pk = TweakedPublicKey::from_keypair(keypair);
/// let _pk = TweakedPublicKey::from(keypair);
/// # }
/// ```
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct TweakedKeypair(Keypair);

/// A trait for tweaking BIP-0340 key types (x-only public keys and key pairs).
pub trait TapTweak {
    /// Tweaked key type with optional auxiliary information.
    type TweakedAux;
    /// Tweaked key type.
    type TweakedKey;

    /// Tweaks an untweaked key with corresponding public key value and optional script tree Merkle
    /// root. For the [`Keypair`] type this also tweaks the private key in the pair.
    ///
    /// This is done by using the equation Q = P + H(P|c)G, where
    ///  * Q is the tweaked public key
    ///  * P is the internal public key
    ///  * H is the hash function
    ///  * c is the commitment data
    ///  * G is the generator point
    ///
    /// # Returns
    ///
    /// The tweaked key and its parity.
    fn tap_tweak<C: Verification>(
        self,
        secp: &Secp256k1<C>,
        merkle_root: Option<TapNodeHash>,
    ) -> Self::TweakedAux;

    /// Directly converts an [`UntweakedPublicKey`] to a [`TweakedPublicKey`].
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    fn dangerous_assume_tweaked(self) -> Self::TweakedKey;
}

impl TapTweak for UntweakedPublicKey {
    type TweakedAux = (TweakedPublicKey, Parity);
    type TweakedKey = TweakedPublicKey;

    /// Tweaks an untweaked public key with corresponding public key value and optional script tree
    /// Merkle root.
    ///
    /// This is done by using the equation Q = P + H(P|c)G, where
    ///  * Q is the tweaked public key
    ///  * P is the internal public key
    ///  * H is the hash function
    ///  * c is the commitment data
    ///  * G is the generator point
    ///
    /// # Returns
    ///
    /// The tweaked key and its parity.
    fn tap_tweak<C: Verification>(
        self,
        secp: &Secp256k1<C>,
        merkle_root: Option<TapNodeHash>,
    ) -> (TweakedPublicKey, Parity) {
        let tweak = TapTweakHash::from_key_and_merkle_root(self, merkle_root).to_scalar();
        let (output_key, parity) = self.add_tweak(secp, &tweak).expect("Tap tweak failed");

        debug_assert!(self.tweak_add_check(secp, &output_key, parity, tweak));
        (TweakedPublicKey(output_key), parity)
    }

    fn dangerous_assume_tweaked(self) -> TweakedPublicKey { TweakedPublicKey(self) }
}

impl TapTweak for UntweakedKeypair {
    type TweakedAux = TweakedKeypair;
    type TweakedKey = TweakedKeypair;

    /// Applies a Taproot tweak to both keys within the keypair.
    ///
    /// If `merkle_root` is provided, produces a Taproot key that can be spent by any
    /// of the script paths committed to by the root. If it is not provided, produces
    /// a Taproot key which can [provably only be spent via
    /// keyspend](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-23).
    ///
    /// # Returns
    ///
    /// The tweaked keypair.
    fn tap_tweak<C: Verification>(
        self,
        secp: &Secp256k1<C>,
        merkle_root: Option<TapNodeHash>,
    ) -> TweakedKeypair {
        let (pubkey, _parity) = XOnlyPublicKey::from_keypair(&self);
        let tweak = TapTweakHash::from_key_and_merkle_root(pubkey, merkle_root).to_scalar();
        let tweaked = self.add_xonly_tweak(secp, &tweak).expect("Tap tweak failed");
        TweakedKeypair(tweaked)
    }

    fn dangerous_assume_tweaked(self) -> TweakedKeypair { TweakedKeypair(self) }
}

impl TweakedPublicKey {
    /// Returns the [`TweakedPublicKey`] for `keypair`.
    #[inline]
    pub fn from_keypair(keypair: TweakedKeypair) -> Self {
        let (xonly, _parity) = keypair.0.x_only_public_key();
        Self(xonly.into())
    }

    /// Constructs a new [`TweakedPublicKey`] from a [`XOnlyPublicKey`]. No tweak is applied, consider
    /// calling `tap_tweak` on an [`UntweakedPublicKey`] instead of using this constructor.
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    #[inline]
    pub fn dangerous_assume_tweaked(key: XOnlyPublicKey) -> Self { Self(key) }

    /// Returns the underlying public key.
    #[inline]
    #[doc(hidden)]
    #[deprecated(since = "0.32.6", note = "use to_x_only_public_key() instead")]
    pub fn to_inner(self) -> XOnlyPublicKey { self.0 }

    /// Returns the underlying x-only public key.
    #[inline]
    pub fn to_x_only_public_key(self) -> XOnlyPublicKey { self.0 }

    /// Returns a reference to the underlying x-only public key.
    #[inline]
    pub fn as_x_only_public_key(&self) -> &XOnlyPublicKey { &self.0 }

    /// Serializes the key as a byte-encoded x coordinate value (32 bytes).
    #[inline]
    pub fn serialize(&self) -> [u8; constants::SCHNORR_PUBLIC_KEY_SIZE] { self.0.serialize() }
}

impl TweakedKeypair {
    /// Constructs a new [`TweakedKeypair`] from a [`Keypair`]. No tweak is applied, consider
    /// calling `tap_tweak` on an [`UntweakedKeypair`] instead of using this constructor.
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    #[inline]
    pub fn dangerous_assume_tweaked(pair: Keypair) -> Self { Self(pair) }

    /// Returns the underlying key pair.
    #[inline]
    #[doc(hidden)]
    #[deprecated(since = "0.32.6", note = "use to_keypair() instead")]
    pub fn to_inner(self) -> Keypair { self.0 }

    /// Returns the underlying key pair.
    #[inline]
    pub fn to_keypair(self) -> Keypair { self.0 }

    /// Returns a reference to the underlying key pair.
    #[inline]
    pub fn as_keypair(&self) -> &Keypair { &self.0 }

    /// Returns the [`TweakedPublicKey`] and its [`Parity`] for this [`TweakedKeypair`].
    #[inline]
    pub fn public_parts(&self) -> (TweakedPublicKey, Parity) {
        let (xonly, parity) = self.0.x_only_public_key();
        (TweakedPublicKey(xonly.into()), parity)
    }
}

impl From<TweakedPublicKey> for XOnlyPublicKey {
    #[inline]
    fn from(pair: TweakedPublicKey) -> Self { pair.0 }
}

impl From<TweakedKeypair> for Keypair {
    #[inline]
    fn from(pair: TweakedKeypair) -> Self { pair.0 }
}

impl From<TweakedKeypair> for TweakedPublicKey {
    #[inline]
    fn from(pair: TweakedKeypair) -> Self { Self::from_keypair(pair) }
}

/// Error returned while generating key from slice.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FromSliceError {
    /// Invalid key prefix error.
    InvalidKeyPrefix(u8),
    /// A secp256k1 error.
    Secp256k1(secp256k1::Error),
    /// Invalid Length of the slice.
    InvalidLength(usize),
}

impl From<Infallible> for FromSliceError {
    fn from(never: Infallible) -> Self { match never {} }
}

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
impl std::error::Error for FromSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use FromSliceError::*;

        match *self {
            Secp256k1(ref e) => Some(e),
            InvalidKeyPrefix(_) | InvalidLength(_) => None,
        }
    }
}

impl From<secp256k1::Error> for FromSliceError {
    fn from(e: secp256k1::Error) -> Self { Self::Secp256k1(e) }
}

/// Error generated from WIF key format.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FromWifError {
    /// A base58 decoding error.
    Base58(base58::Error),
    /// Base58 decoded data was an invalid length.
    InvalidBase58PayloadLength(InvalidBase58PayloadLengthError),
    /// Base58 decoded data contained an invalid address version byte.
    InvalidAddressVersion(InvalidAddressVersionError),
    /// A secp256k1 error.
    Secp256k1(secp256k1::Error),
    /// Invalid WIF compression flag.
    InvalidWifCompressionFlag(InvalidWifCompressionFlagError),
}

impl From<Infallible> for FromWifError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for FromWifError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use FromWifError::*;

        match *self {
            Base58(ref e) => write_err!(f, "invalid base58"; e),
            InvalidBase58PayloadLength(ref e) =>
                write_err!(f, "decoded base58 data was an invalid length"; e),
            InvalidAddressVersion(ref e) =>
                write_err!(f, "decoded base58 data contained an invalid address version byte"; e),
            Secp256k1(ref e) => write_err!(f, "private key validation failed"; e),
            InvalidWifCompressionFlag(ref e) => write_err!(f, "invalid WIF compression flag"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromWifError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use FromWifError::*;

        match *self {
            Base58(ref e) => Some(e),
            InvalidBase58PayloadLength(ref e) => Some(e),
            InvalidAddressVersion(ref e) => Some(e),
            Secp256k1(ref e) => Some(e),
            InvalidWifCompressionFlag(ref e) => Some(e),
        }
    }
}

impl From<base58::Error> for FromWifError {
    fn from(e: base58::Error) -> Self { Self::Base58(e) }
}

impl From<secp256k1::Error> for FromWifError {
    fn from(e: secp256k1::Error) -> Self { Self::Secp256k1(e) }
}

impl From<InvalidBase58PayloadLengthError> for FromWifError {
    fn from(e: InvalidBase58PayloadLengthError) -> Self { Self::InvalidBase58PayloadLength(e) }
}

impl From<InvalidAddressVersionError> for FromWifError {
    fn from(e: InvalidAddressVersionError) -> Self { Self::InvalidAddressVersion(e) }
}

impl From<InvalidWifCompressionFlagError> for FromWifError {
    fn from(e: InvalidWifCompressionFlagError) -> Self { Self::InvalidWifCompressionFlag(e) }
}

/// Error returned while constructing public key from string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsePublicKeyError {
    /// Error originated while parsing string.
    Encoding(FromSliceError),
    /// Hex decoding error.
    InvalidChar(hex::InvalidCharError),
    /// `PublicKey` hex should be 66 or 130 digits long.
    InvalidHexLength(usize),
}

impl From<Infallible> for ParsePublicKeyError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for ParsePublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParsePublicKeyError::*;
        match *self {
            Encoding(ref e) => write_err!(f, "string error"; e),
            InvalidChar(ref e) => write_err!(f, "hex decoding"; e),
            InvalidHexLength(got) =>
                write!(f, "pubkey string should be 66 or 130 digits long, got: {}", got),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParsePublicKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParsePublicKeyError::*;

        match *self {
            Encoding(ref e) => Some(e),
            InvalidChar(ref e) => Some(e),
            InvalidHexLength(_) => None,
        }
    }
}

impl From<FromSliceError> for ParsePublicKeyError {
    fn from(e: FromSliceError) -> Self { Self::Encoding(e) }
}

/// Error returned when parsing a [`CompressedPublicKey`] from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseCompressedPublicKeyError {
    /// secp256k1 Error.
    Secp256k1(secp256k1::Error),
    /// hex to array conversion error.
    Hex(hex::HexToArrayError),
}

impl From<Infallible> for ParseCompressedPublicKeyError {
    fn from(never: Infallible) -> Self { match never {} }
}

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
impl std::error::Error for ParseCompressedPublicKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseCompressedPublicKeyError::*;

        match self {
            Secp256k1(e) => Some(e),
            Hex(e) => Some(e),
        }
    }
}

impl From<secp256k1::Error> for ParseCompressedPublicKeyError {
    fn from(e: secp256k1::Error) -> Self { Self::Secp256k1(e) }
}

impl From<hex::HexToArrayError> for ParseCompressedPublicKeyError {
    fn from(e: hex::HexToArrayError) -> Self { Self::Hex(e) }
}

/// SegWit public keys must always be compressed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UncompressedPublicKeyError;

impl fmt::Display for UncompressedPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("SegWit public keys must always be compressed")
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

/// Invalid compression flag for a WIF key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidWifCompressionFlagError {
    /// The invalid compression flag.
    pub(crate) invalid: u8,
}

impl InvalidWifCompressionFlagError {
    /// Returns the invalid compression flag.
    pub fn invalid_compression_flag(&self) -> u8 { self.invalid }
}

impl fmt::Display for InvalidWifCompressionFlagError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid WIF compression flag. Expected a 0x01 byte at the end of the key but found: {}", self.invalid)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidWifCompressionFlagError {}

mod serialized_x_only {
    internals::transparent_newtype! {
        /// An array of bytes that's semantically an x-only public but was **not** validated.
        ///
        /// This can be useful when validation is not desired but semantics of the bytes should be
        /// preserved. The validation can still happen using `to_validated()` method.
        #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct SerializedXOnlyPublicKey([u8; 32]);

        impl SerializedXOnlyPublicKey {
            pub(crate) fn from_bytes_ref(bytes: &_) -> Self;
        }
    }

    impl SerializedXOnlyPublicKey {
        /// Marks the supplied bytes as a serialized x-only public key.
        pub const fn from_byte_array(bytes: [u8; 32]) -> Self { Self(bytes) }

        /// Returns the raw bytes.
        pub const fn to_byte_array(self) -> [u8; 32] { self.0 }

        /// Returns a reference to the raw bytes.
        pub const fn as_byte_array(&self) -> &[u8; 32] { &self.0 }
    }
}

impl SerializedXOnlyPublicKey {
    /// Returns `XOnlyPublicKey` if the bytes are valid.
    pub fn to_validated(self) -> Result<XOnlyPublicKey, ParseXOnlyPublicKeyError> {
        XOnlyPublicKey::from_byte_array(self.as_byte_array())
    }
}

impl AsRef<[u8; 32]> for SerializedXOnlyPublicKey {
    fn as_ref(&self) -> &[u8; 32] { self.as_byte_array() }
}

impl From<&Self> for SerializedXOnlyPublicKey {
    fn from(borrowed: &Self) -> Self { *borrowed }
}

impl fmt::Debug for SerializedXOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.as_byte_array().as_hex(), f)
    }
}

/// Error that can occur when parsing an [`XOnlyPublicKey`] from bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseXOnlyPublicKeyError {
    /// The provided bytes do not represent a valid secp256k1 point x-coordinate.
    InvalidXCoordinate,
}

impl fmt::Display for ParseXOnlyPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidXCoordinate => write!(f, "Invalid X coordinate for secp256k1 point"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseXOnlyPublicKeyError {}

/// Error that can occur when tweaking an [`XOnlyPublicKey`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TweakXOnlyPublicKeyError {
    /// The tweak value was invalid.
    BadTweak,
    /// The resulting public key would be invalid.
    ResultKeyInvalid,
    /// Invalid parity value encountered during the operation.
    ParityError,
}

impl fmt::Display for TweakXOnlyPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BadTweak => write!(f, "Invalid tweak value"),
            Self::ResultKeyInvalid => write!(f, "Resulting public key would be invalid"),
            Self::ParityError => write!(f, "Invalid parity value encountered"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TweakXOnlyPublicKeyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;

    #[test]
    fn key_derivation() {
        // mainnet compressed WIF with invalid compression flag.
        let sk = PrivateKey::from_wif("L2x4uC2YgfFWZm9tF4pjDnVR6nJkheizFhEr2KvDNnTEmEqVzPJY");
        assert!(matches!(
            sk,
            Err(FromWifError::InvalidWifCompressionFlag(InvalidWifCompressionFlagError {
                invalid: 49
            }))
        ));

        // testnet compressed
        let sk =
            PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
        assert_eq!(sk.network, NetworkKind::Test);
        assert!(sk.compressed);
        assert_eq!(&sk.to_wif(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");

        let secp = Secp256k1::new();
        let pk = Address::p2pkh(sk.public_key(&secp), sk.network);
        assert_eq!(&pk.to_string(), "mqwpxxvfv3QbM8PU8uBx2jaNt9btQqvQNx");

        // test string conversion
        assert_eq!(&sk.to_string(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");
        let sk_str =
            "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy".parse::<PrivateKey>().unwrap();
        assert_eq!(&sk.to_wif(), &sk_str.to_wif());

        // mainnet uncompressed
        let sk =
            PrivateKey::from_wif("5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3").unwrap();
        assert_eq!(sk.network, NetworkKind::Main);
        assert!(!sk.compressed);
        assert_eq!(&sk.to_wif(), "5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3");

        let secp = Secp256k1::new();
        let mut pk = sk.public_key(&secp);
        assert!(!pk.compressed);
        assert_eq!(&pk.to_string(), "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133");
        assert_eq!(pk, "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133"
        .parse::<PublicKey>().unwrap());
        let addr = Address::p2pkh(pk, sk.network);
        assert_eq!(&addr.to_string(), "1GhQvF6dL8xa6wBxLnWmHcQsurx9RxiMc8");
        pk.compressed = true;
        assert_eq!(
            &pk.to_string(),
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
        );
        assert_eq!(
            pk,
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
                .parse::<PublicKey>()
                .unwrap()
        );
    }

    #[test]
    fn pubkey_hash() {
        let pk = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
            .parse::<PublicKey>()
            .unwrap();
        let upk = "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133"
        .parse::<PublicKey>().unwrap();
        assert_eq!(pk.pubkey_hash().to_string(), "9511aa27ef39bbfa4e4f3dd15f4d66ea57f475b4");
        assert_eq!(upk.pubkey_hash().to_string(), "ac2e7daf42d2c97418fd9f78af2de552bb9c6a7a");
    }

    #[test]
    fn wpubkey_hash() {
        let pk = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
            .parse::<PublicKey>()
            .unwrap();
        let upk = "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133".parse::<PublicKey>().unwrap();
        assert_eq!(
            pk.wpubkey_hash().unwrap().to_string(),
            "9511aa27ef39bbfa4e4f3dd15f4d66ea57f475b4"
        );
        assert!(upk.wpubkey_hash().is_err());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn skey_serde() {
        use serde_test::{assert_tokens, Configure, Token};

        static KEY_WIF: &str = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";
        static PK_STR: &str = "039b6347398505f5ec93826dc61c19f47c66c0283ee9be980e29ce325a0f4679ef";
        static PK_STR_U: &str = "\
            04\
            9b6347398505f5ec93826dc61c19f47c66c0283ee9be980e29ce325a0f4679ef\
            87288ed73ce47fc4f5c79d19ebfa57da7cff3aff6e819e4ee971d86b5e61875d\
        ";
        #[rustfmt::skip]
        static PK_BYTES: [u8; 33] = [
            0x03,
            0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec,
            0x93, 0x82, 0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c,
            0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0x0e,
            0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
        ];
        #[rustfmt::skip]
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
        let sk = KEY_WIF.parse::<PrivateKey>().unwrap();
        let pk = PublicKey::from_private_key(&s, sk);
        let pk_u = PublicKey { inner: pk.inner, compressed: false };

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

        let mut reader = v.as_slice();
        let mut dec_keys = vec![];
        for _ in 0..N_KEYS {
            dec_keys.push(PublicKey::read_from(&mut reader).expect("reading from vec"));
        }
        assert_eq!(keys, dec_keys);
        assert!(PublicKey::read_from(&mut reader).is_err());

        // sanity checks
        let mut empty: &[u8] = &[];
        assert!(PublicKey::read_from(&mut empty).is_err());
        assert!(PublicKey::read_from(&mut &[0; 33][..]).is_err());
        assert!(PublicKey::read_from(&mut &[2; 32][..]).is_err());
        assert!(PublicKey::read_from(&mut &[0; 65][..]).is_err());
        assert!(PublicKey::read_from(&mut &[4; 64][..]).is_err());
    }

    #[test]
    fn pubkey_to_sort_key() {
        let key1 = "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8"
            .parse::<PublicKey>()
            .unwrap();
        let key2 = PublicKey { inner: key1.inner, compressed: false };
        let arrayvec1 = ArrayVec::from_slice(
            &<[u8; 33]>::from_hex(
                "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
            )
            .unwrap(),
        );
        let expected1 = SortKey(arrayvec1);
        let arrayvec2 = ArrayVec::from_slice(&<[u8; 65]>::from_hex(
            "04ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f81794e7f3d5e420641a3bc690067df5541470c966cbca8c694bf39aa16d836918",
        ).unwrap());
        let expected2 = SortKey(arrayvec2);
        assert_eq!(key1.to_sort_key(), expected1);
        assert_eq!(key2.to_sort_key(), expected2);
    }

    #[test]
    fn pubkey_sort() {
        struct Vector {
            input: Vec<PublicKey>,
            expect: Vec<PublicKey>,
        }
        let fmt = |v: Vec<_>| {
            v.into_iter().map(|s: &str| s.parse::<PublicKey>().unwrap()).collect::<Vec<_>>()
        };
        let vectors = vec![
            // Start BIP-0067 vectors
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
            vector.input.sort_by_cached_key(|k| PublicKey::to_sort_key(*k));
            assert_eq!(vector.input, vector.expect);
        }
    }

    #[test]
    #[cfg(feature = "rand-std")]
    fn public_key_constructors() {
        use secp256k1::rand;

        let secp = Secp256k1::new();
        let kp = Keypair::new(&secp, &mut rand::thread_rng());

        let _ = PublicKey::new(kp);
        let _ = PublicKey::new_uncompressed(kp);
    }

    #[test]
    fn public_key_from_str_wrong_length() {
        // Sanity checks, we accept string length 130 digits.
        let s = "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133";
        assert_eq!(s.len(), 130);
        assert!(s.parse::<PublicKey>().is_ok());
        // And 66 digits.
        let s = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af";
        assert_eq!(s.len(), 66);
        assert!(s.parse::<PublicKey>().is_ok());

        let s = "aoeusthb";
        assert_eq!(s.len(), 8);
        let res = s.parse::<PublicKey>();
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), ParsePublicKeyError::InvalidHexLength(8));
    }

    #[test]
    fn public_key_from_str_invalid_str() {
        // Ensuring test cases fail when PublicKey::from_str is used on invalid keys
        let s = "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b142";
        assert_eq!(s.len(), 130);
        let res = s.parse::<PublicKey>();
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ParsePublicKeyError::Encoding(FromSliceError::Secp256k1(
                secp256k1::Error::InvalidPublicKey
            ))
        );

        let s = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd169";
        assert_eq!(s.len(), 66);
        let res = s.parse::<PublicKey>();
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ParsePublicKeyError::Encoding(FromSliceError::Secp256k1(
                secp256k1::Error::InvalidPublicKey
            ))
        );

        let s = "062e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133";
        assert_eq!(s.len(), 130);
        let res = s.parse::<PublicKey>();
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ParsePublicKeyError::Encoding(FromSliceError::InvalidKeyPrefix(6))
        );

        let s = "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b13g";
        assert_eq!(s.len(), 130);
        let res = s.parse::<PublicKey>();
        assert!(res.is_err());
        if let Err(ParsePublicKeyError::InvalidChar(err)) = res {
            assert_eq!(err.invalid_char(), b'g');
            assert_eq!(err.pos(), 129);
        } else {
            panic!("expected ParsePublicKeyError::InvalidChar");
        }

        let s = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1ag";
        assert_eq!(s.len(), 66);
        let res = s.parse::<PublicKey>();
        assert!(res.is_err());
        if let Err(ParsePublicKeyError::InvalidChar(err)) = res {
            assert_eq!(err.invalid_char(), b'g');
            assert_eq!(err.pos(), 65);
        } else {
            panic!("expected ParsePublicKeyError::InvalidChar");
        }
    }

    #[test]
    #[allow(deprecated)] // tests the deprecated function
    #[allow(deprecated_in_future)]
    fn invalid_private_key_len() {
        use crate::Network;
        assert!(PrivateKey::from_slice(&[1u8; 31], Network::Regtest).is_err());
        assert!(PrivateKey::from_slice(&[1u8; 33], Network::Regtest).is_err());
    }

    #[test]
    fn xonly_pubkey_from_bytes() {
        let key_bytes = &<[u8; 32]>::from_hex(
            "5b1e57ec453cd33fdc7cfc901450a3931fd315422558f2fb7fefb064e6e7d60d",
        )
        .expect("Failed to convert hex string to byte array");
        let xonly_pub_key = XOnlyPublicKey::from_byte_array(key_bytes)
            .expect("Failed to create an XOnlyPublicKey from a byte array");
        // Confirm that the public key from bytes serializes back to the same bytes
        assert_eq!(&xonly_pub_key.serialize(), key_bytes);
    }

    #[test]
    fn xonly_pubkey_into_inner() {
        let key_bytes = &<[u8; 32]>::from_hex(
            "5b1e57ec453cd33fdc7cfc901450a3931fd315422558f2fb7fefb064e6e7d60d",
        )
        .expect("Failed to convert hex string to byte array");
        let inner_key = secp256k1::XOnlyPublicKey::from_byte_array(key_bytes)
            .expect("Failed to create a secp256k1 x-only public key from a byte array");
        let btc_pubkey = XOnlyPublicKey::new(inner_key);
        // Confirm that the into_inner() returns the same data that was initially wrapped
        assert_eq!(inner_key, btc_pubkey.into_inner());
    }
}
