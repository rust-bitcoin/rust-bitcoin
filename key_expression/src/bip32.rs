// SPDX-License-Identifier: CC0-1.0

//! BIP-0032 implementation.
//!
//! Implementation of BIP-0032 hierarchical deterministic wallets, as defined
//! at <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>.

use alloc::vec;
use alloc::vec::Vec;
use core::ops::Index;
use core::str::FromStr;
use core::{fmt, slice};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use crypto::key::{FullPublicKey, Keypair, PrivateKey, XOnlyPublicKey};
use hashes::{hash160, hash_newtype, sha256, sha512, Hash, HashEngine, Hmac, HmacEngine};
use internals::array::ArrayExt;
use network::NetworkKind;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(no_inline)]
pub use self::error::{
    DerivationError, IndexOutOfRangeError, InvalidBase58PayloadLengthError,
    ParseChildNumberError, ParseDerivationPathError, ParseError, InvalidSeedLengthError
};

/// Version bytes for extended public keys on the Bitcoin network.
const VERSION_BYTES_MAINNET_PUBLIC: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
/// Version bytes for extended private keys on the Bitcoin network.
const VERSION_BYTES_MAINNET_PRIVATE: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
/// Version bytes for extended public keys on any of the testnet networks.
const VERSION_BYTES_TESTNETS_PUBLIC: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];
/// Version bytes for extended private keys on any of the testnet networks.
const VERSION_BYTES_TESTNETS_PRIVATE: [u8; 4] = [0x04, 0x35, 0x83, 0x94];

/// The old name for xpub, extended public key.
#[deprecated(since = "0.31.0", note = "use `Xpub` instead")]
pub type ExtendedPubKey = Xpub;

/// The old name for xpriv, extended private key.
#[deprecated(since = "0.31.0", note = "use `Xpriv` instead")]
pub type ExtendedPrivKey = Xpriv;

/// A chain code
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainCode([u8; 32]);
internals::impl_array_newtype!(ChainCode, u8, 32);
crate::impl_array_newtype_stringify!(ChainCode, 32);

impl ChainCode {
    fn from_hmac(hmac: Hmac<sha512::Hash>) -> Self {
        Self(*hmac.as_byte_array().split_array::<32, 32>().1)
    }

    /// Copies the underlying bytes into a new `Vec`.
    #[inline]
    #[deprecated(since = "TBD", note = "use to_vec instead")]
    pub fn to_bytes(self) -> alloc::vec::Vec<u8> { self.to_vec() }
}

/// A fingerprint
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Fingerprint([u8; 4]);
internals::impl_array_newtype!(Fingerprint, u8, 4);
crate::impl_array_newtype_stringify!(Fingerprint, 4);

hash_newtype! {
    /// Extended key identifier as defined in BIP-0032.
    pub struct XKeyIdentifier(hash160::Hash);
}

hashes::impl_hex_for_newtype!(XKeyIdentifier);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(XKeyIdentifier);

crate::transparent_newtype! {
    /// A master seed validated according to BIP-0032 specifications.
    ///
    /// Construct from a fixed-size array reference via [`From`] when the byte length is known at
    /// compile time, or from an arbitrary slice via [`TryFrom`] which performs the length check.
    pub struct Bip32Seed([u8]);

    impl Bip32Seed {
        const fn from_slice_unchecked(bytes: &_) -> &Self;
    }
}

impl Bip32Seed {
    /// Minimum seed length in bytes (128 bits).
    pub const MIN_LEN: usize = 16;
    /// Maximum seed length in bytes (512 bits).
    pub const MAX_LEN: usize = 64;

    /// Returns the seed bytes.
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
}

impl AsRef<[u8]> for Bip32Seed {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl AsRef<Self> for Bip32Seed {
    fn as_ref(&self) -> &Self { self }
}

impl<'a> TryFrom<&'a [u8]> for &'a Bip32Seed {
    type Error = InvalidSeedLengthError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let len = bytes.len();
        if len < Bip32Seed::MIN_LEN || len > Bip32Seed::MAX_LEN {
            return Err(InvalidSeedLengthError { length: len });
        }
        Ok(Bip32Seed::from_slice_unchecked(bytes))
    }
}

impl fmt::Debug for Bip32Seed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hash = sha256::Hash::hash(self.as_bytes());
        let id = u32::from_be_bytes(*hash.as_byte_array().sub_array::<0, 4>());
        write!(f, "Bip32Seed(sha256={:08x})", id)
    }
}

impl PartialEq for Bip32Seed {
    fn eq(&self, other: &Self) -> bool {
        let a = self.as_bytes();
        let b = other.as_bytes();
        a.len() == b.len() && hashes::cmp::fixed_time_eq(a, b)
    }
}

macro_rules! impl_bip32_seed_from_array {
    ($($n:literal),+ $(,)?) => {
        $(
            impl<'a> From<&'a [u8; $n]> for &'a Bip32Seed {
                fn from(arr: &'a [u8; $n]) -> Self { Bip32Seed::from_slice_unchecked(arr) }
            }

            impl AsRef<Bip32Seed> for [u8; $n] {
                fn as_ref(&self) -> &Bip32Seed { self.into() }
            }
        )+
    };
}

impl_bip32_seed_from_array!(
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
    40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    64,
);

/// Extended private key
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Xpriv {
    /// The network this key is to be used on
    pub network: NetworkKind,
    /// How many derivations this key is from the master (which is 0)
    pub depth: u8,
    /// Fingerprint of the parent key (0 for master)
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_number: ChildNumber,
    /// Private key
    pub private_key: secp256k1::SecretKey,
    /// Chain code
    pub chain_code: ChainCode,
}
#[cfg(feature = "serde")]
internals::serde_string_impl!(Xpriv, "a BIP-0032 extended private key");

#[cfg(not(feature = "std"))]
impl fmt::Debug for Xpriv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Xpriv")
            .field("network", &self.network)
            .field("depth", &self.depth)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .field("child_number", &self.child_number)
            .field("chain_code", &self.chain_code)
            .field("private_key", &"[SecretKey]")
            .finish()
    }
}

/// Extended public key
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct Xpub {
    /// The network kind this key is to be used on
    pub network: NetworkKind,
    /// How many derivations this key is from the master (which is 0)
    pub depth: u8,
    /// Fingerprint of the parent key
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_number: ChildNumber,
    /// Public key
    pub public_key: secp256k1::PublicKey,
    /// Chain code
    pub chain_code: ChainCode,
}
#[cfg(feature = "serde")]
internals::serde_string_impl!(Xpub, "a BIP-0032 extended public key");

/// Flag with the hardened bit turned on.
const HARDENED_FLAG: u32 = 1 << 31;

/// The highest valid child index.
const MAX_CHILD_INDEX: u32 = HARDENED_FLAG - 1;

/// A child number for a derived key.
///
/// The high bit marks whether the index is hardened and the remaining bits
/// store the actual index.
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct ChildNumber(u32);

impl ChildNumber {
    /// Normal child number with index 0.
    pub const ZERO_NORMAL: Self = Self(0);

    /// Normal child number with index 1.
    pub const ONE_NORMAL: Self = Self(1);

    /// Hardened child number with index 0.
    pub const ZERO_HARDENED: Self = Self(HARDENED_FLAG);

    /// Hardened child number with index 1.
    pub const ONE_HARDENED: Self = Self(HARDENED_FLAG | 1);

    /// Constructs a new normal child number from an index.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is not within [0, 2^31 - 1].
    pub fn from_normal_idx(index: u32) -> Result<Self, IndexOutOfRangeError> {
        if index <= MAX_CHILD_INDEX {
            Ok(Self(index))
        } else {
            Err(IndexOutOfRangeError { index })
        }
    }

    /// Constructs a new hardened child number from an index.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is not within [0, 2^31 - 1].
    pub fn from_hardened_idx(index: u32) -> Result<Self, IndexOutOfRangeError> {
        if index <= MAX_CHILD_INDEX {
            Ok(Self(index | HARDENED_FLAG))
        } else {
            Err(IndexOutOfRangeError { index })
        }
    }

    /// Constructs a child number from its raw BIP-0032 representation.
    ///
    /// The raw representation includes the hardened bit. Use [`Self::from_normal_idx`] or
    /// [`Self::from_hardened_idx`] to construct a child number from an index.
    pub fn from_raw(raw: u32) -> Self { Self(raw) }

    /// Returns the raw BIP-0032 representation.
    ///
    /// The raw representation includes the hardened bit. Use [`Self::index`] to get the child
    /// index without the hardened bit.
    pub fn to_raw(self) -> u32 { self.0 }

    /// Returns the child index, without the hardened bit.
    pub fn index(self) -> u32 { self.0 & MAX_CHILD_INDEX }

    /// Returns `true` if the child number is not hardened.
    pub fn is_normal(&self) -> bool { !self.is_hardened() }

    /// Returns `true` if the child number is hardened.
    pub fn is_hardened(&self) -> bool { self.0 & HARDENED_FLAG != 0 }

    /// Returns the child number that is a single increment from this one.
    ///
    /// # Errors
    ///
    /// Returns an error if the index after incrementing will be outside the range [0, 2^31 - 1].
    pub fn increment(self) -> Result<Self, IndexOutOfRangeError> {
        let index = self.index();
        let next = index.checked_add(1).ok_or(IndexOutOfRangeError { index })?;
        if self.is_hardened() {
            Self::from_hardened_idx(next)
        } else {
            Self::from_normal_idx(next)
        }
    }

    /// Formats the child number using the provided formatting function.
    ///
    /// For hardened child numbers appends a `'` or `hardened_alt_suffix`
    /// depending on the formatter.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the formatter fails.
    fn format_with<F>(
        self,
        f: &mut fmt::Formatter,
        format_fn: F,
        hardened_alt_suffix: &str,
    ) -> fmt::Result
    where
        F: Fn(&u32, &mut fmt::Formatter) -> fmt::Result,
    {
        let index = self.index();
        if self.is_hardened() {
            format_fn(&index, f)?;
            let alt = f.alternate();
            f.write_str(if alt { hardened_alt_suffix } else { "'" })
        } else {
            format_fn(&index, f)
        }
    }
}

impl From<ChildNumber> for u32 {
    fn from(number: ChildNumber) -> Self { number.to_raw() }
}

impl From<u32> for ChildNumber {
    fn from(number: u32) -> Self { Self::from_raw(number) }
}

impl fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.format_with(f, fmt::Display::fmt, "h")
    }
}

impl fmt::LowerHex for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.format_with(f, fmt::LowerHex::fmt, "h")
    }
}

impl fmt::UpperHex for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.format_with(f, fmt::UpperHex::fmt, "H")
    }
}

impl fmt::Octal for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.format_with(f, fmt::Octal::fmt, "h")
    }
}

impl fmt::Binary for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.format_with(f, fmt::Binary::fmt, "h")
    }
}

impl FromStr for ChildNumber {
    type Err = ParseChildNumberError;

    fn from_str(inp: &str) -> Result<Self, Self::Err> {
        let is_hardened = inp.chars().last().is_some_and(|l| l == '\'' || l == 'h');
        Ok(if is_hardened {
            Self::from_hardened_idx(
                inp[0..inp.len() - 1].parse().map_err(ParseChildNumberError::ParseInt)?,
            )
            .map_err(ParseChildNumberError::IndexOutOfRange)?
        } else {
            Self::from_normal_idx(inp.parse().map_err(ParseChildNumberError::ParseInt)?)
                .map_err(ParseChildNumberError::IndexOutOfRange)?
        })
    }
}

impl AsRef<[Self]> for ChildNumber {
    fn as_ref(&self) -> &[Self] { slice::from_ref(self) }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ChildNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u32::deserialize(deserializer).map(Self::from)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ChildNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        u32::from(*self).serialize(serializer)
    }
}

/// A relative BIP-0032 derivation path.
#[derive(Default, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct RelativeDerivationPath(Vec<ChildNumber>);

#[cfg(feature = "serde")]
internals::serde_string_impl!(RelativeDerivationPath, "a relative BIP-0032 derivation path");

impl<I> Index<I> for RelativeDerivationPath
where
    Vec<ChildNumber>: Index<I>,
{
    type Output = <Vec<ChildNumber> as Index<I>>::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output { &self.0[index] }
}

impl From<Vec<ChildNumber>> for RelativeDerivationPath {
    fn from(numbers: Vec<ChildNumber>) -> Self { Self(numbers) }
}

impl From<RelativeDerivationPath> for Vec<ChildNumber> {
    fn from(path: RelativeDerivationPath) -> Self { path.0 }
}

impl<'a> From<&'a [ChildNumber]> for RelativeDerivationPath {
    fn from(numbers: &'a [ChildNumber]) -> Self { Self(numbers.to_vec()) }
}

impl core::iter::FromIterator<ChildNumber> for RelativeDerivationPath {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = ChildNumber>,
    {
        Self(Vec::from_iter(iter))
    }
}

#[allow(clippy::into_iter_without_iter)]
impl<'a> core::iter::IntoIterator for &'a RelativeDerivationPath {
    type Item = &'a ChildNumber;
    type IntoIter = slice::Iter<'a, ChildNumber>;
    fn into_iter(self) -> Self::IntoIter { self.0.iter() }
}

impl AsRef<[ChildNumber]> for RelativeDerivationPath {
    fn as_ref(&self) -> &[ChildNumber] { &self.0 }
}

impl FromStr for RelativeDerivationPath {
    type Err = ParseDerivationPathError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        if path.is_empty() {
            return Ok(vec![].into());
        }

        if path == "m" || path.starts_with("m/") {
            return Err(ParseDerivationPathError::UnexpectedMasterPrefix);
        }

        let mut ret = Vec::new();
        for part in path.split('/') {
            if part.is_empty() {
                return Err(ParseDerivationPathError::EmptyChild);
            }
            ret.push(part.parse()?);
        }
        Ok(Self(ret))
    }
}

/// An absolute BIP-0032 derivation path, starting at the master key.
///
/// Conversion to [`RelativeDerivationPath`] is available through
/// [`AbsoluteDerivationPath::as_relative`] or
/// [`AbsoluteDerivationPath::into_relative`].
///
/// The leading `m` in BIP-0032 notation has historically been subtle in this crate:
/// See [PR #2451] and [PR #2677] for prior discussion on the "m/" notation.
///
/// [PR #2451]: https://github.com/rust-bitcoin/rust-bitcoin/pull/2451
/// [PR #2677]: https://github.com/rust-bitcoin/rust-bitcoin/pull/2677
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct AbsoluteDerivationPath(RelativeDerivationPath);

#[cfg(feature = "serde")]
internals::serde_string_impl!(AbsoluteDerivationPath, "an absolute BIP-0032 derivation path");

impl AbsoluteDerivationPath {
    /// Returns the absolute derivation path for a master key.
    pub fn master() -> Self { Self(RelativeDerivationPath::default()) }

    /// Returns `true` if this is the master path.
    pub fn is_master(&self) -> bool { self.0.is_empty() }

    /// Returns the relative path below the master key.
    pub fn as_relative(&self) -> &RelativeDerivationPath { &self.0 }

    /// Converts this absolute path into the relative path below the master key.
    pub fn into_relative(self) -> RelativeDerivationPath { self.0 }

    /// Returns length of the relative derivation path below the master key.
    pub fn len(&self) -> usize { self.0.len() }

    /// Returns `true` if this is the master path.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Returns `true` if the relative path below the master key contains a hardened child number.
    pub fn contains_hardened_child(&self) -> bool { self.0.contains_hardened_child() }

    /// Joins `self` with `path` and returns the resulting new path.
    #[must_use]
    pub fn join<T: AsRef<[ChildNumber]>>(&self, path: T) -> Self { Self(self.0.join(path)) }
}

impl Default for AbsoluteDerivationPath {
    fn default() -> Self { Self::master() }
}

impl FromStr for AbsoluteDerivationPath {
    type Err = ParseDerivationPathError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        if path == "m" {
            return Ok(Self::master());
        }

        let path = path.strip_prefix("m/").ok_or(ParseDerivationPathError::MissingMasterPrefix)?;
        if path.is_empty() {
            return Err(ParseDerivationPathError::EmptyChild);
        }

        Ok(Self(path.parse()?))
    }
}

impl fmt::Display for AbsoluteDerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("m")?;
        if !self.0.is_empty() {
            f.write_str("/")?;
            if f.alternate() {
                write!(f, "{:#}", self.0)?;
            } else {
                write!(f, "{}", self.0)?;
            }
        }
        Ok(())
    }
}

impl From<RelativeDerivationPath> for AbsoluteDerivationPath {
    fn from(path: RelativeDerivationPath) -> Self { Self(path) }
}

impl From<AbsoluteDerivationPath> for RelativeDerivationPath {
    fn from(path: AbsoluteDerivationPath) -> Self { path.0 }
}

/// An iterator over children of a [`RelativeDerivationPath`].
///
/// It is returned by the methods [`RelativeDerivationPath::children_from`],
/// [`RelativeDerivationPath::normal_children`] and [`RelativeDerivationPath::hardened_children`].
pub struct RelativeDerivationPathIterator<'a> {
    base: &'a RelativeDerivationPath,
    next_child: Option<ChildNumber>,
}

impl<'a> RelativeDerivationPathIterator<'a> {
    /// Starts a new [`RelativeDerivationPathIterator`] at the given child.
    pub fn start_from(path: &'a RelativeDerivationPath, start: ChildNumber) -> Self {
        RelativeDerivationPathIterator { base: path, next_child: Some(start) }
    }
}

impl Iterator for RelativeDerivationPathIterator<'_> {
    type Item = RelativeDerivationPath;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.next_child?;
        self.next_child = ret.increment().ok();
        Some(self.base.child(ret))
    }
}

impl RelativeDerivationPath {
    /// Returns length of the derivation path
    pub fn len(&self) -> usize { self.0.len() }

    /// Returns `true` if the derivation path is empty
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Returns `true` if the derivation path contains a hardened child number.
    pub fn contains_hardened_child(&self) -> bool { self.0.iter().any(ChildNumber::is_hardened) }

    /// Constructs a new [`RelativeDerivationPath`] that is a child of this one.
    #[must_use]
    pub fn child(&self, cn: ChildNumber) -> Self {
        let mut path = self.0.clone();
        path.push(cn);
        Self(path)
    }

    /// Converts into a [`RelativeDerivationPath`] that is a child of this one.
    #[must_use]
    pub fn into_child(self, cn: ChildNumber) -> Self {
        let mut path = self.0;
        path.push(cn);
        Self(path)
    }

    /// Gets an [Iterator] over the children of this [`RelativeDerivationPath`]
    /// starting with the given [`ChildNumber`].
    pub fn children_from(&self, cn: ChildNumber) -> RelativeDerivationPathIterator<'_> {
        RelativeDerivationPathIterator::start_from(self, cn)
    }

    /// Gets an [Iterator] over the unhardened children of this [`RelativeDerivationPath`].
    pub fn normal_children(&self) -> RelativeDerivationPathIterator<'_> {
        RelativeDerivationPathIterator::start_from(self, ChildNumber::ZERO_NORMAL)
    }

    /// Gets an [Iterator] over the hardened children of this [`RelativeDerivationPath`].
    pub fn hardened_children(&self) -> RelativeDerivationPathIterator<'_> {
        RelativeDerivationPathIterator::start_from(self, ChildNumber::ZERO_HARDENED)
    }

    /// Joins `self` with `path` and returns the resulting new path.
    ///
    /// ```
    /// use bitcoin_key_expression::bip32::{RelativeDerivationPath, ChildNumber};
    ///
    /// let base = "42".parse::<RelativeDerivationPath>().unwrap();
    ///
    /// let deriv_1 = base.join("0/1".parse::<RelativeDerivationPath>().unwrap());
    /// let deriv_2 = base.join(&[
    ///     ChildNumber::ZERO_NORMAL,
    ///     ChildNumber::ONE_NORMAL
    /// ]);
    ///
    /// assert_eq!(deriv_1, deriv_2);
    /// ```
    #[must_use]
    pub fn join<T: AsRef<[ChildNumber]>>(&self, path: T) -> Self {
        let mut new_path = self.clone();
        new_path.0.extend_from_slice(path.as_ref());
        new_path
    }

    /// Returns the derivation path as a vector of raw BIP-0032 u32 child numbers.
    /// Unhardened elements are copied as is.
    /// 0x80000000 is added to the hardened elements.
    ///
    /// ```
    /// use bitcoin_key_expression::bip32::RelativeDerivationPath;
    ///
    /// let path = "84'/0'/0'/0/1".parse::<RelativeDerivationPath>().unwrap();
    /// const HARDENED: u32 = 0x80000000;
    /// assert_eq!(path.to_u32_vec(), vec![84 + HARDENED, HARDENED, HARDENED, 0, 1]);
    /// ```
    pub fn to_u32_vec(&self) -> Vec<u32> { self.into_iter().map(|&el| el.to_raw()).collect() }

    /// Constructs a new derivation path from a slice of raw BIP-0032 u32 child numbers.
    /// ```
    /// use bitcoin_key_expression::bip32::RelativeDerivationPath;
    ///
    /// const HARDENED: u32 = 0x80000000;
    /// let expected = vec![84 + HARDENED, HARDENED, HARDENED, 0, 1];
    /// let path = RelativeDerivationPath::from_u32_slice(expected.as_slice());
    /// assert_eq!(path.to_u32_vec(), expected);
    /// ```
    pub fn from_u32_slice(numbers: &[u32]) -> Self {
        numbers.iter().map(|&n| ChildNumber::from_raw(n)).collect()
    }
}

impl fmt::Display for RelativeDerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.0.iter();
        if let Some(first_element) = iter.next() {
            if f.alternate() {
                write!(f, "{:#}", first_element)?;
            } else {
                write!(f, "{}", first_element)?;
            }
        }
        for cn in iter {
            f.write_str("/")?;
            if f.alternate() {
                write!(f, "{:#}", cn)?;
            } else {
                write!(f, "{}", cn)?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for RelativeDerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self, f) }
}

/// Full information on the used extended public key: fingerprint of the
/// master extended public key and a derivation path from it.
pub type KeySource = (Fingerprint, RelativeDerivationPath);

impl Xpriv {
    /// Constructs a new master key from a [`Bip32Seed`].
    #[allow(clippy::missing_panics_doc)]
    pub fn new_master(network: impl Into<NetworkKind>, seed: impl AsRef<Bip32Seed>) -> Self {
        let mut engine = HmacEngine::<sha512::HashEngine>::new(b"Bitcoin seed");
        engine.input(seed.as_ref().as_bytes());
        let hmac = engine.finalize();

        Self {
            network: network.into(),
            depth: 0,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::ZERO_NORMAL,
            private_key: secp256k1::SecretKey::from_secret_bytes(
                *hmac.as_byte_array().split_array::<32, 32>().0,
            )
            .expect("cryptographically unreachable"),
            chain_code: ChainCode::from_hmac(hmac),
        }
    }

    /// Constructs a new ECDSA compressed private key matching internal secret key representation.
    #[deprecated(since = "TBD", note = "use `to_private_key()` instead")]
    pub fn to_priv(self) -> PrivateKey { self.to_private_key() }

    /// Constructs a new ECDSA compressed private key matching internal secret key representation.
    pub fn to_private_key(self) -> PrivateKey { PrivateKey::from_secp(self.private_key) }

    /// Constructs a new extended public key from this extended private key.
    pub fn to_xpub(self) -> Xpub { Xpub::from_xpriv(&self) }

    /// Constructs a new BIP-0340 keypair for Schnorr signatures and Taproot use matching the internal
    /// secret key representation.
    pub fn to_keypair(self) -> Keypair { Keypair::from_private_key(&self.to_private_key()) }

    /// Derives an extended private key from a path.
    ///
    /// The `path` argument can be both of type `RelativeDerivationPath` or `Vec<ChildNumber>`.
    ///
    /// # Errors
    ///
    /// See [`derive_xpriv`].
    ///
    /// [`derive_xpriv`]: Xpriv::derive_xpriv
    #[deprecated(since = "TBD", note = "use `derive_xpriv()` instead")]
    pub fn derive_priv<P: AsRef<[ChildNumber]>>(&self, path: P) -> Result<Self, DerivationError> {
        self.derive_xpriv(path)
    }

    /// Derives an extended private key from a path.
    ///
    /// The `path` argument can be both of type `RelativeDerivationPath` or `Vec<ChildNumber>`.
    ///
    /// # Errors
    ///
    /// Returns an error if the derived key exceeds the maximum key depth.
    pub fn derive_xpriv<P: AsRef<[ChildNumber]>>(&self, path: P) -> Result<Self, DerivationError> {
        let mut sk: Self = *self;
        for cnum in path.as_ref() {
            sk = sk.ckd_priv(*cnum)?;
        }
        Ok(sk)
    }

    /// Private->Private child key derivation
    fn ckd_priv(&self, i: ChildNumber) -> Result<Self, DerivationError> {
        let mut engine = HmacEngine::<sha512::HashEngine>::new(&self.chain_code[..]);
        if i.is_normal() {
            // Non-hardened key: compute public data and use that.
            engine.input(&secp256k1::PublicKey::from_secret_key(&self.private_key).serialize()[..]);
        } else {
            // Hardened key: use only secret data to prevent public derivation.
            engine.input(&[0u8]);
            engine.input(&self.private_key[..]);
        }

        engine.input(&u32::from(i).to_be_bytes());
        let hmac: Hmac<sha512::Hash> = engine.finalize();
        let sk = secp256k1::SecretKey::from_secret_bytes(
            *hmac.as_byte_array().split_array::<32, 32>().0,
        )
        .expect("statistically impossible to hit");
        let tweaked =
            sk.add_tweak(&self.private_key.into()).expect("statistically impossible to hit");

        Ok(Self {
            network: self.network,
            depth: self.depth.checked_add(1).ok_or(DerivationError::MaximumDepthExceeded)?,
            parent_fingerprint: self.fingerprint(),
            child_number: i,
            private_key: tweaked,
            chain_code: ChainCode::from_hmac(hmac),
        })
    }

    /// Decoding extended private key from binary data according to BIP-0032
    ///
    /// # Errors
    ///
    /// * [`ParseError::UnknownVersion`] if the decoded network value is not main or testnet.
    /// * [`ParseError::InvalidPrivateKeyPrefix`] if the private key bytes don't start with zero.
    /// * [`ParseError::Secp256k1`] if the private key bytes are not a valid secp secret key.
    /// * [`ParseError::WrongExtendedKeyLength`] if the data is not the correct length.
    /// * [`ParseError::NonZeroParentFingerprintForMasterKey`] if the depth is 0 and the master key
    ///   fingerprint is non-zero.
    /// * [`ParseError::NonZeroChildNumberForMasterKey`] if the depth is 0 and the child number is
    ///   non-zero.
    pub fn decode(data: &[u8]) -> Result<Self, ParseError> {
        let Common { network, depth, parent_fingerprint, child_number, chain_code, key } =
            Common::decode(data)?;

        let network = match network {
            VERSION_BYTES_MAINNET_PRIVATE => NetworkKind::Main,
            VERSION_BYTES_TESTNETS_PRIVATE => NetworkKind::Test,
            unknown => return Err(ParseError::UnknownVersion(unknown)),
        };

        let (&zero, private_key) = key.split_first();
        if zero != 0 {
            return Err(ParseError::InvalidPrivateKeyPrefix);
        }

        Ok(Self {
            network,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            private_key: secp256k1::SecretKey::from_secret_bytes(*private_key)?,
        })
    }

    /// Extended private key binary encoding according to BIP-0032
    pub fn encode(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(&match self.network {
            NetworkKind::Main => VERSION_BYTES_MAINNET_PRIVATE,
            NetworkKind::Test => VERSION_BYTES_TESTNETS_PRIVATE,
        });
        ret[4] = self.depth;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&u32::from(self.child_number).to_be_bytes());
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45] = 0;
        ret[46..78].copy_from_slice(&self.private_key[..]);
        ret
    }

    /// Returns the HASH160 of the public key belonging to the xpriv
    pub fn identifier(&self) -> XKeyIdentifier { Xpub::from_xpriv(self).identifier() }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint(&self) -> Fingerprint {
        self.identifier().as_byte_array().sub_array::<0, 4>().into()
    }
}

impl Xpub {
    /// Constructs a new extended public key from an extended private key.
    #[deprecated(since = "TBD", note = "use `from_xpriv()` instead")]
    pub fn from_priv(sk: &Xpriv) -> Self { Self::from_xpriv(sk) }

    /// Constructs a new extended public key from an extended private key.
    pub fn from_xpriv(xpriv: &Xpriv) -> Self {
        Self {
            network: xpriv.network,
            depth: xpriv.depth,
            parent_fingerprint: xpriv.parent_fingerprint,
            child_number: xpriv.child_number,
            public_key: secp256k1::PublicKey::from_secret_key(&xpriv.private_key),
            chain_code: xpriv.chain_code,
        }
    }

    /// Constructs a new ECDSA compressed public key matching internal public key representation.
    #[deprecated(since = "TBD", note = "use `to_public_key()` instead")]
    pub fn to_pub(self) -> FullPublicKey { self.to_public_key() }

    /// Constructs a new ECDSA compressed public key matching internal public key representation.
    pub fn to_public_key(self) -> FullPublicKey { FullPublicKey::from_secp(self.public_key) }

    /// Constructs a new BIP-0340 x-only public key for BIP-0340 signatures and Taproot use matching
    /// the internal public key representation.
    #[deprecated(since = "TBD", note = "use `to_x_only_public_key()` instead")]
    pub fn to_x_only_pub(self) -> XOnlyPublicKey { self.to_x_only_public_key() }

    /// Constructs a new BIP-0340 x-only public key for BIP-0340 signatures and Taproot use matching
    /// the internal public key representation.
    pub fn to_x_only_public_key(self) -> XOnlyPublicKey { XOnlyPublicKey::from(self.public_key) }

    /// Attempts to derive an extended public key from a path.
    ///
    /// The `path` argument can be any type implementing `AsRef<[ChildNumber]>`, such as `RelativeDerivationPath`, for instance.
    ///
    /// # Errors
    ///
    /// See [`derive_xpub`].
    ///
    /// [`derive_xpub`]: Xpub::derive_xpub
    #[deprecated(since = "TBD", note = "use `derive_xpub()` instead")]
    pub fn derive_pub<P: AsRef<[ChildNumber]>>(&self, path: P) -> Result<Self, DerivationError> {
        self.derive_xpub(path)
    }

    /// Attempts to derive an extended public key from a path.
    ///
    /// The `path` argument can be any type implementing `AsRef<[ChildNumber]>`, such as
    /// `RelativeDerivationPath`, for instance.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the [`ChildNumber`]s are hardened.
    pub fn derive_xpub<P: AsRef<[ChildNumber]>>(&self, path: P) -> Result<Self, DerivationError> {
        let mut pk: Self = *self;
        for cnum in path.as_ref() {
            pk = pk.ckd_pub(*cnum)?;
        }
        Ok(pk)
    }

    /// Computes the scalar tweak added to this key to get a child key
    ///
    /// # Errors
    ///
    /// Returns an error if the given [`ChildNumber`] is hardened.
    #[allow(clippy::missing_panics_doc)]
    pub fn ckd_pub_tweak(
        &self,
        i: ChildNumber,
    ) -> Result<(secp256k1::SecretKey, ChainCode), DerivationError> {
        if i.is_hardened() {
            return Err(DerivationError::CannotDeriveHardenedChild);
        }

        let mut engine = HmacEngine::<sha512::HashEngine>::new(&self.chain_code[..]);
        engine.input(&self.public_key.serialize()[..]);
        engine.input(&i.index().to_be_bytes());

        let hmac = engine.finalize();
        let private_key = secp256k1::SecretKey::from_secret_bytes(
            *hmac.as_byte_array().split_array::<32, 32>().0,
        )
        .expect("cryptographically unreachable");
        let chain_code = ChainCode::from_hmac(hmac);
        Ok((private_key, chain_code))
    }

    /// Public->Public child key derivation
    ///
    /// # Errors
    ///
    /// Returns an error if the given [`ChildNumber`] is hardened, or if next key exceeds
    /// the maximum derivation depth.
    #[allow(clippy::missing_panics_doc)]
    pub fn ckd_pub(&self, i: ChildNumber) -> Result<Self, DerivationError> {
        let (sk, chain_code) = self.ckd_pub_tweak(i)?;
        let tweaked =
            self.public_key.add_exp_tweak(&sk.into()).expect("cryptographically unreachable");

        Ok(Self {
            network: self.network,
            depth: self.depth.checked_add(1).ok_or(DerivationError::MaximumDepthExceeded)?,
            parent_fingerprint: self.fingerprint(),
            child_number: i,
            public_key: tweaked,
            chain_code,
        })
    }

    /// Decoding extended public key from binary data according to BIP-0032
    ///
    /// # Errors
    ///
    /// * [`ParseError::UnknownVersion`] if the decoded network value is not main or testnet.
    /// * [`ParseError::Secp256k1`] if the public key bytes are not a valid secp public key.
    /// * [`ParseError::WrongExtendedKeyLength`] if the data is not the correct length.
    /// * [`ParseError::NonZeroParentFingerprintForMasterKey`] if the depth is 0 and the master key
    ///   fingerprint is non-zero.
    /// * [`ParseError::NonZeroChildNumberForMasterKey`] if the depth is 0 and the child number is
    ///   non-zero.
    pub fn decode(data: &[u8]) -> Result<Self, ParseError> {
        let Common { network, depth, parent_fingerprint, child_number, chain_code, key } =
            Common::decode(data)?;

        let network = match network {
            VERSION_BYTES_MAINNET_PUBLIC => NetworkKind::Main,
            VERSION_BYTES_TESTNETS_PUBLIC => NetworkKind::Test,
            unknown => return Err(ParseError::UnknownVersion(unknown)),
        };

        Ok(Self {
            network,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            public_key: secp256k1::PublicKey::from_slice(&key)?,
        })
    }

    /// Extended public key binary encoding according to BIP-0032
    pub fn encode(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(&match self.network {
            NetworkKind::Main => VERSION_BYTES_MAINNET_PUBLIC,
            NetworkKind::Test => VERSION_BYTES_TESTNETS_PUBLIC,
        });
        ret[4] = self.depth;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&u32::from(self.child_number).to_be_bytes());
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45..78].copy_from_slice(&self.public_key.serialize()[..]);
        ret
    }

    /// Returns the HASH160 of the public key component of the xpub
    pub fn identifier(&self) -> XKeyIdentifier {
        XKeyIdentifier(hash160::Hash::hash(&self.public_key.serialize()))
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint(&self) -> Fingerprint {
        self.identifier().as_byte_array().sub_array::<0, 4>().into()
    }
}

impl fmt::Display for Xpriv {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        base58::encode_check_to_fmt(fmt, &self.encode()[..])
    }
}

impl FromStr for Xpriv {
    type Err = ParseError;

    fn from_str(inp: &str) -> Result<Self, ParseError> {
        let data = base58::decode_check(inp)?;

        if data.len() != 78 {
            return Err(InvalidBase58PayloadLengthError { length: data.len() }.into());
        }

        Self::decode(&data)
    }
}

impl fmt::Display for Xpub {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        base58::encode_check_to_fmt(fmt, &self.encode()[..])
    }
}

impl FromStr for Xpub {
    type Err = ParseError;

    fn from_str(inp: &str) -> Result<Self, ParseError> {
        let data = base58::decode_check(inp)?;

        if data.len() != 78 {
            return Err(InvalidBase58PayloadLengthError { length: data.len() }.into());
        }

        Self::decode(&data)
    }
}

impl From<Xpub> for XKeyIdentifier {
    fn from(key: Xpub) -> Self { key.identifier() }
}

impl From<&Xpub> for XKeyIdentifier {
    fn from(key: &Xpub) -> Self { key.identifier() }
}

// Helps unify decoding
struct Common {
    network: [u8; 4],
    depth: u8,
    parent_fingerprint: Fingerprint,
    child_number: ChildNumber,
    chain_code: ChainCode,
    // public key (compressed) or 0 byte followed by a private key
    key: [u8; 33],
}

impl Common {
    /// Decodes common fields for [`Xpriv`] and [`Xpub`].
    ///
    /// # Errors
    ///
    /// * [`ParseError::WrongExtendedKeyLength`] if the data is not the correct length.
    /// * [`ParseError::NonZeroParentFingerprintForMasterKey`] if the depth is 0 and the master key
    ///   fingerprint is non-zero.
    /// * [`ParseError::NonZeroChildNumberForMasterKey`] if the depth is 0 and the child number is
    ///   non-zero.
    fn decode(data: &[u8]) -> Result<Self, ParseError> {
        let data: &[u8; 78] =
            data.try_into().map_err(|_| ParseError::WrongExtendedKeyLength(data.len()))?;

        let (&network, data) = data.split_array::<4, 74>();
        let (&depth, data) = data.split_first::<73>();
        let (&parent_fingerprint, data) = data.split_array::<4, 69>();
        let (&child_number, data) = data.split_array::<4, 65>();
        let (&chain_code, &key) = data.split_array::<32, 33>();

        if depth == 0 {
            if parent_fingerprint != [0u8; 4] {
                return Err(ParseError::NonZeroParentFingerprintForMasterKey);
            }

            if child_number != [0u8; 4] {
                return Err(ParseError::NonZeroChildNumberForMasterKey);
            }
        }

        Ok(Self {
            network,
            depth,
            parent_fingerprint: parent_fingerprint.into(),
            child_number: u32::from_be_bytes(child_number).into(),
            chain_code: chain_code.into(),
            key,
        })
    }
}

/// Error types for BIP-0032 operations
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    use internals::write_err;

    /// A BIP-0032 error
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum ParseError {
        /// A secp256k1 error occurred
        Secp256k1(secp256k1::Error),
        /// Unknown version magic bytes
        UnknownVersion([u8; 4]),
        /// Encoded extended key data has wrong length
        WrongExtendedKeyLength(usize),
        /// Base58 encoding error
        Base58(base58::Error),
        /// Base58 decoded data was an invalid length.
        InvalidBase58PayloadLength(InvalidBase58PayloadLengthError),
        /// Invalid private key prefix (byte 45 must be 0)
        InvalidPrivateKeyPrefix,
        /// Non-zero parent fingerprint for a master key (depth 0)
        NonZeroParentFingerprintForMasterKey,
        /// Non-zero child number for a master key (depth 0)
        NonZeroChildNumberForMasterKey,
    }

    impl From<Infallible> for ParseError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for ParseError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::Secp256k1(ref e) => write_err!(f, "secp256k1 error"; e),
                Self::UnknownVersion(ref bytes) =>
                    write!(f, "unknown version magic bytes: {:?}", bytes),
                Self::WrongExtendedKeyLength(ref len) =>
                    write!(f, "encoded extended key data has wrong length {}", len),
                Self::Base58(ref e) => write_err!(f, "base58 encoding error"; e),
                Self::InvalidBase58PayloadLength(ref e) => write_err!(f, "base58 payload"; e),
                Self::InvalidPrivateKeyPrefix => f.write_str(
                    "invalid private key prefix, byte 45 must be 0 as required by BIP-0032",
                ),
                Self::NonZeroParentFingerprintForMasterKey =>
                    f.write_str("non-zero parent fingerprint in master key"),
                Self::NonZeroChildNumberForMasterKey =>
                    f.write_str("non-zero child number in master key"),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for ParseError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Secp256k1(ref e) => Some(e),
                Self::Base58(ref e) => Some(e),
                Self::InvalidBase58PayloadLength(ref e) => Some(e),
                Self::UnknownVersion(_) | Self::WrongExtendedKeyLength(_) => None,
                Self::InvalidPrivateKeyPrefix => None,
                Self::NonZeroParentFingerprintForMasterKey => None,
                Self::NonZeroChildNumberForMasterKey => None,
            }
        }
    }

    impl From<secp256k1::Error> for ParseError {
        fn from(e: secp256k1::Error) -> Self { Self::Secp256k1(e) }
    }

    impl From<base58::Error> for ParseError {
        fn from(err: base58::Error) -> Self { Self::Base58(err) }
    }

    impl From<InvalidBase58PayloadLengthError> for ParseError {
        fn from(e: InvalidBase58PayloadLengthError) -> Self { Self::InvalidBase58PayloadLength(e) }
    }

    /// A BIP-0032 error
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum DerivationError {
        /// Attempted to derive a hardened child from an xpub.
        ///
        /// You can only derive hardened children from xprivs.
        CannotDeriveHardenedChild,
        /// Attempted to derive a child of depth 256 or higher.
        ///
        /// There is no way to encode such xkeys.
        MaximumDepthExceeded,
    }

    #[cfg(feature = "std")]
    impl std::error::Error for DerivationError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::CannotDeriveHardenedChild => None,
                Self::MaximumDepthExceeded => None,
            }
        }
    }

    impl fmt::Display for DerivationError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match *self {
                Self::CannotDeriveHardenedChild =>
                    f.write_str("cannot derive hardened child of public key"),
                Self::MaximumDepthExceeded =>
                    f.write_str("cannot derive child of depth 256 or higher"),
            }
        }
    }

    /// Out-of-range index when constructing a child number.
    ///
    /// *Indices* are always in the range [0, 2^31 - 1]. Normal child numbers have the
    /// same range, while hardened child numbers lie in the range [2^31, 2^32 - 1].
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct IndexOutOfRangeError {
        /// The index that was out of range for a child number.
        pub index: u32,
    }

    impl From<Infallible> for IndexOutOfRangeError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for IndexOutOfRangeError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "index {} out of range [0, 2^31 - 1] (do you have a hardened child number, rather than an index?)", self.index)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for IndexOutOfRangeError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
    }

    /// Error parsing a child number.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ParseChildNumberError {
        /// Parsed the child number as an integer, but the integer was out of range.
        IndexOutOfRange(IndexOutOfRangeError),
        /// Failed to parse the child number as an integer.
        ParseInt(core::num::ParseIntError),
    }

    impl From<Infallible> for ParseChildNumberError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for ParseChildNumberError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match *self {
                Self::IndexOutOfRange(ref e) => e.fmt(f),
                Self::ParseInt(ref e) => e.fmt(f),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for ParseChildNumberError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match *self {
                Self::IndexOutOfRange(ref e) => Some(e),
                Self::ParseInt(ref e) => Some(e),
            }
        }
    }

    /// Error parsing a derivation path.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ParseDerivationPathError {
        /// Failed to parse a child number.
        Child(ParseChildNumberError),
        /// The path contained an empty child number.
        EmptyChild,
        /// The absolute path was missing the `m` master prefix.
        MissingMasterPrefix,
        /// The relative path unexpectedly contained the `m` master prefix.
        UnexpectedMasterPrefix,
    }

    impl From<Infallible> for ParseDerivationPathError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for ParseDerivationPathError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match *self {
                Self::Child(ref e) => write_err!(f, "failed to parse child number"; e),
                Self::EmptyChild => f.write_str("derivation path contains an empty child number"),
                Self::MissingMasterPrefix =>
                    f.write_str("absolute derivation path is missing master prefix `m`"),
                Self::UnexpectedMasterPrefix =>
                    f.write_str("relative derivation path contains unexpected master prefix `m`"),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for ParseDerivationPathError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match *self {
                Self::Child(ref e) => Some(e),
                Self::EmptyChild | Self::MissingMasterPrefix | Self::UnexpectedMasterPrefix => None,
            }
        }
    }

    impl From<ParseChildNumberError> for ParseDerivationPathError {
        fn from(e: ParseChildNumberError) -> Self { Self::Child(e) }
    }

    /// Decoded base58 data was an invalid length.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct InvalidBase58PayloadLengthError {
        /// The base58 payload length we got after decoding xpriv/xpub string.
        pub(crate) length: usize,
    }

    impl InvalidBase58PayloadLengthError {
        /// Returns the invalid payload length.
        pub fn invalid_base58_payload_length(&self) -> usize { self.length }
    }

    impl fmt::Display for InvalidBase58PayloadLengthError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(
                f,
                "decoded base58 xpriv/xpub data was an invalid length: {} (expected 78)",
                self.length
            )
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for InvalidBase58PayloadLengthError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
    }

    /// Master seed had an invalid length.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct InvalidSeedLengthError {
        pub(crate) length: usize,
    }

    impl InvalidSeedLengthError {
        /// Returns the invalid seed length.
        pub fn invalid_seed_length(&self) -> usize { self.length }
    }

    impl fmt::Display for InvalidSeedLengthError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "invalid BIP-0032 master seed length: {} (expected 16 to 64)", self.length)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for InvalidSeedLengthError {}
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for RelativeDerivationPath {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes = Vec::<u32>::arbitrary(u)?;
        Ok(Self::from_u32_slice(bytes.as_slice()))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for AbsoluteDerivationPath {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(RelativeDerivationPath::arbitrary(u)?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Fingerprint {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_byte_array(u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for ChainCode {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_byte_array(u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for ChildNumber {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_raw(u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Xpub {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            network: u.arbitrary()?,
            depth: u.arbitrary()?,
            parent_fingerprint: u.arbitrary()?,
            child_number: u.arbitrary()?,
            public_key: u.arbitrary()?,
            chain_code: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Xpriv {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let depth = u.arbitrary()?;
        let (parent_fingerprint, child_number) = match depth {
            0 => (Fingerprint::default(), ChildNumber::ZERO_NORMAL),
            _ => (u.arbitrary()?, u.arbitrary()?),
        };

        Ok(Self {
            network: u.arbitrary()?,
            depth,
            parent_fingerprint,
            child_number,
            private_key: u.arbitrary()?,
            chain_code: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::ToString;

    use hex::hex;
    #[cfg(feature = "serde")]
    use internals::serde_round_trip;

    use super::*;

    #[test]
    fn parse_derivation_path_invalid_format() {
        for path in ["n/0'/0", "4/m/5", "0h/0x"] {
            assert!(matches!(
                path.parse::<RelativeDerivationPath>(),
                Err(ParseDerivationPathError::Child(ParseChildNumberError::ParseInt(..))),
            ));
        }
        assert_eq!(
            "//3/0'".parse::<RelativeDerivationPath>(),
            Err(ParseDerivationPathError::EmptyChild)
        );
    }

    #[test]
    fn test_derivation_path_display() {
        let path = RelativeDerivationPath::from_str("84'/0'/0'/0/0").unwrap();
        assert_eq!(format!("{}", path), "84'/0'/0'/0/0");
        assert_eq!(format!("{:#}", path), "84h/0h/0h/0/0");
    }

    #[test]
    fn test_lowerhex_formatting() {
        let normal = ChildNumber::from_normal_idx(42).unwrap();
        let hardened = ChildNumber::from_hardened_idx(42).unwrap();

        assert_eq!(format!("{:x}", normal), "2a");
        assert_eq!(format!("{:#x}", normal), "0x2a");

        assert_eq!(format!("{:x}", hardened), "2a'");
        assert_eq!(format!("{:#x}", hardened), "0x2ah");
    }

    #[test]
    fn test_upperhex_formatting() {
        let normal = ChildNumber::from_normal_idx(42).unwrap();
        let hardened = ChildNumber::from_hardened_idx(42).unwrap();

        assert_eq!(format!("{:X}", normal), "2A");
        assert_eq!(format!("{:#X}", normal), "0x2A");

        assert_eq!(format!("{:X}", hardened), "2A'");
        assert_eq!(format!("{:#X}", hardened), "0x2AH");
    }

    #[test]
    fn test_octal_formatting() {
        let normal = ChildNumber::from_normal_idx(42).unwrap();
        let hardened = ChildNumber::from_hardened_idx(42).unwrap();

        assert_eq!(format!("{:o}", normal), "52");
        assert_eq!(format!("{:#o}", normal), "0o52");

        assert_eq!(format!("{:o}", hardened), "52'");
        assert_eq!(format!("{:#o}", hardened), "0o52h");
    }

    #[test]
    fn test_binary_formatting() {
        let normal = ChildNumber::from_normal_idx(42).unwrap();
        let hardened = ChildNumber::from_hardened_idx(42).unwrap();

        assert_eq!(format!("{:b}", normal), "101010");
        assert_eq!(format!("{:#b}", normal), "0b101010");

        assert_eq!(format!("{:b}", hardened), "101010'");
        assert_eq!(format!("{:#b}", hardened), "0b101010h");
    }

    #[test]
    fn parse_derivation_path_out_of_range() {
        let invalid_path = "2147483648";
        assert_eq!(
            invalid_path.parse::<RelativeDerivationPath>(),
            Err(ParseDerivationPathError::Child(ParseChildNumberError::IndexOutOfRange(
                IndexOutOfRangeError { index: 2_147_483_648 }
            ))),
        );
    }

    #[test]
    fn parse_derivation_path_valid_empty() {
        // Sanity checks.
        assert_eq!(RelativeDerivationPath::default(), RelativeDerivationPath(vec![]));
        assert_eq!(
            RelativeDerivationPath::default(),
            "".parse::<RelativeDerivationPath>().unwrap()
        );

        // A relative path is empty without an `m`.
        assert_eq!("".parse::<RelativeDerivationPath>().unwrap(), RelativeDerivationPath(vec![]));
        assert_eq!(
            "m".parse::<RelativeDerivationPath>(),
            Err(ParseDerivationPathError::UnexpectedMasterPrefix)
        );
        assert_eq!(
            "m/".parse::<RelativeDerivationPath>(),
            Err(ParseDerivationPathError::UnexpectedMasterPrefix)
        );
    }

    #[test]
    fn parse_derivation_path_valid() {
        let valid_paths = [
            ("0'", vec![ChildNumber::ZERO_HARDENED]),
            ("0'/1", vec![ChildNumber::ZERO_HARDENED, ChildNumber::ONE_NORMAL]),
            (
                "0h/1/2'",
                vec![
                    ChildNumber::ZERO_HARDENED,
                    ChildNumber::ONE_NORMAL,
                    ChildNumber::from_hardened_idx(2).unwrap(),
                ],
            ),
            (
                "0'/1/2h/2",
                vec![
                    ChildNumber::ZERO_HARDENED,
                    ChildNumber::ONE_NORMAL,
                    ChildNumber::from_hardened_idx(2).unwrap(),
                    ChildNumber::from_normal_idx(2).unwrap(),
                ],
            ),
            (
                "0'/1/2'/2/1000000000",
                vec![
                    ChildNumber::ZERO_HARDENED,
                    ChildNumber::ONE_NORMAL,
                    ChildNumber::from_hardened_idx(2).unwrap(),
                    ChildNumber::from_normal_idx(2).unwrap(),
                    ChildNumber::from_normal_idx(1_000_000_000).unwrap(),
                ],
            ),
        ];
        for (path, expected) in valid_paths {
            // Access the inner private field so we don't have to clone expected.
            assert_eq!(path.parse::<RelativeDerivationPath>().unwrap().0, expected);
        }
    }

    #[test]
    fn parse_absolute_derivation_path() {
        let master = "m".parse::<AbsoluteDerivationPath>().unwrap();
        assert_eq!(master, AbsoluteDerivationPath::master());
        assert_eq!(master.to_string(), "m");
        assert!(!master.contains_hardened_child());

        let path = "m/0'/1".parse::<AbsoluteDerivationPath>().unwrap();
        assert_eq!(path.as_relative(), &"0'/1".parse::<RelativeDerivationPath>().unwrap());
        assert_eq!(path.to_string(), "m/0'/1");
        assert_eq!(format!("{:#}", path), "m/0h/1");
        assert!(path.contains_hardened_child());

        assert_eq!(
            "".parse::<AbsoluteDerivationPath>(),
            Err(ParseDerivationPathError::MissingMasterPrefix)
        );
        assert_eq!(
            "0/1".parse::<AbsoluteDerivationPath>(),
            Err(ParseDerivationPathError::MissingMasterPrefix)
        );
        assert_eq!(
            "m/".parse::<AbsoluteDerivationPath>(),
            Err(ParseDerivationPathError::EmptyChild)
        );
    }

    #[test]
    fn derivation_path_contains_hardened_child() {
        assert!(!"".parse::<RelativeDerivationPath>().unwrap().contains_hardened_child());
        assert!(!"0/1".parse::<RelativeDerivationPath>().unwrap().contains_hardened_child());
        assert!("0'/1".parse::<RelativeDerivationPath>().unwrap().contains_hardened_child());
    }

    #[test]
    fn derivation_path_conversion_index() {
        let path = "0h/1/2'".parse::<RelativeDerivationPath>().unwrap();
        let numbers: Vec<ChildNumber> = path.clone().into();
        let path2: RelativeDerivationPath = numbers.into();
        assert_eq!(path, path2);
        assert_eq!(&path[..2], &[ChildNumber::ZERO_HARDENED, ChildNumber::ONE_NORMAL]);
        let indexed: RelativeDerivationPath = path[..2].into();
        assert_eq!(indexed, "0h/1".parse::<RelativeDerivationPath>().unwrap());
        assert_eq!(indexed.child(ChildNumber::from_hardened_idx(2).unwrap()), path);
    }

    #[test]
    fn child_number_raw_conversion() {
        let normal = ChildNumber::from_normal_idx(42).unwrap();
        assert_eq!(normal.to_raw(), 42);
        assert_eq!(normal.index(), 42);
        assert!(normal.is_normal());
        assert!(!normal.is_hardened());
        assert_eq!(ChildNumber::from_raw(42), normal);

        let hardened = ChildNumber::from_hardened_idx(42).unwrap();
        assert_eq!(hardened.to_raw(), HARDENED_FLAG | 42);
        assert_eq!(hardened.index(), 42);
        assert!(!hardened.is_normal());
        assert!(hardened.is_hardened());
        assert_eq!(ChildNumber::from_raw(HARDENED_FLAG | 42), hardened);
    }

    #[test]
    fn child_number_index_boundaries() {
        let max = HARDENED_FLAG - 1;

        assert_eq!(ChildNumber::from_normal_idx(max).unwrap().index(), max);
        assert_eq!(ChildNumber::from_hardened_idx(max).unwrap().index(), max);

        assert_eq!(
            ChildNumber::from_normal_idx(HARDENED_FLAG),
            Err(IndexOutOfRangeError { index: HARDENED_FLAG })
        );
        assert_eq!(
            ChildNumber::from_hardened_idx(HARDENED_FLAG),
            Err(IndexOutOfRangeError { index: HARDENED_FLAG })
        );
    }

    fn test_path(
        network: NetworkKind,
        seed: &[u8],
        path: &AbsoluteDerivationPath,
        expected_sk: &str,
        expected_pk: &str,
    ) {
        let seed = <&Bip32Seed>::try_from(seed).unwrap();
        let mut sk = Xpriv::new_master(network, seed);
        let mut pk = Xpub::from_xpriv(&sk);
        let path = path.as_relative();

        // Check derivation convenience method for Xpriv
        assert_eq!(&sk.derive_xpriv(path).unwrap().to_string()[..], expected_sk);

        // Check derivation convenience method for Xpub, should error
        // appropriately if any ChildNumber is hardened
        if path.contains_hardened_child() {
            assert_eq!(pk.derive_xpub(path), Err(DerivationError::CannotDeriveHardenedChild));
        } else {
            assert_eq!(&pk.derive_xpub(path).unwrap().to_string()[..], expected_pk);
        }

        // Derive keys, checking hardened and non-hardened derivation one-by-one
        for &num in &path.0 {
            sk = sk.ckd_priv(num).unwrap();
            if num.is_normal() {
                let pk2 = pk.ckd_pub(num).unwrap();
                pk = Xpub::from_xpriv(&sk);
                assert_eq!(pk, pk2);
            } else {
                assert_eq!(pk.ckd_pub(num), Err(DerivationError::CannotDeriveHardenedChild));
                pk = Xpub::from_xpriv(&sk);
            }
        }

        // Check result against expected base58
        assert_eq!(&sk.to_string()[..], expected_sk);
        assert_eq!(&pk.to_string()[..], expected_pk);
        // Check decoded base58 against result
        let decoded_sk = expected_sk.parse::<Xpriv>();
        let decoded_pk = expected_pk.parse::<Xpub>();
        assert_eq!(Ok(sk), decoded_sk);
        assert_eq!(Ok(pk), decoded_pk);
    }

    #[test]
    fn increment() {
        let idx = 9_345_497; // randomly generated, I promise
        let cn = ChildNumber::from_normal_idx(idx).unwrap();
        assert_eq!(cn.increment().ok(), Some(ChildNumber::from_normal_idx(idx + 1).unwrap()));
        let cn = ChildNumber::from_hardened_idx(idx).unwrap();
        assert_eq!(cn.increment().ok(), Some(ChildNumber::from_hardened_idx(idx + 1).unwrap()));

        let max = (1 << 31) - 1;
        let cn = ChildNumber::from_normal_idx(max).unwrap();
        assert_eq!(cn.increment(), Err(IndexOutOfRangeError { index: 1 << 31 }),);
        let cn = ChildNumber::from_hardened_idx(max).unwrap();
        assert_eq!(cn.increment(), Err(IndexOutOfRangeError { index: 1 << 31 }),);

        let cn = ChildNumber::from_normal_idx(350).unwrap();
        let path = "42'".parse::<RelativeDerivationPath>().unwrap();
        let mut iter = path.children_from(cn);
        assert_eq!(iter.next(), Some("42'/350".parse().unwrap()));
        assert_eq!(iter.next(), Some("42'/351".parse().unwrap()));

        let path = "42'/350'".parse::<RelativeDerivationPath>().unwrap();
        let mut iter = path.normal_children();
        assert_eq!(iter.next(), Some("42'/350'/0".parse().unwrap()));
        assert_eq!(iter.next(), Some("42'/350'/1".parse().unwrap()));

        let path = "42'/350'".parse::<RelativeDerivationPath>().unwrap();
        let mut iter = path.hardened_children();
        assert_eq!(iter.next(), Some("42'/350'/0'".parse().unwrap()));
        assert_eq!(iter.next(), Some("42'/350'/1'".parse().unwrap()));

        let cn = ChildNumber::from_hardened_idx(42350).unwrap();
        let path = "42'".parse::<RelativeDerivationPath>().unwrap();
        let mut iter = path.children_from(cn);
        assert_eq!(iter.next(), Some("42'/42350'".parse().unwrap()));
        assert_eq!(iter.next(), Some("42'/42351'".parse().unwrap()));

        let cn = ChildNumber::from_hardened_idx(max).unwrap();
        let path = "42'".parse::<RelativeDerivationPath>().unwrap();
        let mut iter = path.children_from(cn);
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
    }

    #[test]
    fn vector_1() {
        let seed = hex!("000102030405060708090a0b0c0d0e0f");

        // m
        test_path(NetworkKind::Main, &seed, &"m".parse().unwrap(),
                  "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                  "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");

        // m/0h
        test_path(NetworkKind::Main, &seed, &"m/0h".parse().unwrap(),
                  "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                  "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw");

        // m/0h/1
        test_path(NetworkKind::Main, &seed, &"m/0h/1".parse().unwrap(),
                   "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                   "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ");

        // m/0h/1/2h
        test_path(NetworkKind::Main, &seed, &"m/0h/1/2h".parse().unwrap(),
                  "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                  "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5");

        // m/0h/1/2h/2
        test_path(NetworkKind::Main, &seed, &"m/0h/1/2h/2".parse().unwrap(),
                  "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                  "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV");

        // m/0h/1/2h/2/1000000000
        test_path(NetworkKind::Main, &seed, &"m/0h/1/2h/2/1000000000".parse().unwrap(),
                  "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                  "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy");
    }

    #[test]
    fn vector_2() {
        let seed = hex!("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");

        // m
        test_path(NetworkKind::Main, &seed, &"m".parse().unwrap(),
                  "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                  "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB");

        // m/0
        test_path(NetworkKind::Main, &seed, &"m/0".parse().unwrap(),
                  "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                  "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH");

        // m/0/2147483647h
        test_path(NetworkKind::Main, &seed, &"m/0/2147483647h".parse().unwrap(),
                  "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                  "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a");

        // m/0/2147483647h/1
        test_path(NetworkKind::Main, &seed, &"m/0/2147483647h/1".parse().unwrap(),
                  "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                  "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon");

        // m/0/2147483647h/1/2147483646h
        test_path(NetworkKind::Main, &seed, &"m/0/2147483647h/1/2147483646h".parse().unwrap(),
                  "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                  "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL");

        // m/0/2147483647h/1/2147483646h/2
        test_path(NetworkKind::Main, &seed, &"m/0/2147483647h/1/2147483646h/2".parse().unwrap(),
                  "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                  "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt");
    }

    #[test]
    fn vector_3() {
        let seed = hex!("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be");

        // m
        test_path(NetworkKind::Main, &seed, &"m".parse().unwrap(),
                  "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
                  "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13");

        // m/0h
        test_path(NetworkKind::Main, &seed, &"m/0h".parse().unwrap(),
                  "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
                  "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y");
    }

    #[test]
    fn test_reject_xpriv_with_non_zero_byte_at_index_45() {
        let mut xpriv = base58::decode_check("xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9").unwrap();

        // Modify byte at index 45 to be non-zero (e.g., 1)
        xpriv[45] = 1;

        let result = Xpriv::decode(&xpriv);
        assert!(result.is_err());

        match result {
            Err(ParseError::InvalidPrivateKeyPrefix) => {}
            _ => panic!("Expected InvalidPrivateKeyPrefix error, got {:?}", result),
        }
    }

    #[test]
    fn test_reject_xpriv_with_zero_depth_and_non_zero_index() {
        let result = "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN".parse::<Xpriv>();
        assert!(result.is_err());

        match result {
            Err(ParseError::NonZeroChildNumberForMasterKey) => {}
            _ => panic!("Expected NonZeroChildNumberForMasterKey error, got {:?}", result),
        }
    }

    #[test]
    fn test_reject_xpriv_with_zero_depth_and_non_zero_parent_fingerprint() {
        let result = "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv".parse::<Xpriv>();
        assert!(result.is_err());

        match result {
            Err(ParseError::NonZeroParentFingerprintForMasterKey) => {}
            _ => panic!("Expected NonZeroParentFingerprintForMasterKey error, got {:?}", result),
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    pub fn encode_decode_childnumber() {
        serde_round_trip!(ChildNumber::ZERO_NORMAL);
        serde_round_trip!(ChildNumber::ONE_NORMAL);
        serde_round_trip!(ChildNumber::from_normal_idx((1 << 31) - 1).unwrap());
        serde_round_trip!(ChildNumber::ZERO_HARDENED);
        serde_round_trip!(ChildNumber::ONE_HARDENED);
        serde_round_trip!(ChildNumber::from_hardened_idx((1 << 31) - 1).unwrap());
    }

    #[test]
    #[cfg(feature = "serde")]
    pub fn encode_decode_derivation_paths() {
        serde_round_trip!("0'/1".parse::<RelativeDerivationPath>().unwrap());
        serde_round_trip!("m/0'/1".parse::<AbsoluteDerivationPath>().unwrap());
    }

    #[test]
    #[cfg(feature = "serde")]
    pub fn encode_fingerprint_chaincode() {
        use serde_json;
        let fp = Fingerprint::from([1u8, 2, 3, 42]);
        #[rustfmt::skip]
        let cc = ChainCode::from(
            [1u8,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]
        );

        serde_round_trip!(fp);
        serde_round_trip!(cc);

        assert_eq!("\"0102032a\"", serde_json::to_string(&fp).unwrap());
        assert_eq!(
            "\"0102030405060708090001020304050607080900010203040506070809000102\"",
            serde_json::to_string(&cc).unwrap()
        );
        assert_eq!("0102032a", fp.to_string());
        assert_eq!(
            "0102030405060708090001020304050607080900010203040506070809000102",
            cc.to_string()
        );
    }

    #[test]
    fn fmt_child_number() {
        assert_eq!("000005h", &format!("{:#06}", ChildNumber::from_hardened_idx(5).unwrap()));
        assert_eq!("5h", &format!("{:#}", ChildNumber::from_hardened_idx(5).unwrap()));
        assert_eq!("000005'", &format!("{:06}", ChildNumber::from_hardened_idx(5).unwrap()));
        assert_eq!("5'", &format!("{}", ChildNumber::from_hardened_idx(5).unwrap()));
        assert_eq!("42", &format!("{}", ChildNumber::from_normal_idx(42).unwrap()));
        assert_eq!("000042", &format!("{:06}", ChildNumber::from_normal_idx(42).unwrap()));
    }

    #[test]
    #[should_panic(expected = "Secp256k1(InvalidSecretKey)")]
    fn schnorr_broken_privkey_zeros() {
        /* this is how we generate key:
        let mut sk = secp256k1::key::ONE_KEY;

        let zeros = [0u8; 32];
        unsafe {
            sk.as_mut_ptr().copy_from(zeros.as_ptr(), 32);
        }

        let xpriv = Xpriv {
            network: NetworkKind::Main,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::ZERO_NORMAL,
            private_key: sk,
            chain_code: ChainCode::from([0u8; 32])
        };

        println!("{}", xpriv);
         */

        // Xpriv having secret key set to all zeros
        let xpriv_str = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx";
        xpriv_str.parse::<Xpriv>().unwrap();
    }

    #[test]
    #[should_panic(expected = "Secp256k1(InvalidSecretKey)")]
    fn schnorr_broken_privkey_ffs() {
        // Xpriv having secret key set to all 0xFF's
        let xpriv_str = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fENZ3QzxW";
        xpriv_str.parse::<Xpriv>().unwrap();
    }

    #[test]
    fn official_vectors_5() {
        let invalid_keys = [
            "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH",
            "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ",
            "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4",
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J",
            "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",
            "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",
            "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN",
            "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8",
            "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
            "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx",
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G",
            "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY",
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",
        ];
        for key in invalid_keys {
            if key.starts_with("xpub") {
                key.parse::<Xpub>().unwrap_err();
            } else {
                key.parse::<Xpriv>().unwrap_err();
            }
        }
    }

    #[test]
    fn bip32_seed_rejects_out_of_range_length() {
        for len in [0usize, 1, 15, 65, 128, 1024] {
            let bytes = vec![0u8; len];
            assert_eq!(
                <&Bip32Seed>::try_from(bytes.as_slice()),
                Err(InvalidSeedLengthError { length: len }),
            );
        }
    }

    #[test]
    fn bip32_seed_accepts_in_range_length() {
        for len in [16usize, 17, 32, 63, 64] {
            let bytes = vec![0u8; len];
            let seed = <&Bip32Seed>::try_from(bytes.as_slice()).unwrap();
            assert_eq!(seed.as_bytes().len(), len);
        }

        let arr32 = [7u8; 32];
        assert_eq!(<&Bip32Seed>::from(&arr32).as_bytes(), &arr32[..]);

        let arr64 = [9u8; 64];
        assert_eq!(<&Bip32Seed>::from(&arr64).as_bytes(), &arr64[..]);
    }

    #[test]
    fn bip32_seed_debug_redacts_bytes() {
        let arr = [0xABu8; 32];
        let seed: &Bip32Seed = (&arr).into();
        let rendered = alloc::format!("{:?}", seed);
        assert_eq!(rendered, "Bip32Seed(sha256=9a2db2e2)");
    }
}
