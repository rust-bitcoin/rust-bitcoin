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

//! BIP32 Implementation
//!
//! Implementation of BIP32 hierarchical deterministic wallets, as defined
//! at https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

use std::default::Default;
use std::{error, fmt};
use std::str::FromStr;
#[cfg(feature = "serde")] use serde;

use hash_types::XpubIdentifier;
use hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine};
use secp256k1::{self, Secp256k1};

use network::constants::Network;
use util::{base58, endian};
use util::key::{PublicKey, PrivateKey};

/// Magical version bytes for xpub: bitcoin mainnet public key for P2PKH or P2SH
pub const VERSION_MAGIC_XPUB: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
/// Magical version bytes for xprv: bitcoin mainnet private key for P2PKH or P2SH
pub const VERSION_MAGIC_XPRV: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
/// Magical version bytes for ypub: bitcoin mainnet public key for P2WPKH in P2SH
pub const VERSION_MAGIC_YPUB: [u8; 4] = [0x04, 0x9D, 0x7C, 0xB2];
/// Magical version bytes for yprv: bitcoin mainnet private key for P2WPKH in P2SH
pub const VERSION_MAGIC_YPRV: [u8; 4] = [0x04, 0x9D, 0x78, 0x78];
/// Magical version bytes for zpub: bitcoin mainnet public key for P2WPKH
pub const VERSION_MAGIC_ZPUB: [u8; 4] = [0x04, 0xB2, 0x47, 0x46];
/// Magical version bytes for zprv: bitcoin mainnet private key for P2WPKH
pub const VERSION_MAGIC_ZPRV: [u8; 4] = [0x04, 0xB2, 0x43, 0x0C];
/// Magical version bytes for Ypub: bitcoin mainnet public key for
/// multi-signature P2WSH in P2SH
pub const VERSION_MAGIC_YPUB_MULTISIG: [u8; 4] = [0x02, 0x95, 0xb4, 0x3f];
/// Magical version bytes for Yprv: bitcoin mainnet private key for
/// multi-signature P2WSH in P2SH
pub const VERSION_MAGIC_YPRV_MULTISIG: [u8; 4] = [0x02, 0x95, 0xb0, 0x05];
/// Magical version bytes for Zpub: bitcoin mainnet public key for
/// multi-signature P2WSH
pub const VERSION_MAGIC_ZPUB_MULTISIG: [u8; 4] = [0x02, 0xaa, 0x7e, 0xd3];
/// Magical version bytes for Zprv: bitcoin mainnet private key for
/// multi-signature P2WSH
pub const VERSION_MAGIC_ZPRV_MULTISIG: [u8; 4] = [0x02, 0xaa, 0x7a, 0x99];

/// Magical version bytes for tpub: bitcoin testnet/regtest public key for
/// P2PKH or P2SH
pub const VERSION_MAGIC_TPUB: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];
/// Magical version bytes for tprv: bitcoin testnet/regtest private key for
/// P2PKH or P2SH
pub const VERSION_MAGIC_TPRV: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
/// Magical version bytes for upub: bitcoin testnet/regtest public key for
/// P2WPKH in P2SH
pub const VERSION_MAGIC_UPUB: [u8; 4] = [0x04, 0x4A, 0x52, 0x62];
/// Magical version bytes for uprv: bitcoin testnet/regtest private key for
/// P2WPKH in P2SH
pub const VERSION_MAGIC_UPRV: [u8; 4] = [0x04, 0x4A, 0x4E, 0x28];
/// Magical version bytes for vpub: bitcoin testnet/regtest public key for
/// P2WPKH
pub const VERSION_MAGIC_VPUB: [u8; 4] = [0x04, 0x5F, 0x1C, 0xF6];
/// Magical version bytes for vprv: bitcoin testnet/regtest private key for
/// P2WPKH
pub const VERSION_MAGIC_VPRV: [u8; 4] = [0x04, 0x5F, 0x18, 0xBC];
/// Magical version bytes for Upub: bitcoin testnet/regtest public key for
/// multi-signature P2WSH in P2SH
pub const VERSION_MAGIC_UPUB_MULTISIG: [u8; 4] = [0x02, 0x42, 0x89, 0xef];
/// Magical version bytes for Uprv: bitcoin testnet/regtest private key for
/// multi-signature P2WSH in P2SH
pub const VERSION_MAGIC_UPRV_MULTISIG: [u8; 4] = [0x02, 0x42, 0x85, 0xb5];
/// Magical version bytes for Zpub: bitcoin testnet/regtest public key for
/// multi-signature P2WSH
pub const VERSION_MAGIC_VPUB_MULTISIG: [u8; 4] = [0x02, 0x57, 0x54, 0x83];
/// Magical version bytes for Zprv: bitcoin testnet/regtest private key for
/// multi-signature P2WSH
pub const VERSION_MAGIC_VPRV_MULTISIG: [u8; 4] = [0x02, 0x57, 0x50, 0x48];

/// A chain code
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainCode([u8; 32]);
impl_array_newtype!(ChainCode, u8, 32);
impl_array_newtype_show!(ChainCode);
impl_bytes_newtype!(ChainCode, 32);

/// A fingerprint
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint([u8; 4]);
impl_array_newtype!(Fingerprint, u8, 4);
impl_array_newtype_show!(Fingerprint);
impl_bytes_newtype!(Fingerprint, 4);

impl Default for Fingerprint {
    fn default() -> Fingerprint { Fingerprint([0; 4]) }
}

/// Structure holding 4 verion bytes with magical numbers representing different
/// versions of extended public and private keys according to BIP-32.
/// Key version stores raw bytes without their check, interpretation or
/// verification; for these purposes special helpers structures implementing
/// [VersionResolver] are used.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct KeyVersion([u8; 4]);

/// Trait which must be implemented by helpers which do construction,
/// interpretation, verification and cross-conversion of extended public and
/// private key version magic bytes from [KeyVersion]
pub trait VersionResolver: Copy + Clone + PartialEq + Eq + PartialOrd + Ord + ::std::hash::Hash + fmt::Debug {
    /// Type that defines recognized network options
    type Network;

    /// Type that defines possible applications fro public and private keys
    /// (types of scriptPubkey descriptors in which they can be used)
    type Applications;

    /// Constructor for [KeyVersion] with given network, application scope and
    /// key type (public or private)
    fn resolve(network: Self::Network, applicable_for: Self::Applications, is_priv: bool) -> KeyVersion;

    /// Detects whether provided version corresponds to an extended public key.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    fn is_pub(_: &KeyVersion) -> Option<bool> { return None }

    /// Detects whether provided version corresponds to an extended private key.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    fn is_prv(_: &KeyVersion) -> Option<bool> { return None }

    /// Detects network used by the provided key version bytes.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    fn network(_: &KeyVersion) -> Option<Self::Network> { return None }

    /// Detects application scope defined by the provided key version bytes.
    /// Application scope is a types of scriptPubkey descriptors in which given
    /// extended public/private keys can be used.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    fn applications(_: &KeyVersion) -> Option<Self::Applications> { return None }

    /// Returns BIP 32 derivation path for the provided key version.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    fn derivation_path(_: &KeyVersion) -> Option<DerivationPath> { return None }

    /// Converts version into version corresponding to an extended public key.
    /// Returns `None` if the resolver does not know how to perform conversion.
    fn make_pub(_: &KeyVersion) -> Option<KeyVersion> { return None }

    /// Converts version into version corresponding to an extended private key.
    /// Returns `None` if the resolver does not know how to perform conversion.
    fn make_prv(_: &KeyVersion) -> Option<KeyVersion> { return None }
}

impl KeyVersion {
    /// Detects whether provided version corresponds to an extended public key.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    pub fn is_pub<R: VersionResolver>(&self) -> Option<bool> { R::is_pub(&self) }

    /// Detects whether provided version corresponds to an extended private key.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    pub fn is_prv<R: VersionResolver>(&self) -> Option<bool> { R::is_prv(&self) }

    /// Detects network used by the provided key version bytes.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    pub fn network<R: VersionResolver>(&self) -> Option<R::Network> { R::network(&self) }

    /// Detects application scope defined by the provided key version bytes.
    /// Application scope is a types of scriptPubkey descriptors in which given
    /// extended public/private keys can be used.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    pub fn applications<R: VersionResolver>(&self) -> Option<R::Applications> { R::applications(&self) }

    /// Returns BIP 32 derivation path for the provided key version.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    pub fn derivation_path<R: VersionResolver>(&self) -> Option<DerivationPath> { R::derivation_path(&self) }

    /// Converts version into version corresponding to an extended public key.
    /// Returns `None` if the resolver does not know how to perform conversion.
    pub fn try_to_pub<R: VersionResolver>(&self) -> Option<KeyVersion> { R::make_pub(&self) }

    /// Converts version into version corresponding to an extended private key.
    /// Returns `None` if the resolver does not know how to perform conversion.
    pub fn try_to_prv<R: VersionResolver>(&self) -> Option<KeyVersion> { R::make_prv(&self) }
}

/// Default resolver knowing native [bitcoin::network::constants::Network]
/// and BIP 32 and SLIP 132-defined key applications with [KeyApplications]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DefaultResolver;

/// SLIP 132-defined key applications defining types of scriptPubkey descriptors
/// in which they can be used
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum KeyApplications {
    /// xprv/xpub: keys that can be used for P2PKH and multisig P2SH scriptPubkey
    /// descriptors.
    Legacy,
    /// zprv/zpub: keys that can be used for P2WPKH scriptPubkey descriptors
    SegWitV0Singlesig,
    /// yprv/ypub: keys that can be used for P2WPKH-in-P2SH scriptPubkey descriptors
    SegWitLegacySinglesig,
    /// Zprv/Zpub: keys that can be used for multisig P2WSH scriptPubkey descriptors
    SegWitV0Miltisig,
    /// Yprv/Ypub: keys that can be used for multisig P2WSH-in-P2SH scriptPubkey descriptors
    SegWitLegacyMultisig,
}

/// Extended private key
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ExtendedPrivKey<R: VersionResolver> {
    /// Version bytes specifying to which network the key belongs
    /// and for which types of scriptPubkey it may be used
    pub version: KeyVersion,
    /// How many derivations this key is from the master (which is 0)
    pub depth: u8,
    /// Fingerprint of the parent key (0 for master)
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_number: ChildNumber,
    /// Private key
    pub private_key: PrivateKey,
    /// Chain code
    pub chain_code: ChainCode,
    _marker: ::std::marker::PhantomData<R>
}
serde_string_impl!(ExtendedPrivKey<R: VersionResolver>, "a BIP-32 extended private key");

/// Extended public key
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct ExtendedPubKey<R: VersionResolver> {
    /// Version bytes specifying to which network the key belongs
    /// and for which types of scriptPubkey it may be used
    pub version: KeyVersion,
    /// How many derivations this key is from the master (which is 0)
    pub depth: u8,
    /// Fingerprint of the parent key
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_number: ChildNumber,
    /// Public key
    pub public_key: PublicKey,
    /// Chain code
    pub chain_code: ChainCode,
    _marker: ::std::marker::PhantomData<R>
}
serde_string_impl!(ExtendedPubKey<R: VersionResolver>, "a BIP-32 extended public key");

/// A child number for a derived key
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub enum ChildNumber {
    /// Non-hardened key
    Normal {
        /// Key index, within [0, 2^31 - 1]
        index: u32
    },
    /// Hardened key
    Hardened {
        /// Key index, within [0, 2^31 - 1]
        index: u32
    },
}

impl ChildNumber {
    /// Create a [`Normal`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    ///
    /// [`Normal`]: #variant.Normal
    pub fn from_normal_idx(index: u32) -> Result<Self, Error> {
        if index & (1 << 31) == 0 {
            Ok(ChildNumber::Normal { index: index })
        } else {
            Err(Error::InvalidChildNumber(index))
        }
    }

    /// Create a [`Hardened`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    ///
    /// [`Hardened`]: #variant.Hardened
    pub fn from_hardened_idx(index: u32) -> Result<Self, Error> {
        if index & (1 << 31) == 0 {
            Ok(ChildNumber::Hardened { index: index })
        } else {
            Err(Error::InvalidChildNumber(index))
        }
    }

    /// Returns `true` if the child number is a [`Normal`] value.
    ///
    /// [`Normal`]: #variant.Normal
    pub fn is_normal(self) -> bool {
        !self.is_hardened()
    }

    /// Returns `true` if the child number is a [`Hardened`] value.
    ///
    /// [`Hardened`]: #variant.Hardened
    pub fn is_hardened(self) -> bool {
        match self {
            ChildNumber::Hardened {..} => true,
            ChildNumber::Normal {..} => false,
        }
    }

    /// Returns the child number that is a single increment from this one.
    pub fn increment(self) -> Result<ChildNumber, Error> {
        match self {
            ChildNumber::Normal{ index: idx } => ChildNumber::from_normal_idx(idx+1),
            ChildNumber::Hardened{ index: idx } => ChildNumber::from_hardened_idx(idx+1),
        }
    }
}

impl From<u32> for ChildNumber {
    fn from(number: u32) -> Self {
        if number & (1 << 31) != 0 {
            ChildNumber::Hardened { index: number ^ (1 << 31) }
        } else {
            ChildNumber::Normal { index: number }
        }
    }
}

impl From<ChildNumber> for u32 {
    fn from(cnum: ChildNumber) -> Self {
        match cnum {
            ChildNumber::Normal { index } => index,
            ChildNumber::Hardened { index } => index | (1 << 31),
        }
    }
}

impl fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ChildNumber::Hardened { index } => write!(f, "{}'", index),
            ChildNumber::Normal { index } => write!(f, "{}", index),
        }
    }
}

impl FromStr for ChildNumber {
    type Err = Error;

    fn from_str(inp: &str) -> Result<ChildNumber, Error> {
        let is_hardened = inp.chars().last().map_or(false, |l| l == '\'' || l == 'h');
        Ok(if is_hardened {
            ChildNumber::from_hardened_idx(inp[0..inp.len() - 1].parse().map_err(|_| Error::InvalidChildNumberFormat)?)?
        } else {
            ChildNumber::from_normal_idx(inp.parse().map_err(|_| Error::InvalidChildNumberFormat)?)?
        })
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ChildNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u32::deserialize(deserializer).map(ChildNumber::from)
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

/// A BIP-32 derivation path.
#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct DerivationPath(Vec<ChildNumber>);
impl_index_newtype!(DerivationPath, ChildNumber);
serde_string_impl!(DerivationPath, "a BIP-32 derivation path");

impl From<Vec<ChildNumber>> for DerivationPath {
    fn from(numbers: Vec<ChildNumber>) -> Self {
        DerivationPath(numbers)
    }
}

impl Into<Vec<ChildNumber>> for DerivationPath {
    fn into(self) -> Vec<ChildNumber> {
        self.0
    }
}

impl<'a> From<&'a [ChildNumber]> for DerivationPath {
    fn from(numbers: &'a [ChildNumber]) -> Self {
        DerivationPath(numbers.to_vec())
    }
}

impl ::std::iter::FromIterator<ChildNumber> for DerivationPath {
    fn from_iter<T>(iter: T) -> Self where T: IntoIterator<Item = ChildNumber> {
        DerivationPath(Vec::from_iter(iter))
    }
}

impl<'a> ::std::iter::IntoIterator for &'a DerivationPath {
    type Item = &'a ChildNumber;
    type IntoIter = ::std::slice::Iter<'a, ChildNumber>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl AsRef<[ChildNumber]> for DerivationPath {
    fn as_ref(&self) -> &[ChildNumber] {
        &self.0
    }
}

impl FromStr for DerivationPath {
    type Err = Error;

    fn from_str(path: &str) -> Result<DerivationPath, Error> {
        let mut parts = path.split('/');
        // First parts must be `m`.
        if parts.next().unwrap() != "m" {
            return Err(Error::InvalidDerivationPathFormat);
        }

        let ret: Result<Vec<ChildNumber>, Error> = parts.map(str::parse).collect();
        Ok(DerivationPath(ret?))
    }
}

/// An iterator over children of a [DerivationPath].
///
/// It is returned by the methods [DerivationPath::children_since],
/// [DerivationPath::normal_children] and [DerivationPath::hardened_children].
pub struct DerivationPathIterator<'a> {
    base: &'a DerivationPath,
    next_child: Option<ChildNumber>,
}

impl<'a> DerivationPathIterator<'a> {
    /// Start a new [DerivationPathIterator] at the given child.
    pub fn start_from(path: &'a DerivationPath, start: ChildNumber) -> DerivationPathIterator<'a> {
        DerivationPathIterator {
            base: path,
            next_child: Some(start),
        }
    }
}

impl<'a> Iterator for DerivationPathIterator<'a> {
    type Item = DerivationPath;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.next_child?;
        self.next_child = ret.increment().ok();
        Some(self.base.child(ret))
    }
}

impl DerivationPath {
    /// Create a new [DerivationPath] that is a child of this one.
    pub fn child(&self, cn: ChildNumber) -> DerivationPath {
        let mut path = self.0.clone();
        path.push(cn);
        DerivationPath(path)
    }

    /// Convert into a [DerivationPath] that is a child of this one.
    pub fn into_child(self, cn: ChildNumber) -> DerivationPath {
        let mut path = self.0;
        path.push(cn);
        DerivationPath(path)
    }

    /// Get an [Iterator] over the children of this [DerivationPath]
    /// starting with the given [ChildNumber].
    pub fn children_from(&self, cn: ChildNumber) -> DerivationPathIterator {
        DerivationPathIterator::start_from(&self, cn)
    }

    /// Get an [Iterator] over the unhardened children of this [DerivationPath].
    pub fn normal_children(&self) -> DerivationPathIterator {
        DerivationPathIterator::start_from(&self, ChildNumber::Normal{ index: 0 })
    }

    /// Get an [Iterator] over the hardened children of this [DerivationPath].
    pub fn hardened_children(&self) -> DerivationPathIterator {
        DerivationPathIterator::start_from(&self, ChildNumber::Hardened{ index: 0 })
    }

    /// Concatenate `self` with `path` and return the resulting new path.
    ///
    /// ```
    /// use bitcoin::util::bip32::{DerivationPath, ChildNumber};
    /// use std::str::FromStr;
    ///
    /// let base = DerivationPath::from_str("m/42").unwrap();
    ///
    /// let deriv_1 = base.extend(DerivationPath::from_str("m/0/1").unwrap());
    /// let deriv_2 = base.extend(&[
    ///     ChildNumber::from_normal_idx(0).unwrap(),
    ///     ChildNumber::from_normal_idx(1).unwrap()
    /// ]);
    ///
    /// assert_eq!(deriv_1, deriv_2);
    /// ```
    pub fn extend<T: AsRef<[ChildNumber]>>(&self, path: T) -> DerivationPath {
        let mut new_path = self.clone();
        new_path.0.extend_from_slice(path.as_ref());
        new_path
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("m")?;
        for cn in self.0.iter() {
            f.write_str("/")?;
            fmt::Display::fmt(cn, f)?;
        }
        Ok(())
    }
}

impl fmt::Debug for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

/// Full information on the used extended public key: fingerprint of the
/// master extended public key and a derivation path from it.
pub type KeySource = (Fingerprint, DerivationPath);

/// A BIP32 error
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// A pk->pk derivation was attempted on a hardened key
    CannotDeriveFromHardenedKey,
    /// A secp256k1 error occurred
    Ecdsa(secp256k1::Error),
    /// A child number was provided that was out of range
    InvalidChildNumber(u32),
    /// Error creating a master seed --- for application use
    RngError(String),
    /// Invalid childnumber format.
    InvalidChildNumberFormat,
    /// Invalid derivation path format.
    InvalidDerivationPathFormat,
    /// Unknown version magic bytes
    UnknownVersion([u8; 4])
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::CannotDeriveFromHardenedKey => f.write_str("cannot derive hardened key from public key"),
            Error::Ecdsa(ref e) => fmt::Display::fmt(e, f),
            Error::InvalidChildNumber(ref n) => write!(f, "child number {} is invalid (not within [0, 2^31 - 1])", n),
            Error::RngError(ref s) => write!(f, "rng error {}", s),
            Error::InvalidChildNumberFormat => f.write_str("invalid child number format"),
            Error::InvalidDerivationPathFormat => f.write_str("invalid derivation path format"),
            Error::UnknownVersion(ref bytes) => write!(f, "unknown version magic bytes: {:?}", bytes),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
       if let Error::Ecdsa(ref e) = *self {
           Some(e)
       } else {
           None
       }
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error { Error::Ecdsa(e) }
}

impl KeyVersion {
    /// Tries to construct [KeyVersion] object from a byte slice. If byte slice
    /// length is not equal to 4, returns `None`
    pub fn from_slice(version_slice: &[u8]) -> Option<KeyVersion> {
        if version_slice.len() != 4 {
            return None;
        }
        Some(KeyVersion::from_u32(endian::slice_to_u32_be(version_slice)))
    }

    /// Constructs [KeyVersion] from a fixed 4 bytes values
    pub fn from_bytes(version_bytes: [u8; 4]) -> KeyVersion {
        KeyVersion(version_bytes)
    }

    /// Constructs [KeyVersion from a `u32`-representation of the version
    /// bytes (the representation must be in bing endian format)
    pub fn from_u32(version_bytes: u32) -> KeyVersion {
        KeyVersion(endian::u32_to_array_be(version_bytes))
    }

    /// Converts version bytes into `u32` representation in big endian format
    pub fn to_u32(&self) -> u32 {
        endian::slice_to_u32_be(&self.0)
    }

    /// Returns slice representing internal version bytes
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns internal representation of version bytes
    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Constructs 4-byte array containing version byte values
    pub fn to_bytes(&self) -> [u8; 4] {
        self.0
    }

    /// Converts into 4-byte array containing version byte values
    pub fn into_bytes(self) -> [u8; 4] {
        self.0
    }
}

impl VersionResolver for DefaultResolver {
    type Network = Network;
    type Applications = KeyApplications;

    fn resolve(network: Self::Network, applicable_for: Self::Applications, is_priv: bool) -> KeyVersion {
        match (network, applicable_for, is_priv) {
            (Network::Bitcoin, KeyApplications::Legacy, false) => KeyVersion(VERSION_MAGIC_XPUB),
            (Network::Bitcoin, KeyApplications::Legacy, true) => KeyVersion(VERSION_MAGIC_XPRV),
            (Network::Bitcoin, KeyApplications::SegWitLegacySinglesig, false) => KeyVersion(VERSION_MAGIC_YPUB),
            (Network::Bitcoin, KeyApplications::SegWitLegacySinglesig, true) => KeyVersion(VERSION_MAGIC_YPRV),
            (Network::Bitcoin, KeyApplications::SegWitV0Singlesig, false) => KeyVersion(VERSION_MAGIC_ZPUB),
            (Network::Bitcoin, KeyApplications::SegWitV0Singlesig, true) => KeyVersion(VERSION_MAGIC_ZPRV),
            (Network::Bitcoin, KeyApplications::SegWitLegacyMultisig, false) => KeyVersion(VERSION_MAGIC_YPUB_MULTISIG),
            (Network::Bitcoin, KeyApplications::SegWitLegacyMultisig, true) => KeyVersion(VERSION_MAGIC_YPRV_MULTISIG),
            (Network::Bitcoin, KeyApplications::SegWitV0Miltisig, false) => KeyVersion(VERSION_MAGIC_ZPUB_MULTISIG),
            (Network::Bitcoin, KeyApplications::SegWitV0Miltisig, true) => KeyVersion(VERSION_MAGIC_ZPRV_MULTISIG),
            (_, KeyApplications::Legacy, false) => KeyVersion(VERSION_MAGIC_TPUB),
            (_, KeyApplications::Legacy, true) => KeyVersion(VERSION_MAGIC_TPRV),
            (_, KeyApplications::SegWitLegacySinglesig, false) => KeyVersion(VERSION_MAGIC_UPUB),
            (_, KeyApplications::SegWitLegacySinglesig, true) => KeyVersion(VERSION_MAGIC_UPRV),
            (_, KeyApplications::SegWitV0Singlesig, false) => KeyVersion(VERSION_MAGIC_VPUB),
            (_, KeyApplications::SegWitV0Singlesig, true) => KeyVersion(VERSION_MAGIC_VPRV),
            (_, KeyApplications::SegWitLegacyMultisig, false) => KeyVersion(VERSION_MAGIC_UPUB_MULTISIG),
            (_, KeyApplications::SegWitLegacyMultisig, true) => KeyVersion(VERSION_MAGIC_UPRV_MULTISIG),
            (_, KeyApplications::SegWitV0Miltisig, false) => KeyVersion(VERSION_MAGIC_VPUB_MULTISIG),
            (_, KeyApplications::SegWitV0Miltisig, true) => KeyVersion(VERSION_MAGIC_VPRV_MULTISIG),
        }
    }

    fn is_pub(kv: &KeyVersion) -> Option<bool> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPUB
            | &VERSION_MAGIC_YPUB
            | &VERSION_MAGIC_ZPUB
            | &VERSION_MAGIC_TPUB
            | &VERSION_MAGIC_UPUB
            | &VERSION_MAGIC_VPUB
            | &VERSION_MAGIC_YPUB_MULTISIG
            | &VERSION_MAGIC_ZPUB_MULTISIG
            | &VERSION_MAGIC_UPUB_MULTISIG
            | &VERSION_MAGIC_VPUB_MULTISIG => Some(true),
            &VERSION_MAGIC_XPRV
            | &VERSION_MAGIC_YPRV
            | &VERSION_MAGIC_ZPRV
            | &VERSION_MAGIC_TPRV
            | &VERSION_MAGIC_UPRV
            | &VERSION_MAGIC_VPRV
            | &VERSION_MAGIC_YPRV_MULTISIG
            | &VERSION_MAGIC_ZPRV_MULTISIG
            | &VERSION_MAGIC_UPRV_MULTISIG
            | &VERSION_MAGIC_VPRV_MULTISIG => Some(false),
            _ => None,
        }
    }

    fn is_prv(kv: &KeyVersion) -> Option<bool> {
        DefaultResolver::is_pub(kv).map(|v| !v)
    }

    fn network(kv: &KeyVersion) -> Option<Self::Network> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPRV
            | &VERSION_MAGIC_XPUB
            | &VERSION_MAGIC_YPRV
            | &VERSION_MAGIC_YPUB
            | &VERSION_MAGIC_ZPRV
            | &VERSION_MAGIC_ZPUB
            | &VERSION_MAGIC_YPRV_MULTISIG
            | &VERSION_MAGIC_YPUB_MULTISIG
            | &VERSION_MAGIC_ZPRV_MULTISIG
            | &VERSION_MAGIC_ZPUB_MULTISIG => Some(Network::Bitcoin),
            &VERSION_MAGIC_TPRV
            | &VERSION_MAGIC_TPUB
            | &VERSION_MAGIC_UPRV
            | &VERSION_MAGIC_UPUB
            | &VERSION_MAGIC_VPRV
            | &VERSION_MAGIC_VPUB
            | &VERSION_MAGIC_UPRV_MULTISIG
            | &VERSION_MAGIC_UPUB_MULTISIG
            | &VERSION_MAGIC_VPRV_MULTISIG
            | &VERSION_MAGIC_VPUB_MULTISIG => Some(Network::Testnet),
            _ => None,
        }
    }

    fn applications(kv: &KeyVersion) -> Option<Self::Applications> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPUB
            | &VERSION_MAGIC_XPRV
            | &VERSION_MAGIC_TPUB
            | &VERSION_MAGIC_TPRV => Some(KeyApplications::Legacy),
            &VERSION_MAGIC_YPUB
            | &VERSION_MAGIC_YPRV
            | &VERSION_MAGIC_UPUB
            | &VERSION_MAGIC_UPRV => Some(KeyApplications::SegWitLegacySinglesig),
            &VERSION_MAGIC_YPUB_MULTISIG
            | &VERSION_MAGIC_YPRV_MULTISIG
            | &VERSION_MAGIC_UPUB_MULTISIG
            | &VERSION_MAGIC_UPRV_MULTISIG => Some(KeyApplications::SegWitLegacyMultisig),
            &VERSION_MAGIC_ZPUB
            | &VERSION_MAGIC_ZPRV
            | &VERSION_MAGIC_VPUB
            | &VERSION_MAGIC_VPRV => Some(KeyApplications::SegWitV0Singlesig),
            &VERSION_MAGIC_ZPUB_MULTISIG
            | &VERSION_MAGIC_ZPRV_MULTISIG
            | &VERSION_MAGIC_VPUB_MULTISIG
            | &VERSION_MAGIC_VPRV_MULTISIG => Some(KeyApplications::SegWitV0Miltisig),
            _ => None,
        }
    }

    fn derivation_path(kv: &KeyVersion) -> Option<DerivationPath> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPUB
            | &VERSION_MAGIC_XPRV => Some(DerivationPath::from(vec![ChildNumber::Hardened { index: 44 }, ChildNumber::Hardened { index: 0 }])),
            &VERSION_MAGIC_TPUB
            | &VERSION_MAGIC_TPRV => Some(DerivationPath::from(vec![ChildNumber::Hardened { index: 44 }, ChildNumber::Hardened { index: 1 }])),
            &VERSION_MAGIC_YPUB
            | &VERSION_MAGIC_YPRV => Some(DerivationPath::from(vec![ChildNumber::Hardened { index: 49 }, ChildNumber::Hardened { index: 0 }])),
            &VERSION_MAGIC_UPUB
            | &VERSION_MAGIC_UPRV => Some(DerivationPath::from(vec![ChildNumber::Hardened { index: 49 }, ChildNumber::Hardened { index: 1 }])),
            &VERSION_MAGIC_ZPUB
            | &VERSION_MAGIC_ZPRV => Some(DerivationPath::from(vec![ChildNumber::Hardened { index: 84 }, ChildNumber::Hardened { index: 0 }])),
            &VERSION_MAGIC_VPUB
            | &VERSION_MAGIC_VPRV => Some(DerivationPath::from(vec![ChildNumber::Hardened { index: 84 }, ChildNumber::Hardened { index: 1 }])),
            _ => None,
        }
    }

    fn make_pub(kv: &KeyVersion) -> Option<KeyVersion> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPRV => Some(KeyVersion::from_bytes(VERSION_MAGIC_XPUB)),
            &VERSION_MAGIC_YPRV => Some(KeyVersion::from_bytes(VERSION_MAGIC_YPUB)),
            &VERSION_MAGIC_ZPRV => Some(KeyVersion::from_bytes(VERSION_MAGIC_ZPUB)),
            &VERSION_MAGIC_TPRV => Some(KeyVersion::from_bytes(VERSION_MAGIC_TPUB)),
            &VERSION_MAGIC_UPRV => Some(KeyVersion::from_bytes(VERSION_MAGIC_UPUB)),
            &VERSION_MAGIC_VPRV => Some(KeyVersion::from_bytes(VERSION_MAGIC_VPUB)),
            &VERSION_MAGIC_YPRV_MULTISIG => Some(KeyVersion::from_bytes(VERSION_MAGIC_YPUB_MULTISIG)),
            &VERSION_MAGIC_ZPRV_MULTISIG => Some(KeyVersion::from_bytes(VERSION_MAGIC_ZPUB_MULTISIG)),
            &VERSION_MAGIC_UPRV_MULTISIG => Some(KeyVersion::from_bytes(VERSION_MAGIC_UPUB_MULTISIG)),
            &VERSION_MAGIC_VPRV_MULTISIG => Some(KeyVersion::from_bytes(VERSION_MAGIC_VPUB_MULTISIG)),
            &VERSION_MAGIC_XPUB
            | &VERSION_MAGIC_YPUB
            | &VERSION_MAGIC_ZPUB
            | &VERSION_MAGIC_TPUB
            | &VERSION_MAGIC_UPUB
            | &VERSION_MAGIC_VPUB
            | &VERSION_MAGIC_YPUB_MULTISIG
            | &VERSION_MAGIC_ZPUB_MULTISIG
            | &VERSION_MAGIC_UPUB_MULTISIG
            | &VERSION_MAGIC_VPUB_MULTISIG => Some(kv.clone()),
            _ => None,
        }
    }

    fn make_prv(kv: &KeyVersion) -> Option<KeyVersion> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPUB => Some(KeyVersion::from_bytes(VERSION_MAGIC_XPRV)),
            &VERSION_MAGIC_YPUB => Some(KeyVersion::from_bytes(VERSION_MAGIC_YPRV)),
            &VERSION_MAGIC_ZPUB => Some(KeyVersion::from_bytes(VERSION_MAGIC_ZPRV)),
            &VERSION_MAGIC_TPUB => Some(KeyVersion::from_bytes(VERSION_MAGIC_TPRV)),
            &VERSION_MAGIC_UPUB => Some(KeyVersion::from_bytes(VERSION_MAGIC_UPRV)),
            &VERSION_MAGIC_VPUB => Some(KeyVersion::from_bytes(VERSION_MAGIC_VPRV)),
            &VERSION_MAGIC_YPUB_MULTISIG => Some(KeyVersion::from_bytes(VERSION_MAGIC_YPRV_MULTISIG)),
            &VERSION_MAGIC_ZPUB_MULTISIG => Some(KeyVersion::from_bytes(VERSION_MAGIC_ZPRV_MULTISIG)),
            &VERSION_MAGIC_UPUB_MULTISIG => Some(KeyVersion::from_bytes(VERSION_MAGIC_UPRV_MULTISIG)),
            &VERSION_MAGIC_VPUB_MULTISIG => Some(KeyVersion::from_bytes(VERSION_MAGIC_VPRV_MULTISIG)),
            &VERSION_MAGIC_XPRV
            | &VERSION_MAGIC_YPRV
            | &VERSION_MAGIC_ZPRV
            | &VERSION_MAGIC_TPRV
            | &VERSION_MAGIC_UPRV
            | &VERSION_MAGIC_VPRV
            | &VERSION_MAGIC_YPRV_MULTISIG
            | &VERSION_MAGIC_ZPRV_MULTISIG
            | &VERSION_MAGIC_UPRV_MULTISIG
            | &VERSION_MAGIC_VPRV_MULTISIG => Some(kv.clone()),
            _ => None,
        }
    }
}

impl<R: VersionResolver<Network=Network>> ExtendedPrivKey<R> {
    /// Construct a new master key from a seed value
    pub fn new_master(kv: KeyVersion, seed: &[u8]) -> Result<ExtendedPrivKey<R>, Error> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(b"Bitcoin seed");
        hmac_engine.input(seed);
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        Ok(ExtendedPrivKey {
            version: kv,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from_normal_idx(0)?,
            private_key: PrivateKey {
                compressed: true,
                network: kv.network::<R>().ok_or(Error::UnknownVersion(kv.as_bytes().clone()))?,
                key: secp256k1::SecretKey::from_slice(
                    &hmac_result[..32]
                ).map_err(Error::Ecdsa)?,
            },
            chain_code: ChainCode::from(&hmac_result[32..]),
            _marker: Default::default()
        })
    }

    /// Attempts to derive an extended private key from a path.
    ///
    /// The `path` argument can be both of type `DerivationPath` or `Vec<ChildNumber>`.
    pub fn derive_priv<C: secp256k1::Signing, P: AsRef<[ChildNumber]>>(
        &self,
        secp: &Secp256k1<C>,
        path: &P,
    ) -> Result<ExtendedPrivKey<R>, Error> {
        let mut sk: ExtendedPrivKey<R> = *self;
        for cnum in path.as_ref() {
            sk = sk.ckd_priv(secp, *cnum)?;
        }
        Ok(sk)
    }

    /// Private->Private child key derivation
    pub fn ckd_priv<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>, i: ChildNumber) -> Result<ExtendedPrivKey<R>, Error> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);
        match i {
            ChildNumber::Normal { .. } => {
                // Non-hardened key: compute public data and use that
                hmac_engine.input(&PublicKey::from_private_key(secp, &self.private_key).key.serialize()[..]);
            }
            ChildNumber::Hardened { .. } => {
                // Hardened key: use only secret data to prevent public derivation
                hmac_engine.input(&[0u8]);
                hmac_engine.input(&self.private_key[..]);
            }
        }

        hmac_engine.input(&endian::u32_to_array_be(u32::from(i)));
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
        let mut sk = PrivateKey {
            compressed: true,
            network: self.version.network::<R>().ok_or(Error::UnknownVersion(self.version.as_bytes().clone()))?,
            key: secp256k1::SecretKey::from_slice(&hmac_result[..32]).map_err(Error::Ecdsa)?,
        };
        sk.key.add_assign(&self.private_key[..]).map_err(Error::Ecdsa)?;

        Ok(ExtendedPrivKey {
            version: self.version,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(secp)?,
            child_number: i,
            private_key: sk,
            chain_code: ChainCode::from(&hmac_result[32..]),
            _marker: Default::default()
        })
    }

    /// Returns the HASH160 of the chaincode
    pub fn identifier<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> Result<XpubIdentifier, Error> {
        Ok(ExtendedPubKey::<R>::from_private(secp, self)
            .ok_or(Error::UnknownVersion(self.version.as_bytes().clone()))?
            .identifier())
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> Result<Fingerprint, Error> {
        Ok(Fingerprint::from(&self.identifier(secp)?[0..4]))
    }
}

impl<R: VersionResolver<Network=Network>> ExtendedPubKey<R> {
    /// Derives a public key from a private key
    pub fn from_private<C: secp256k1::Signing>(secp: &Secp256k1<C>, sk: &ExtendedPrivKey<R>) -> Option<ExtendedPubKey<R>> {
        Some(ExtendedPubKey {
            version: sk.version.try_to_pub::<R>()?,
            depth: sk.depth,
            parent_fingerprint: sk.parent_fingerprint,
            child_number: sk.child_number,
            public_key: PublicKey::from_private_key(secp, &sk.private_key),
            chain_code: sk.chain_code,
            _marker: Default::default()
        })
    }

    /// Attempts to derive an extended public key from a path.
    ///
    /// The `path` argument can be both of type `DerivationPath` or `Vec<ChildNumber>`.
    pub fn derive_pub<C: secp256k1::Verification, P: AsRef<[ChildNumber]>>(
        &self,
        secp: &Secp256k1<C>,
        path: &P,
    ) -> Result<ExtendedPubKey<R>, Error> {
        let mut pk: ExtendedPubKey<R> = *self;
        for cnum in path.as_ref() {
            pk = pk.ckd_pub(secp, *cnum)?
        }
        Ok(pk)
    }

    /// Compute the scalar tweak added to this key to get a child key
    pub fn ckd_pub_tweak(&self, i: ChildNumber) -> Result<(PrivateKey, ChainCode), Error> {
        match i {
            ChildNumber::Hardened { .. } => {
                Err(Error::CannotDeriveFromHardenedKey)
            }
            ChildNumber::Normal { index: n } => {
                let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);
                hmac_engine.input(&self.public_key.key.serialize()[..]);
                hmac_engine.input(&endian::u32_to_array_be(n));

                let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

                let private_key = PrivateKey {
                    compressed: true,
                    network: self.version.network::<R>().ok_or(Error::UnknownVersion(self.version.as_bytes().clone()))?,
                    key: secp256k1::SecretKey::from_slice(&hmac_result[..32])?,
                };
                let chain_code = ChainCode::from(&hmac_result[32..]);
                Ok((private_key, chain_code))
            }
        }
    }

    /// Public->Public child key derivation
    pub fn ckd_pub<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        i: ChildNumber,
    ) -> Result<ExtendedPubKey<R>, Error> {
        let (sk, chain_code) = self.ckd_pub_tweak(i)?;
        let mut pk = self.public_key;
        pk.key.add_exp_assign(secp, &sk[..]).map_err(Error::Ecdsa)?;

        Ok(ExtendedPubKey {
            version: self.version,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: i,
            public_key: pk,
            chain_code: chain_code,
            _marker: Default::default()
        })
    }
}

impl<R: VersionResolver> ExtendedPubKey<R> {
    /// Returns the HASH160 of the chaincode
    pub fn identifier(&self) -> XpubIdentifier {
        let mut engine = XpubIdentifier::engine();
        self.public_key.write_into(&mut engine);
        XpubIdentifier::from_engine(engine)
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from(&self.identifier()[0..4])
    }
}

impl<R: VersionResolver> fmt::Display for ExtendedPrivKey<R> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(self.version.as_bytes());
        ret[4] = self.depth as u8;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&endian::u32_to_array_be(u32::from(self.child_number)));
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45] = 0;
        ret[46..78].copy_from_slice(&self.private_key[..]);
        fmt.write_str(&base58::check_encode_slice(&ret[..]))
    }
}

impl<R: VersionResolver> FromStr for ExtendedPrivKey<R> {
    type Err = base58::Error;

    fn from_str(inp: &str) -> Result<ExtendedPrivKey<R>, base58::Error> {
        let data = base58::from_check(inp)?;

        if data.len() != 78 {
            return Err(base58::Error::InvalidLength(data.len()));
        }

        let cn_int: u32 = endian::slice_to_u32_be(&data[9..13]);
        let child_number: ChildNumber = ChildNumber::from(cn_int);

        let ver_bytes = &data[0..4];
        let invalid_ver_err = base58::Error::InvalidVersion(ver_bytes.to_vec());
        let kv = KeyVersion::from_slice(&ver_bytes)
            .ok_or(invalid_ver_err.clone())?;
        if !kv.is_prv::<R>().ok_or(invalid_ver_err.clone())? {
            return Err(invalid_ver_err.clone());
        }

        Ok(ExtendedPrivKey {
            version: kv,
            depth: data[4],
            parent_fingerprint: Fingerprint::from(&data[5..9]),
            child_number: child_number,
            chain_code: ChainCode::from(&data[13..45]),
            private_key: PrivateKey {
                compressed: true,
                network: kv.network::<DefaultResolver>().ok_or(invalid_ver_err)?,
                key: secp256k1::SecretKey::from_slice(
                    &data[46..78]
                ).map_err(|e|
                    base58::Error::Other(e.to_string())
                )?,
            },
            _marker: Default::default()
        })
    }
}

impl<R: VersionResolver> fmt::Display for ExtendedPubKey<R> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(self.version.as_bytes());
        ret[4] = self.depth as u8;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&endian::u32_to_array_be(u32::from(self.child_number)));
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45..78].copy_from_slice(&self.public_key.key.serialize()[..]);
        fmt.write_str(&base58::check_encode_slice(&ret[..]))
    }
}

impl<R: VersionResolver> FromStr for ExtendedPubKey<R> {
    type Err = base58::Error;

    fn from_str(inp: &str) -> Result<ExtendedPubKey<R>, base58::Error> {
        let data = base58::from_check(inp)?;

        if data.len() != 78 {
            return Err(base58::Error::InvalidLength(data.len()));
        }

        let cn_int: u32 = endian::slice_to_u32_be(&data[9..13]);
        let child_number: ChildNumber = ChildNumber::from(cn_int);

        let ver_bytes = &data[0..4];
        let invalid_ver_err = base58::Error::InvalidVersion(ver_bytes.to_vec());
        let kv = KeyVersion::from_slice(&ver_bytes)
            .ok_or(invalid_ver_err.clone())?;
        if !kv.is_pub::<R>().ok_or(invalid_ver_err.clone())? {
            return Err(invalid_ver_err);
        }

        Ok(ExtendedPubKey {
            version: kv,
            depth: data[4],
            parent_fingerprint: Fingerprint::from(&data[5..9]),
            child_number: child_number,
            chain_code: ChainCode::from(&data[13..45]),
            public_key: PublicKey::from_slice(
                             &data[45..78]).map_err(|e|
                                 base58::Error::Other(e.to_string()))?,
            _marker: Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::ChildNumber::{Hardened, Normal};

    use std::str::FromStr;
    use std::string::ToString;

    use secp256k1::{self, Secp256k1};
    use hashes::hex::FromHex;

    use network::constants::Network::{self, Bitcoin};

    #[test]
    fn test_parse_derivation_path() {
        assert_eq!(DerivationPath::from_str("42"), Err(Error::InvalidDerivationPathFormat));
        assert_eq!(DerivationPath::from_str("n/0'/0"), Err(Error::InvalidDerivationPathFormat));
        assert_eq!(DerivationPath::from_str("4/m/5"), Err(Error::InvalidDerivationPathFormat));
        assert_eq!(DerivationPath::from_str("m//3/0'"), Err(Error::InvalidChildNumberFormat));
        assert_eq!(DerivationPath::from_str("m/0h/0x"), Err(Error::InvalidChildNumberFormat));
        assert_eq!(DerivationPath::from_str("m/2147483648"), Err(Error::InvalidChildNumber(2147483648)));

        assert_eq!(DerivationPath::from_str("m"), Ok(vec![].into()));
        assert_eq!(
            DerivationPath::from_str("m/0'"),
            Ok(vec![ChildNumber::from_hardened_idx(0).unwrap()].into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0'/1"),
            Ok(vec![ChildNumber::from_hardened_idx(0).unwrap(), ChildNumber::from_normal_idx(1).unwrap()].into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0h/1/2'"),
            Ok(vec![
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(2).unwrap(),
            ].into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0'/1/2h/2"),
            Ok(vec![
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(2).unwrap(),
                ChildNumber::from_normal_idx(2).unwrap(),
            ].into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0'/1/2'/2/1000000000"),
            Ok(vec![
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(2).unwrap(),
                ChildNumber::from_normal_idx(2).unwrap(),
                ChildNumber::from_normal_idx(1000000000).unwrap(),
            ].into())
        );
    }

    #[test]
    fn test_derivation_path_conversion_index() {
        let path = DerivationPath::from_str("m/0h/1/2'").unwrap();
        let numbers: Vec<ChildNumber> = path.clone().into();
        let path2: DerivationPath = numbers.into();
        assert_eq!(path, path2);
        assert_eq!(&path[..2], &[ChildNumber::from_hardened_idx(0).unwrap(), ChildNumber::from_normal_idx(1).unwrap()]);
        let indexed: DerivationPath = path[..2].into();
        assert_eq!(indexed, DerivationPath::from_str("m/0h/1").unwrap());
        assert_eq!(indexed.child(ChildNumber::from_hardened_idx(2).unwrap()), path);
    }

    fn test_path<C: secp256k1::Signing + secp256k1::Verification>(secp: &Secp256k1<C>,
                 network: Network,
                 seed: &[u8],
                 path: DerivationPath,
                 expected_sk: &str,
                 expected_pk: &str) {

        let mut sk = ExtendedPrivKey::<DefaultResolver>::new_master(DefaultResolver::resolve(network, KeyApplications::Legacy, true), seed).unwrap();
        let mut pk = ExtendedPubKey::from_private(secp, &sk).unwrap();

        // Check derivation convenience method for ExtendedPrivKey
        assert_eq!(
            &sk.derive_priv(secp, &path).unwrap().to_string()[..],
            expected_sk
        );

        // Check derivation convenience method for ExtendedPubKey, should error
        // appropriately if any ChildNumber is hardened
        if path.0.iter().any(|cnum| cnum.is_hardened()) {
            assert_eq!(
                pk.derive_pub(secp, &path),
                Err(Error::CannotDeriveFromHardenedKey)
            );
        } else {
            assert_eq!(
                &pk.derive_pub(secp, &path).unwrap().to_string()[..],
                expected_pk
            );
        }

        // Derive keys, checking hardened and non-hardened derivation one-by-one
        for &num in path.0.iter() {
            sk = sk.ckd_priv(secp, num).unwrap();
            match num {
                Normal {..} => {
                    let pk2 = pk.ckd_pub(secp, num).unwrap();
                    pk = ExtendedPubKey::from_private(secp, &sk).unwrap();
                    assert_eq!(pk, pk2);
                }
                Hardened {..} => {
                    assert_eq!(
                        pk.ckd_pub(secp, num),
                        Err(Error::CannotDeriveFromHardenedKey)
                    );
                    pk = ExtendedPubKey::from_private(secp, &sk).unwrap();
                }
            }
        }

        // Check result against expected base58
        assert_eq!(&sk.to_string()[..], expected_sk);
        assert_eq!(&pk.to_string()[..], expected_pk);
        // Check decoded base58 against result
        let decoded_sk = ExtendedPrivKey::from_str(expected_sk);
        let decoded_pk = ExtendedPubKey::from_str(expected_pk);
        assert_eq!(Ok(sk), decoded_sk);
        assert_eq!(Ok(pk), decoded_pk);
    }

    #[test]
    fn test_increment() {
        let idx = 9345497; // randomly generated, I promise
        let cn = ChildNumber::from_normal_idx(idx).unwrap();
        assert_eq!(cn.increment().ok(), Some(ChildNumber::from_normal_idx(idx+1).unwrap()));
        let cn = ChildNumber::from_hardened_idx(idx).unwrap();
        assert_eq!(cn.increment().ok(), Some(ChildNumber::from_hardened_idx(idx+1).unwrap()));

        let max = (1<<31)-1;
        let cn = ChildNumber::from_normal_idx(max).unwrap();
        assert_eq!(cn.increment().err(), Some(Error::InvalidChildNumber(1<<31)));
        let cn = ChildNumber::from_hardened_idx(max).unwrap();
        assert_eq!(cn.increment().err(), Some(Error::InvalidChildNumber(1<<31)));

        let cn = ChildNumber::from_normal_idx(350).unwrap();
        let path = DerivationPath::from_str("m/42'").unwrap();
        let mut iter = path.children_from(cn);
        assert_eq!(iter.next(), Some("m/42'/350".parse().unwrap()));
        assert_eq!(iter.next(), Some("m/42'/351".parse().unwrap()));

        let path = DerivationPath::from_str("m/42'/350'").unwrap();
        let mut iter = path.normal_children();
        assert_eq!(iter.next(), Some("m/42'/350'/0".parse().unwrap()));
        assert_eq!(iter.next(), Some("m/42'/350'/1".parse().unwrap()));

        let path = DerivationPath::from_str("m/42'/350'").unwrap();
        let mut iter = path.hardened_children();
        assert_eq!(iter.next(), Some("m/42'/350'/0'".parse().unwrap()));
        assert_eq!(iter.next(), Some("m/42'/350'/1'".parse().unwrap()));

        let cn = ChildNumber::from_hardened_idx(42350).unwrap();
        let path = DerivationPath::from_str("m/42'").unwrap();
        let mut iter = path.children_from(cn);
        assert_eq!(iter.next(), Some("m/42'/42350'".parse().unwrap()));
        assert_eq!(iter.next(), Some("m/42'/42351'".parse().unwrap()));

        let cn = ChildNumber::from_hardened_idx(max).unwrap();
        let path = DerivationPath::from_str("m/42'").unwrap();
        let mut iter = path.children_from(cn);
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_vector_1() {
        let secp = Secp256k1::new();
        let seed = Vec::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();

        // m
        test_path(&secp, Bitcoin, &seed, "m".parse().unwrap(),
                  "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                  "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");

        // m/0h
        test_path(&secp, Bitcoin, &seed, "m/0h".parse().unwrap(),
                  "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                  "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw");

        // m/0h/1
        test_path(&secp, Bitcoin, &seed, "m/0h/1".parse().unwrap(),
                   "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                   "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ");

        // m/0h/1/2h
        test_path(&secp, Bitcoin, &seed, "m/0h/1/2h".parse().unwrap(),
                  "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                  "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5");

        // m/0h/1/2h/2
        test_path(&secp, Bitcoin, &seed, "m/0h/1/2h/2".parse().unwrap(),
                  "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                  "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV");

        // m/0h/1/2h/2/1000000000
        test_path(&secp, Bitcoin, &seed, "m/0h/1/2h/2/1000000000".parse().unwrap(),
                  "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                  "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy");
    }

    #[test]
    fn test_vector_2() {
        let secp = Secp256k1::new();
        let seed = Vec::from_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();

        // m
        test_path(&secp, Bitcoin, &seed, "m".parse().unwrap(),
                  "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                  "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB");

        // m/0
        test_path(&secp, Bitcoin, &seed, "m/0".parse().unwrap(),
                  "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                  "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH");

        // m/0/2147483647h
        test_path(&secp, Bitcoin, &seed, "m/0/2147483647h".parse().unwrap(),
                  "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                  "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a");

        // m/0/2147483647h/1
        test_path(&secp, Bitcoin, &seed, "m/0/2147483647h/1".parse().unwrap(),
                  "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                  "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon");

        // m/0/2147483647h/1/2147483646h
        test_path(&secp, Bitcoin, &seed, "m/0/2147483647h/1/2147483646h".parse().unwrap(),
                  "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                  "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL");

        // m/0/2147483647h/1/2147483646h/2
        test_path(&secp, Bitcoin, &seed, "m/0/2147483647h/1/2147483646h/2".parse().unwrap(),
                  "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                  "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt");
    }

    #[test]
    fn test_vector_3() {
        let secp = Secp256k1::new();
        let seed = Vec::from_hex("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be").unwrap();

        // m
        test_path(&secp, Bitcoin, &seed, "m".parse().unwrap(),
                  "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
                  "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13");

        // m/0h
        test_path(&secp, Bitcoin, &seed, "m/0h".parse().unwrap(),
                  "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
                  "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y");

    }

    #[test]
    #[cfg(feature = "serde")]
    pub fn encode_decode_childnumber() {
        serde_round_trip!(ChildNumber::from_normal_idx(0).unwrap());
        serde_round_trip!(ChildNumber::from_normal_idx(1).unwrap());
        serde_round_trip!(ChildNumber::from_normal_idx((1 << 31) - 1).unwrap());
        serde_round_trip!(ChildNumber::from_hardened_idx(0).unwrap());
        serde_round_trip!(ChildNumber::from_hardened_idx(1).unwrap());
        serde_round_trip!(ChildNumber::from_hardened_idx((1 << 31) - 1).unwrap());
    }

    #[test]
    #[cfg(feature = "serde")]
    pub fn encode_fingerprint_chaincode() {
        use serde_json;
        let fp = Fingerprint::from(&[1u8,2,3,42][..]);
        let cc = ChainCode::from(
            &[1u8,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2][..]
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
}

