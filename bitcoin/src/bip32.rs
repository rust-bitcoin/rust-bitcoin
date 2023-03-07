// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! BIP32 implementation.
//!
//! Implementation of BIP32 hierarchical deterministic wallets, as defined
//! at <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>.
//!

use core::convert::TryInto;
use core::default::Default;
use core::fmt;
use core::ops::Index;
use core::str::FromStr;

use bitcoin_internals::{impl_array_newtype, write_err};
use secp256k1::{self, Secp256k1, XOnlyPublicKey};
#[cfg(feature = "serde")]
use serde;

use crate::base58;
use crate::crypto::key::{self, KeyPair, PrivateKey, PublicKey};
use crate::hash_types::XpubIdentifier;
use crate::hashes::{hex, sha512, Hash, HashEngine, Hmac, HmacEngine};
use crate::internal_macros::impl_bytes_newtype;
use crate::io::Write;
use crate::network::constants::Network;
use crate::prelude::*;

/// A chain code
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainCode([u8; 32]);
impl_array_newtype!(ChainCode, u8, 32);
impl_bytes_newtype!(ChainCode, 32);

impl ChainCode {
    fn from_hmac(hmac: Hmac<sha512::Hash>) -> Self {
        hmac[32..].try_into().expect("half of hmac is guaranteed to be 32 bytes")
    }
}

/// A fingerprint
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Fingerprint([u8; 4]);
impl_array_newtype!(Fingerprint, u8, 4);
impl_bytes_newtype!(Fingerprint, 4);

/// Extended private key
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct ExtendedPrivKey {
    /// The network this key is to be used on
    pub network: Network,
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
crate::serde_utils::serde_string_impl!(ExtendedPrivKey, "a BIP-32 extended private key");

#[cfg(not(feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(not(feature = "std"))))]
impl fmt::Debug for ExtendedPrivKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ExtendedPrivKey")
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
pub struct ExtendedPubKey {
    /// The network this key is to be used on
    pub network: Network,
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
crate::serde_utils::serde_string_impl!(ExtendedPubKey, "a BIP-32 extended public key");

/// A child number for a derived key
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub enum ChildNumber {
    /// Non-hardened key
    Normal {
        /// Key index, within [0, 2^31 - 1]
        index: u32,
    },
    /// Hardened key
    Hardened {
        /// Key index, within [0, 2^31 - 1]
        index: u32,
    },
}

impl ChildNumber {
    /// Create a [`Normal`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    ///
    /// [`Normal`]: #variant.Normal
    pub fn from_normal_idx(index: u32) -> Result<Self, Error> {
        if index & (1 << 31) == 0 {
            Ok(ChildNumber::Normal { index })
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
            Ok(ChildNumber::Hardened { index })
        } else {
            Err(Error::InvalidChildNumber(index))
        }
    }

    /// Returns `true` if the child number is a [`Normal`] value.
    ///
    /// [`Normal`]: #variant.Normal
    pub fn is_normal(&self) -> bool { !self.is_hardened() }

    /// Returns `true` if the child number is a [`Hardened`] value.
    ///
    /// [`Hardened`]: #variant.Hardened
    pub fn is_hardened(&self) -> bool {
        match self {
            ChildNumber::Hardened { .. } => true,
            ChildNumber::Normal { .. } => false,
        }
    }

    /// Returns the child number that is a single increment from this one.
    pub fn increment(self) -> Result<ChildNumber, Error> {
        match self {
            ChildNumber::Normal { index: idx } => ChildNumber::from_normal_idx(idx + 1),
            ChildNumber::Hardened { index: idx } => ChildNumber::from_hardened_idx(idx + 1),
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
            ChildNumber::Hardened { index } => {
                fmt::Display::fmt(&index, f)?;
                let alt = f.alternate();
                f.write_str(if alt { "h" } else { "'" })
            }
            ChildNumber::Normal { index } => fmt::Display::fmt(&index, f),
        }
    }
}

impl FromStr for ChildNumber {
    type Err = Error;

    fn from_str(inp: &str) -> Result<ChildNumber, Error> {
        let is_hardened = inp.chars().last().map_or(false, |l| l == '\'' || l == 'h');
        Ok(if is_hardened {
            ChildNumber::from_hardened_idx(
                inp[0..inp.len() - 1].parse().map_err(|_| Error::InvalidChildNumberFormat)?,
            )?
        } else {
            ChildNumber::from_normal_idx(inp.parse().map_err(|_| Error::InvalidChildNumberFormat)?)?
        })
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> serde::Deserialize<'de> for ChildNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u32::deserialize(deserializer).map(ChildNumber::from)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl serde::Serialize for ChildNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        u32::from(*self).serialize(serializer)
    }
}

/// Trait that allows possibly failable conversion from a type into a
/// derivation path
pub trait IntoDerivationPath {
    /// Convers a given type into a [`DerivationPath`] with possible error
    fn into_derivation_path(self) -> Result<DerivationPath, Error>;
}

/// A BIP-32 derivation path.
#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct DerivationPath(Vec<ChildNumber>);

#[cfg(feature = "serde")]
crate::serde_utils::serde_string_impl!(DerivationPath, "a BIP-32 derivation path");

impl<I> Index<I> for DerivationPath
where
    Vec<ChildNumber>: Index<I>,
{
    type Output = <Vec<ChildNumber> as Index<I>>::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output { &self.0[index] }
}

impl Default for DerivationPath {
    fn default() -> DerivationPath { DerivationPath::master() }
}

impl<T> IntoDerivationPath for T
where
    T: Into<DerivationPath>,
{
    fn into_derivation_path(self) -> Result<DerivationPath, Error> { Ok(self.into()) }
}

impl IntoDerivationPath for String {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> { self.parse() }
}

impl<'a> IntoDerivationPath for &'a str {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> { self.parse() }
}

impl From<Vec<ChildNumber>> for DerivationPath {
    fn from(numbers: Vec<ChildNumber>) -> Self { DerivationPath(numbers) }
}

impl From<DerivationPath> for Vec<ChildNumber> {
    fn from(path: DerivationPath) -> Self { path.0 }
}

impl<'a> From<&'a [ChildNumber]> for DerivationPath {
    fn from(numbers: &'a [ChildNumber]) -> Self { DerivationPath(numbers.to_vec()) }
}

impl core::iter::FromIterator<ChildNumber> for DerivationPath {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = ChildNumber>,
    {
        DerivationPath(Vec::from_iter(iter))
    }
}

impl<'a> core::iter::IntoIterator for &'a DerivationPath {
    type Item = &'a ChildNumber;
    type IntoIter = slice::Iter<'a, ChildNumber>;
    fn into_iter(self) -> Self::IntoIter { self.0.iter() }
}

impl AsRef<[ChildNumber]> for DerivationPath {
    fn as_ref(&self) -> &[ChildNumber] { &self.0 }
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
/// It is returned by the methods [DerivationPath::children_from],
/// [DerivationPath::normal_children] and [DerivationPath::hardened_children].
pub struct DerivationPathIterator<'a> {
    base: &'a DerivationPath,
    next_child: Option<ChildNumber>,
}

impl<'a> DerivationPathIterator<'a> {
    /// Start a new [DerivationPathIterator] at the given child.
    pub fn start_from(path: &'a DerivationPath, start: ChildNumber) -> DerivationPathIterator<'a> {
        DerivationPathIterator { base: path, next_child: Some(start) }
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
    /// Returns length of the derivation path
    pub fn len(&self) -> usize { self.0.len() }

    /// Returns `true` if the derivation path is empty
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Returns derivation path for a master key (i.e. empty derivation path)
    pub fn master() -> DerivationPath { DerivationPath(vec![]) }

    /// Returns whether derivation path represents master key (i.e. it's length
    /// is empty). True for `m` path.
    pub fn is_master(&self) -> bool { self.0.is_empty() }

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
        DerivationPathIterator::start_from(self, cn)
    }

    /// Get an [Iterator] over the unhardened children of this [DerivationPath].
    pub fn normal_children(&self) -> DerivationPathIterator {
        DerivationPathIterator::start_from(self, ChildNumber::Normal { index: 0 })
    }

    /// Get an [Iterator] over the hardened children of this [DerivationPath].
    pub fn hardened_children(&self) -> DerivationPathIterator {
        DerivationPathIterator::start_from(self, ChildNumber::Hardened { index: 0 })
    }

    /// Concatenate `self` with `path` and return the resulting new path.
    ///
    /// ```
    /// use bitcoin::bip32::{DerivationPath, ChildNumber};
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self, f) }
}

/// Full information on the used extended public key: fingerprint of the
/// master extended public key and a derivation path from it.
pub type KeySource = (Fingerprint, DerivationPath);

/// A BIP32 error
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub enum Error {
    /// A pk->pk derivation was attempted on a hardened key
    CannotDeriveFromHardenedKey,
    /// A secp256k1 error occurred
    Secp256k1(secp256k1::Error),
    /// A child number was provided that was out of range
    InvalidChildNumber(u32),
    /// Invalid childnumber format.
    InvalidChildNumberFormat,
    /// Invalid derivation path format.
    InvalidDerivationPathFormat,
    /// Unknown version magic bytes
    UnknownVersion([u8; 4]),
    /// Encoded extended key data has wrong length
    WrongExtendedKeyLength(usize),
    /// Base58 encoding error
    Base58(base58::Error),
    /// Hexadecimal decoding error
    Hex(hex::Error),
    /// `PublicKey` hex should be 66 or 130 digits long.
    InvalidPublicKeyHexLength(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::CannotDeriveFromHardenedKey =>
                f.write_str("cannot derive hardened key from public key"),
            Error::Secp256k1(ref e) => write_err!(f, "secp256k1 error"; e),
            Error::InvalidChildNumber(ref n) =>
                write!(f, "child number {} is invalid (not within [0, 2^31 - 1])", n),
            Error::InvalidChildNumberFormat => f.write_str("invalid child number format"),
            Error::InvalidDerivationPathFormat => f.write_str("invalid derivation path format"),
            Error::UnknownVersion(ref bytes) =>
                write!(f, "unknown version magic bytes: {:?}", bytes),
            Error::WrongExtendedKeyLength(ref len) =>
                write!(f, "encoded extended key data has wrong length {}", len),
            Error::Base58(ref e) => write_err!(f, "base58 encoding error"; e),
            Error::Hex(ref e) => write_err!(f, "Hexadecimal decoding error"; e),
            Error::InvalidPublicKeyHexLength(got) =>
                write!(f, "PublicKey hex should be 66 or 130 digits long, got: {}", got),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            Secp256k1(e) => Some(e),
            Base58(e) => Some(e),
            Hex(e) => Some(e),
            CannotDeriveFromHardenedKey
            | InvalidChildNumber(_)
            | InvalidChildNumberFormat
            | InvalidDerivationPathFormat
            | UnknownVersion(_)
            | WrongExtendedKeyLength(_)
            | InvalidPublicKeyHexLength(_) => None,
        }
    }
}

impl From<key::Error> for Error {
    fn from(err: key::Error) -> Self {
        match err {
            key::Error::Base58(e) => Error::Base58(e),
            key::Error::Secp256k1(e) => Error::Secp256k1(e),
            key::Error::InvalidKeyPrefix(_) => Error::Secp256k1(secp256k1::Error::InvalidPublicKey),
            key::Error::Hex(e) => Error::Hex(e),
            key::Error::InvalidHexLength(got) => Error::InvalidPublicKeyHexLength(got),
        }
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error { Error::Secp256k1(e) }
}

impl From<base58::Error> for Error {
    fn from(err: base58::Error) -> Self { Error::Base58(err) }
}

impl ExtendedPrivKey {
    /// Construct a new master key from a seed value
    pub fn new_master(network: Network, seed: &[u8]) -> Result<ExtendedPrivKey, Error> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(b"Bitcoin seed");
        hmac_engine.input(seed);
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        Ok(ExtendedPrivKey {
            network,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from_normal_idx(0)?,
            private_key: secp256k1::SecretKey::from_slice(&hmac_result[..32])?,
            chain_code: ChainCode::from_hmac(hmac_result),
        })
    }

    /// Constructs ECDSA compressed private key matching internal secret key representation.
    pub fn to_priv(self) -> PrivateKey {
        PrivateKey { compressed: true, network: self.network, inner: self.private_key }
    }

    /// Constructs BIP340 keypair for Schnorr signatures and Taproot use matching the internal
    /// secret key representation.
    pub fn to_keypair<C: secp256k1::Signing>(self, secp: &Secp256k1<C>) -> KeyPair {
        KeyPair::from_seckey_slice(secp, &self.private_key[..])
            .expect("BIP32 internal private key representation is broken")
    }

    /// Attempts to derive an extended private key from a path.
    ///
    /// The `path` argument can be both of type `DerivationPath` or `Vec<ChildNumber>`.
    pub fn derive_priv<C: secp256k1::Signing, P: AsRef<[ChildNumber]>>(
        &self,
        secp: &Secp256k1<C>,
        path: &P,
    ) -> Result<ExtendedPrivKey, Error> {
        let mut sk: ExtendedPrivKey = *self;
        for cnum in path.as_ref() {
            sk = sk.ckd_priv(secp, *cnum)?;
        }
        Ok(sk)
    }

    /// Private->Private child key derivation
    pub fn ckd_priv<C: secp256k1::Signing>(
        &self,
        secp: &Secp256k1<C>,
        i: ChildNumber,
    ) -> Result<ExtendedPrivKey, Error> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);
        match i {
            ChildNumber::Normal { .. } => {
                // Non-hardened key: compute public data and use that
                hmac_engine.input(
                    &secp256k1::PublicKey::from_secret_key(secp, &self.private_key).serialize()[..],
                );
            }
            ChildNumber::Hardened { .. } => {
                // Hardened key: use only secret data to prevent public derivation
                hmac_engine.input(&[0u8]);
                hmac_engine.input(&self.private_key[..]);
            }
        }

        hmac_engine.input(&u32::from(i).to_be_bytes());
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
        let sk = secp256k1::SecretKey::from_slice(&hmac_result[..32])
            .expect("statistically impossible to hit");
        let tweaked =
            sk.add_tweak(&self.private_key.into()).expect("statistically impossible to hit");

        Ok(ExtendedPrivKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(secp),
            child_number: i,
            private_key: tweaked,
            chain_code: ChainCode::from_hmac(hmac_result),
        })
    }

    /// Decoding extended private key from binary data according to BIP 32
    pub fn decode(data: &[u8]) -> Result<ExtendedPrivKey, Error> {
        if data.len() != 78 {
            return Err(Error::WrongExtendedKeyLength(data.len()));
        }

        let network = if data[0..4] == [0x04u8, 0x88, 0xAD, 0xE4] {
            Network::Bitcoin
        } else if data[0..4] == [0x04u8, 0x35, 0x83, 0x94] {
            Network::Testnet
        } else {
            let mut ver = [0u8; 4];
            ver.copy_from_slice(&data[0..4]);
            return Err(Error::UnknownVersion(ver));
        };

        Ok(ExtendedPrivKey {
            network,
            depth: data[4],
            parent_fingerprint: data[5..9]
                .try_into()
                .expect("9 - 5 == 4, which is the Fingerprint length"),
            child_number: u32::from_be_bytes(data[9..13].try_into().expect("4 byte slice")).into(),
            chain_code: data[13..45]
                .try_into()
                .expect("45 - 13 == 32, which is the ChainCode length"),
            private_key: secp256k1::SecretKey::from_slice(&data[46..78])?,
        })
    }

    /// Extended private key binary encoding according to BIP 32
    pub fn encode(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(
            &match self.network {
                Network::Bitcoin => [0x04, 0x88, 0xAD, 0xE4],
                Network::Testnet | Network::Signet | Network::Regtest => [0x04, 0x35, 0x83, 0x94],
            }[..],
        );
        ret[4] = self.depth;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&u32::from(self.child_number).to_be_bytes());
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45] = 0;
        ret[46..78].copy_from_slice(&self.private_key[..]);
        ret
    }

    /// Returns the HASH160 of the public key belonging to the xpriv
    pub fn identifier<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> XpubIdentifier {
        ExtendedPubKey::from_priv(secp, self).identifier()
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> Fingerprint {
        self.identifier(secp)[0..4].try_into().expect("4 is the fingerprint length")
    }
}

impl ExtendedPubKey {
    /// Derives a public key from a private key
    pub fn from_priv<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        sk: &ExtendedPrivKey,
    ) -> ExtendedPubKey {
        ExtendedPubKey {
            network: sk.network,
            depth: sk.depth,
            parent_fingerprint: sk.parent_fingerprint,
            child_number: sk.child_number,
            public_key: secp256k1::PublicKey::from_secret_key(secp, &sk.private_key),
            chain_code: sk.chain_code,
        }
    }

    /// Constructs ECDSA compressed public key matching internal public key representation.
    pub fn to_pub(self) -> PublicKey { PublicKey { compressed: true, inner: self.public_key } }

    /// Constructs BIP340 x-only public key for BIP-340 signatures and Taproot use matching
    /// the internal public key representation.
    pub fn to_x_only_pub(self) -> XOnlyPublicKey { XOnlyPublicKey::from(self.public_key) }

    /// Attempts to derive an extended public key from a path.
    ///
    /// The `path` argument can be any type implementing `AsRef<ChildNumber>`, such as `DerivationPath`, for instance.
    pub fn derive_pub<C: secp256k1::Verification, P: AsRef<[ChildNumber]>>(
        &self,
        secp: &Secp256k1<C>,
        path: &P,
    ) -> Result<ExtendedPubKey, Error> {
        let mut pk: ExtendedPubKey = *self;
        for cnum in path.as_ref() {
            pk = pk.ckd_pub(secp, *cnum)?
        }
        Ok(pk)
    }

    /// Compute the scalar tweak added to this key to get a child key
    pub fn ckd_pub_tweak(
        &self,
        i: ChildNumber,
    ) -> Result<(secp256k1::SecretKey, ChainCode), Error> {
        match i {
            ChildNumber::Hardened { .. } => Err(Error::CannotDeriveFromHardenedKey),
            ChildNumber::Normal { index: n } => {
                let mut hmac_engine: HmacEngine<sha512::Hash> =
                    HmacEngine::new(&self.chain_code[..]);
                hmac_engine.input(&self.public_key.serialize()[..]);
                hmac_engine.input(&n.to_be_bytes());

                let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

                let private_key = secp256k1::SecretKey::from_slice(&hmac_result[..32])?;
                let chain_code = ChainCode::from_hmac(hmac_result);
                Ok((private_key, chain_code))
            }
        }
    }

    /// Public->Public child key derivation
    pub fn ckd_pub<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        i: ChildNumber,
    ) -> Result<ExtendedPubKey, Error> {
        let (sk, chain_code) = self.ckd_pub_tweak(i)?;
        let tweaked = self.public_key.add_exp_tweak(secp, &sk.into())?;

        Ok(ExtendedPubKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: i,
            public_key: tweaked,
            chain_code,
        })
    }

    /// Decoding extended public key from binary data according to BIP 32
    pub fn decode(data: &[u8]) -> Result<ExtendedPubKey, Error> {
        if data.len() != 78 {
            return Err(Error::WrongExtendedKeyLength(data.len()));
        }

        Ok(ExtendedPubKey {
            network: if data[0..4] == [0x04u8, 0x88, 0xB2, 0x1E] {
                Network::Bitcoin
            } else if data[0..4] == [0x04u8, 0x35, 0x87, 0xCF] {
                Network::Testnet
            } else {
                let mut ver = [0u8; 4];
                ver.copy_from_slice(&data[0..4]);
                return Err(Error::UnknownVersion(ver));
            },
            depth: data[4],
            parent_fingerprint: data[5..9]
                .try_into()
                .expect("9 - 5 == 4, which is the Fingerprint length"),
            child_number: u32::from_be_bytes(data[9..13].try_into().expect("4 byte slice")).into(),
            chain_code: data[13..45]
                .try_into()
                .expect("45 - 13 == 32, which is the ChainCode length"),
            public_key: secp256k1::PublicKey::from_slice(&data[45..78])?,
        })
    }

    /// Extended public key binary encoding according to BIP 32
    pub fn encode(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(
            &match self.network {
                Network::Bitcoin => [0x04u8, 0x88, 0xB2, 0x1E],
                Network::Testnet | Network::Signet | Network::Regtest => [0x04u8, 0x35, 0x87, 0xCF],
            }[..],
        );
        ret[4] = self.depth;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&u32::from(self.child_number).to_be_bytes());
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45..78].copy_from_slice(&self.public_key.serialize()[..]);
        ret
    }

    /// Returns the HASH160 of the chaincode
    pub fn identifier(&self) -> XpubIdentifier {
        let mut engine = XpubIdentifier::engine();
        engine.write_all(&self.public_key.serialize()).expect("engines don't error");
        XpubIdentifier::from_engine(engine)
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint(&self) -> Fingerprint {
        self.identifier()[0..4].try_into().expect("4 is the fingerprint length")
    }
}

impl fmt::Display for ExtendedPrivKey {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        base58::encode_check_to_fmt(fmt, &self.encode()[..])
    }
}

impl FromStr for ExtendedPrivKey {
    type Err = Error;

    fn from_str(inp: &str) -> Result<ExtendedPrivKey, Error> {
        let data = base58::decode_check(inp)?;

        if data.len() != 78 {
            return Err(base58::Error::InvalidLength(data.len()).into());
        }

        ExtendedPrivKey::decode(&data)
    }
}

impl fmt::Display for ExtendedPubKey {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        base58::encode_check_to_fmt(fmt, &self.encode()[..])
    }
}

impl FromStr for ExtendedPubKey {
    type Err = Error;

    fn from_str(inp: &str) -> Result<ExtendedPubKey, Error> {
        let data = base58::decode_check(inp)?;

        if data.len() != 78 {
            return Err(base58::Error::InvalidLength(data.len()).into());
        }

        ExtendedPubKey::decode(&data)
    }
}

impl From<ExtendedPubKey> for XpubIdentifier {
    fn from(key: ExtendedPubKey) -> XpubIdentifier { key.identifier() }
}

impl From<&ExtendedPubKey> for XpubIdentifier {
    fn from(key: &ExtendedPubKey) -> XpubIdentifier { key.identifier() }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use secp256k1::{self, Secp256k1};

    use super::ChildNumber::{Hardened, Normal};
    use super::*;
    use crate::internal_macros::hex;
    use crate::network::constants::Network::{self, Bitcoin};

    #[test]
    fn test_parse_derivation_path() {
        assert_eq!(DerivationPath::from_str("42"), Err(Error::InvalidDerivationPathFormat));
        assert_eq!(DerivationPath::from_str("n/0'/0"), Err(Error::InvalidDerivationPathFormat));
        assert_eq!(DerivationPath::from_str("4/m/5"), Err(Error::InvalidDerivationPathFormat));
        assert_eq!(DerivationPath::from_str("m//3/0'"), Err(Error::InvalidChildNumberFormat));
        assert_eq!(DerivationPath::from_str("m/0h/0x"), Err(Error::InvalidChildNumberFormat));
        assert_eq!(
            DerivationPath::from_str("m/2147483648"),
            Err(Error::InvalidChildNumber(2147483648))
        );

        assert_eq!(DerivationPath::master(), DerivationPath::from_str("m").unwrap());
        assert_eq!(DerivationPath::master(), DerivationPath::default());
        assert_eq!(DerivationPath::from_str("m"), Ok(vec![].into()));
        assert_eq!(
            DerivationPath::from_str("m/0'"),
            Ok(vec![ChildNumber::from_hardened_idx(0).unwrap()].into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0'/1"),
            Ok(vec![
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(1).unwrap()
            ]
            .into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0h/1/2'"),
            Ok(vec![
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(2).unwrap(),
            ]
            .into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0'/1/2h/2"),
            Ok(vec![
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(2).unwrap(),
                ChildNumber::from_normal_idx(2).unwrap(),
            ]
            .into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0'/1/2'/2/1000000000"),
            Ok(vec![
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(2).unwrap(),
                ChildNumber::from_normal_idx(2).unwrap(),
                ChildNumber::from_normal_idx(1000000000).unwrap(),
            ]
            .into())
        );
        let s = "m/0'/50/3'/5/545456";
        assert_eq!(DerivationPath::from_str(s), s.into_derivation_path());
        assert_eq!(DerivationPath::from_str(s), s.to_string().into_derivation_path());
    }

    #[test]
    fn test_derivation_path_conversion_index() {
        let path = DerivationPath::from_str("m/0h/1/2'").unwrap();
        let numbers: Vec<ChildNumber> = path.clone().into();
        let path2: DerivationPath = numbers.into();
        assert_eq!(path, path2);
        assert_eq!(
            &path[..2],
            &[ChildNumber::from_hardened_idx(0).unwrap(), ChildNumber::from_normal_idx(1).unwrap()]
        );
        let indexed: DerivationPath = path[..2].into();
        assert_eq!(indexed, DerivationPath::from_str("m/0h/1").unwrap());
        assert_eq!(indexed.child(ChildNumber::from_hardened_idx(2).unwrap()), path);
    }

    fn test_path<C: secp256k1::Signing + secp256k1::Verification>(
        secp: &Secp256k1<C>,
        network: Network,
        seed: &[u8],
        path: DerivationPath,
        expected_sk: &str,
        expected_pk: &str,
    ) {
        let mut sk = ExtendedPrivKey::new_master(network, seed).unwrap();
        let mut pk = ExtendedPubKey::from_priv(secp, &sk);

        // Check derivation convenience method for ExtendedPrivKey
        assert_eq!(&sk.derive_priv(secp, &path).unwrap().to_string()[..], expected_sk);

        // Check derivation convenience method for ExtendedPubKey, should error
        // appropriately if any ChildNumber is hardened
        if path.0.iter().any(|cnum| cnum.is_hardened()) {
            assert_eq!(pk.derive_pub(secp, &path), Err(Error::CannotDeriveFromHardenedKey));
        } else {
            assert_eq!(&pk.derive_pub(secp, &path).unwrap().to_string()[..], expected_pk);
        }

        // Derive keys, checking hardened and non-hardened derivation one-by-one
        for &num in path.0.iter() {
            sk = sk.ckd_priv(secp, num).unwrap();
            match num {
                Normal { .. } => {
                    let pk2 = pk.ckd_pub(secp, num).unwrap();
                    pk = ExtendedPubKey::from_priv(secp, &sk);
                    assert_eq!(pk, pk2);
                }
                Hardened { .. } => {
                    assert_eq!(pk.ckd_pub(secp, num), Err(Error::CannotDeriveFromHardenedKey));
                    pk = ExtendedPubKey::from_priv(secp, &sk);
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
        assert_eq!(cn.increment().ok(), Some(ChildNumber::from_normal_idx(idx + 1).unwrap()));
        let cn = ChildNumber::from_hardened_idx(idx).unwrap();
        assert_eq!(cn.increment().ok(), Some(ChildNumber::from_hardened_idx(idx + 1).unwrap()));

        let max = (1 << 31) - 1;
        let cn = ChildNumber::from_normal_idx(max).unwrap();
        assert_eq!(cn.increment().err(), Some(Error::InvalidChildNumber(1 << 31)));
        let cn = ChildNumber::from_hardened_idx(max).unwrap();
        assert_eq!(cn.increment().err(), Some(Error::InvalidChildNumber(1 << 31)));

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
        let seed = hex!("000102030405060708090a0b0c0d0e0f");

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
        let seed = hex!("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");

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
        let seed = hex!("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be");

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

        let xpriv = ExtendedPrivKey {
            network: Network::Bitcoin,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::Normal { index: 0 },
            private_key: sk,
            chain_code: ChainCode::from([0u8; 32])
        };

        println!("{}", xpriv);
         */

        // Xpriv having secret key set to all zeros
        let xpriv_str = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx";
        ExtendedPrivKey::from_str(xpriv_str).unwrap();
    }

    #[test]
    #[should_panic(expected = "Secp256k1(InvalidSecretKey)")]
    fn schnorr_broken_privkey_ffs() {
        // Xpriv having secret key set to all 0xFF's
        let xpriv_str = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fENZ3QzxW";
        ExtendedPrivKey::from_str(xpriv_str).unwrap();
    }
}
