// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! ECDSA Bitcoin signatures.
//!
//! This module provides ECDSA signatures used Bitcoin that can be roundtrip (de)serialized.

use core::str::FromStr;
use core::{fmt, iter};

use bitcoin_internals::write_err;
use bitcoin_internals::hex::display::DisplayHex;
use secp256k1;

use crate::prelude::*;
use crate::hashes::hex::{self, FromHex};
use crate::sighash::{EcdsaSighashType, NonStandardSighashType};
use crate::script::PushBytes;

const MAX_SIG_LEN: usize = 73;

/// An ECDSA signature with the corresponding hash type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Signature {
    /// The underlying ECDSA Signature
    pub sig: secp256k1::ecdsa::Signature,
    /// The corresponding hash type
    pub hash_ty: EcdsaSighashType,
}

impl Signature {
    /// Constructs an ECDSA bitcoin signature for [`EcdsaSighashType::All`].
    pub fn sighash_all(sig: secp256k1::ecdsa::Signature) -> Signature {
        Signature {
            sig,
            hash_ty: EcdsaSighashType::All
        }
    }

    /// Deserializes from slice following the standardness rules for [`EcdsaSighashType`].
    pub fn from_slice(sl: &[u8]) -> Result<Self, Error> {
        let (hash_ty, sig) = sl.split_last()
            .ok_or(Error::EmptySignature)?;
        let hash_ty = EcdsaSighashType::from_standard(*hash_ty as u32)
            .map_err(|_| Error::NonStandardSighashType(*hash_ty as u32))?;
        let sig = secp256k1::ecdsa::Signature::from_der(sig)
            .map_err(Error::Secp256k1)?;
        Ok(Signature { sig, hash_ty })
    }

    /// Serializes an ECDSA signature (inner secp256k1 signature in DER format).
    ///
    /// This does **not** perform extra heap allocation.
    pub fn serialize(&self) -> SerializedSignature {
        let mut buf = [0u8; MAX_SIG_LEN];
        let signature = self.sig.serialize_der();
        buf[..signature.len()].copy_from_slice(&signature);
        buf[signature.len()] = self.hash_ty as u8;
        SerializedSignature {
            data: buf,
            len: signature.len() + 1,
        }
    }

    /// Serializes an ECDSA signature (inner secp256k1 signature in DER format) into `Vec`.
    ///
    /// Note: this performs an extra heap allocation, you might prefer the
    /// [`serialize`](Self::serialize) method instead.
    pub fn to_vec(self) -> Vec<u8> {
        // TODO: add support to serialize to a writer to SerializedSig
        self.sig.serialize_der()
            .iter().copied()
            .chain(iter::once(self.hash_ty as u8))
            .collect()
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.sig.serialize_der().as_hex(), f)?;
        fmt::LowerHex::fmt(&[self.hash_ty as u8].as_hex(), f)
    }
}

impl FromStr for Signature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = Vec::from_hex(s)?;
        let (sighash_byte, signature) = bytes.split_last()
            .ok_or(Error::EmptySignature)?;
        Ok(Signature {
            sig: secp256k1::ecdsa::Signature::from_der(signature)?,
            hash_ty: EcdsaSighashType::from_standard(*sighash_byte as u32)?
        })
    }
}

/// Holds signature serialized in-line (not in `Vec`).
///
/// This avoids allocation and allows proving maximum size of the signature (73 bytes).
/// The type can be used largely as a byte slice. It implements all standard traits one would
/// expect and has familiar methods.
/// However, the usual use case is to push it into a script. This can be done directly passing it
/// into [`push_slice`](crate::script::ScriptBuf::push_slice).
#[derive(Copy, Clone)]
pub struct SerializedSignature {
    data: [u8; MAX_SIG_LEN],
    len: usize,
}

impl SerializedSignature {
    /// Returns an iterator over bytes of the signature.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, u8> {
        self.into_iter()
    }
}

impl core::ops::Deref for SerializedSignature {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.data[..self.len]
    }
}

impl core::ops::DerefMut for SerializedSignature {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data[..self.len]
    }
}

impl AsRef<[u8]> for SerializedSignature {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl AsMut<[u8]> for SerializedSignature {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self
    }
}

impl AsRef<PushBytes> for SerializedSignature {
    #[inline]
    fn as_ref(&self) -> &PushBytes {
        &<&PushBytes>::from(&self.data)[..self.len()]
    }
}

impl core::borrow::Borrow<[u8]> for SerializedSignature {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self
    }
}

impl core::borrow::BorrowMut<[u8]> for SerializedSignature {
    #[inline]
    fn borrow_mut(&mut self) -> &mut [u8] {
        self
    }
}

impl fmt::Debug for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(self, f) }
}

impl fmt::Display for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl fmt::LowerHex for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&(**self).as_hex(), f)
    }
}

impl fmt::UpperHex for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&(**self).as_hex(), f)
    }
}

impl PartialEq for SerializedSignature {
    #[inline]
    fn eq(&self, other: &SerializedSignature) -> bool { **self == **other }
}

impl Eq for SerializedSignature {}

impl core::hash::Hash for SerializedSignature {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::hash::Hash::hash(&**self, state)
    }
}

impl<'a> IntoIterator for &'a SerializedSignature {
    type IntoIter = core::slice::Iter<'a, u8>;
    type Item = &'a u8;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        (*self).iter()
    }
}

/// A key-related error.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Hex encoding error
    HexEncoding(hex::Error),
    /// Base58 encoding error
    NonStandardSighashType(u32),
    /// Empty Signature
    EmptySignature,
    /// secp256k1-related error
    Secp256k1(secp256k1::Error),
}


impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::HexEncoding(ref e) =>
                write_err!(f, "Signature hex encoding error"; e),
            Error::NonStandardSighashType(hash_ty) =>
                write!(f, "Non standard signature hash type {}", hash_ty),
            Error::EmptySignature =>
                write!(f, "Empty ECDSA signature"),
            Error::Secp256k1(ref e) =>
                write_err!(f, "invalid ECDSA signature"; e),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            HexEncoding(e) => Some(e),
            Secp256k1(e) => Some(e),
            NonStandardSighashType(_) | EmptySignature => None,
        }
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Secp256k1(e)
    }
}

impl From<NonStandardSighashType> for Error {
    fn from(err: NonStandardSighashType) -> Self {
        Error::NonStandardSighashType(err.0)
    }
}

impl From<hex::Error> for Error {
    fn from(err: hex::Error) -> Self {
        Error::HexEncoding(err)
    }
}
