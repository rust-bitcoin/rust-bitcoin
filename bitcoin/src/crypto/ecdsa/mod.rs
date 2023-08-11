// SPDX-License-Identifier: CC0-1.0

//! ECDSA Bitcoin signatures.
//!
//! This module provides ECDSA signatures used by Bitcoin that can be roundtrip (de)serialized.

mod error;
pub mod legacy;
pub mod segwit_v0;

use core::str::FromStr;
use core::{fmt, iter};

use hex::FromHex;
use io::Write;
use secp256k1;

use crate::prelude::*;
use crate::script::PushBytes;
use crate::sighash::EcdsaSighashType;

#[rustfmt::skip]
#[doc(inline)]
pub use self::error::Error;

const MAX_SIG_LEN: usize = 73;

/// An ECDSA signature with the corresponding hash type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Signature {
    /// The underlying ECDSA Signature.
    pub signature: secp256k1::ecdsa::Signature,
    /// The corresponding hash type.
    pub sighash_type: EcdsaSighashType,
}

impl Signature {
    /// Constructs an ECDSA Bitcoin signature for [`EcdsaSighashType::All`].
    pub fn sighash_all(signature: secp256k1::ecdsa::Signature) -> Signature {
        Signature { signature, sighash_type: EcdsaSighashType::All }
    }

    /// Deserializes from slice following the standardness rules for [`EcdsaSighashType`].
    pub fn from_slice(sl: &[u8]) -> Result<Self, Error> {
        let (sighash_type, sig) = sl.split_last().ok_or(Error::EmptySignature)?;
        let sighash_type = EcdsaSighashType::from_standard(*sighash_type as u32)?;
        let signature = secp256k1::ecdsa::Signature::from_der(sig).map_err(Error::Secp256k1)?;
        Ok(Signature { signature, sighash_type })
    }

    /// Serializes an ECDSA signature (inner secp256k1 signature in DER format).
    ///
    /// This does **not** perform extra heap allocation.
    pub fn serialize(&self) -> SerializedSignature {
        let mut buf = [0u8; MAX_SIG_LEN];
        let signature = self.signature.serialize_der();
        buf[..signature.len()].copy_from_slice(&signature);
        buf[signature.len()] = self.sighash_type as u8;
        SerializedSignature { data: buf, len: signature.len() + 1 }
    }

    /// Serializes an ECDSA signature (inner secp256k1 signature in DER format) into `Vec`.
    ///
    /// Note: this performs an extra heap allocation, you might prefer the
    /// [`serialize`](Self::serialize) method instead.
    pub fn to_bytes(self) -> Vec<u8> {
        self.signature
            .serialize_der()
            .iter()
            .copied()
            .chain(iter::once(self.sighash_type as u8))
            .collect()
    }

    /// Serializes an ECDSA signature (inner secp256k1 signature in DER format) into `Vec`.
    #[deprecated(since = "TBD", note = "Use to_bytes instead")]
    pub fn to_vec(self) -> Vec<u8> { self.to_bytes() }

    /// Serializes an ECDSA signature (inner secp256k1 signature in DER format) to a `writer`.
    #[inline]
    pub fn serialize_to_writer<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
        let sig = self.serialize();
        sig.write_to(writer)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.signature.serialize_der().as_hex(), f)?;
        fmt::LowerHex::fmt(&[self.sighash_type as u8].as_hex(), f)
    }
}

impl FromStr for Signature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = Vec::from_hex(s)?;
        let (sighash_byte, signature) = bytes.split_last().ok_or(Error::EmptySignature)?;
        Ok(Signature {
            signature: secp256k1::ecdsa::Signature::from_der(signature)?,
            sighash_type: EcdsaSighashType::from_standard(*sighash_byte as u32)?,
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
    pub fn iter(&self) -> core::slice::Iter<'_, u8> { self.into_iter() }

    /// Writes this serialized signature to a `writer`.
    #[inline]
    pub fn write_to<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
        writer.write_all(self)
    }
}

impl core::ops::Deref for SerializedSignature {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target { &self.data[..self.len] }
}

impl core::ops::DerefMut for SerializedSignature {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.data[..self.len] }
}

impl AsRef<[u8]> for SerializedSignature {
    #[inline]
    fn as_ref(&self) -> &[u8] { self }
}

impl AsMut<[u8]> for SerializedSignature {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] { self }
}

impl AsRef<PushBytes> for SerializedSignature {
    #[inline]
    fn as_ref(&self) -> &PushBytes { &<&PushBytes>::from(&self.data)[..self.len()] }
}

impl core::borrow::Borrow<[u8]> for SerializedSignature {
    #[inline]
    fn borrow(&self) -> &[u8] { self }
}

impl core::borrow::BorrowMut<[u8]> for SerializedSignature {
    #[inline]
    fn borrow_mut(&mut self) -> &mut [u8] { self }
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
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) { core::hash::Hash::hash(&**self, state) }
}

impl<'a> IntoIterator for &'a SerializedSignature {
    type IntoIter = core::slice::Iter<'a, u8>;
    type Item = &'a u8;

    #[inline]
    fn into_iter(self) -> Self::IntoIter { (*self).iter() }
}
