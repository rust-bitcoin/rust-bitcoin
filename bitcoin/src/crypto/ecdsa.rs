// SPDX-License-Identifier: CC0-1.0

//! ECDSA Bitcoin signatures.
//!
//! This module provides ECDSA signatures used by Bitcoin that can be roundtrip (de)serialized.

use core::convert::Infallible;
use core::str::FromStr;
use core::{fmt, iter};
use core::convert::TryFrom;
use alloc::boxed::Box;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hex::FromHex;
use internals::{impl_to_hex_from_lower_hex, write_err};
use io::Write;
use alloc::rc::Rc;
use alloc::sync::Arc;
use alloc::string::String;

use crate::prelude::{DisplayHex, Vec};
use crate::script::PushBytes;
#[cfg(doc)]
use crate::script::ScriptPubKeyBufExt as _;
use crate::sighash::{EcdsaSighashType, NonStandardSighashTypeError};

const MAX_SIG_LEN: usize = 73;

/// An ECDSA signature with the corresponding hash type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signature {
    /// The underlying ECDSA Signature.
    pub signature: secp256k1::ecdsa::Signature,
    /// The corresponding hash type.
    pub sighash_type: EcdsaSighashType,
}

impl Signature {
    /// Constructs a new ECDSA Bitcoin signature for [`EcdsaSighashType::All`].
    pub fn sighash_all(signature: secp256k1::ecdsa::Signature) -> Signature {
        Signature { signature, sighash_type: EcdsaSighashType::All }
    }

    /// Deserializes from slice following the standardness rules for [`EcdsaSighashType`].
    pub fn from_slice(sl: &[u8]) -> Result<Self, DecodeError> {
        let (sighash_type, sig) = sl.split_last().ok_or(DecodeError::EmptySignature)?;
        let sighash_type = EcdsaSighashType::from_standard(*sighash_type as u32)?;
        let signature =
            secp256k1::ecdsa::Signature::from_der(sig).map_err(DecodeError::Secp256k1)?;
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
    pub fn to_vec(self) -> Vec<u8> {
        self.signature
            .serialize_der()
            .iter()
            .copied()
            .chain(iter::once(self.sighash_type as u8))
            .collect()
    }

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
    type Err = ParseSignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = Vec::from_hex(s)?;
        Ok(Self::from_slice(&bytes)?)
    }
}

impl TryFrom<&str> for Signature {
    type Error = ParseSignatureError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_str(s)
    }
}

impl TryFrom<String> for Signature {
    type Error = ParseSignatureError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_str(&s)
    }
}

impl TryFrom<Box<str>> for Signature {
    type Error = ParseSignatureError;

    fn try_from(s: Box<str>) -> Result<Self, Self::Error> {
        Self::from_str(&s)
    }
}

impl TryFrom<Arc<str>> for Signature {
    type Error = ParseSignatureError;

    fn try_from(s: Arc<str>) -> Result<Self, Self::Error> {
        Self::from_str(&s)
    }
}

impl TryFrom<Rc<str>> for Signature {
    type Error = ParseSignatureError;

    fn try_from(s: Rc<str>) -> Result<Self, Self::Error> {
        Self::from_str(&s)
    }
}

/// Holds signature serialized in-line (not in `Vec`).
///
/// This avoids allocation and allows proving maximum size of the signature (73 bytes).
/// The type can be used largely as a byte slice. It implements all standard traits one would
/// expect and has familiar methods.
///
/// However, the usual use case is to push it into a script. This can be done directly passing it
/// into [`push_slice`](crate::script::ScriptBufExt::push_slice).
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
impl_to_hex_from_lower_hex!(SerializedSignature, |signature: &SerializedSignature| signature.len
    * 2);

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
    fn into_iter(self) -> Self::IntoIter { (**self).iter() }
}

/// Error encountered while parsing an ECDSA signature from a byte slice.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// Non-standard sighash type.
    SighashType(NonStandardSighashTypeError),
    /// Signature was empty.
    EmptySignature,
    /// A secp256k1 error.
    Secp256k1(secp256k1::Error),
}

impl From<Infallible> for DecodeError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DecodeError::*;

        match *self {
            SighashType(ref e) => write_err!(f, "non-standard signature hash type"; e),
            EmptySignature => write!(f, "empty ECDSA signature"),
            Secp256k1(ref e) => write_err!(f, "secp256k1"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DecodeError::*;

        match *self {
            Secp256k1(ref e) => Some(e),
            SighashType(ref e) => Some(e),
            EmptySignature => None,
        }
    }
}

impl From<secp256k1::Error> for DecodeError {
    fn from(e: secp256k1::Error) -> Self { Self::Secp256k1(e) }
}

impl From<NonStandardSighashTypeError> for DecodeError {
    fn from(e: NonStandardSighashTypeError) -> Self { Self::SighashType(e) }
}

/// Error encountered while parsing an ECDSA signature from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseSignatureError {
    /// Hex string decoding error.
    Hex(hex::HexToBytesError),
    /// Signature byte slice decoding error.
    Decode(DecodeError),
}

impl From<Infallible> for ParseSignatureError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for ParseSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseSignatureError::*;

        match *self {
            Hex(ref e) => write_err!(f, "signature hex decoding error"; e),
            Decode(ref e) => write_err!(f, "signature byte slice decoding error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseSignatureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseSignatureError::*;

        match *self {
            Hex(ref e) => Some(e),
            Decode(ref e) => Some(e),
        }
    }
}

impl From<hex::HexToBytesError> for ParseSignatureError {
    fn from(e: hex::HexToBytesError) -> Self { Self::Hex(e) }
}

impl From<DecodeError> for ParseSignatureError {
    fn from(e: DecodeError) -> Self { Self::Decode(e) }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Signature {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // The valid range of r and s should be between 0 and n-1 where
        // n = 0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        let high_min = 0x0u128;
        let high_max = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEu128;
        let low_min = 0x0u128;
        let low_max = 0xBAAEDCE6AF48A03BBFD25E8CD0364140u128;

        // Equally weight the chances of getting a minimum value for a signature, maximum value for
        // a signature, and an arbitrary valid signature
        let choice = u.int_in_range(0..=2)?;
        let (high, low) = match choice {
            0 => (high_min, low_min),
            1 => (high_max, low_max),
            _ => (u.int_in_range(high_min..=high_max)?, u.int_in_range(low_min..=low_max)?),
        };

        // We can use the same bytes for r and s since they're just arbitrary values
        let mut bytes: [u8; 32] = [0; 32];
        bytes[..16].copy_from_slice(&high.to_be_bytes());
        bytes[16..].copy_from_slice(&low.to_be_bytes());

        let mut signature_bytes: [u8; 64] = [0; 64];
        signature_bytes[..32].copy_from_slice(&bytes);
        signature_bytes[32..].copy_from_slice(&bytes);

        Ok(Signature {
            signature: secp256k1::ecdsa::Signature::from_compact(&signature_bytes).unwrap(),
            sighash_type: EcdsaSighashType::arbitrary(u)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SIGNATURE_HEX: &str = "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45";

    #[test]
    fn write_serialized_signature() {
        let sig = Signature {
            signature: secp256k1::ecdsa::Signature::from_str(TEST_SIGNATURE_HEX).unwrap(),
            sighash_type: EcdsaSighashType::All,
        };

        let mut buf = vec![];
        sig.serialize_to_writer(&mut buf).expect("write failed");

        assert_eq!(sig.to_vec(), buf)
    }

    #[test]
    fn iterate_serialized_signature() {
        let sig = Signature {
            signature: secp256k1::ecdsa::Signature::from_str(TEST_SIGNATURE_HEX).unwrap(),
            sighash_type: EcdsaSighashType::All,
        };

        assert_eq!(sig.serialize().iter().copied().collect::<Vec<u8>>(), sig.to_vec());
    }
}
