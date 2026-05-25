// SPDX-License-Identifier: CC0-1.0

//! ECDSA Bitcoin signatures.
//!
//! This module provides ECDSA signatures used by Bitcoin that can be roundtrip (de)serialized.

#[cfg(feature = "hex")]
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::fmt;
#[cfg(feature = "alloc")]
use core::iter;
use core::ops::Deref;
#[cfg(feature = "hex")]
#[cfg(feature = "alloc")]
use core::str::FromStr;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(feature = "hex")]
use hex::DisplayHex;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "hex")]
#[cfg(feature = "alloc")]
use crate::hex;
use crate::sighash::EcdsaSighashType;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(no_inline)]
pub use self::error::{DecodeError, InvalidDerError};
#[cfg(feature = "hex")]
#[doc(no_inline)]
pub use self::error::ParseSignatureError;

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
    #[inline]
    pub fn sighash_all(signature: secp256k1::ecdsa::Signature) -> Self {
        Self { signature, sighash_type: EcdsaSighashType::All }
    }

    /// Deserializes from slice following the standardness rules for [`EcdsaSighashType`].
    ///
    /// # Errors
    ///
    /// * [`DecodeError::EmptySignature`] if the slice is empty.
    /// * [`DecodeError::InvalidDer`] if the slice is not a valid DER encoding for an ECDSA signature.
    pub fn from_slice(sl: &[u8]) -> Result<Self, DecodeError> {
        let (sighash_type, sig) = sl.split_last().ok_or(DecodeError::EmptySignature)?;
        let sighash_type = EcdsaSighashType::from_standard(u32::from(*sighash_type))
            .map_err(DecodeError::SighashType)?;
        let signature = secp256k1::ecdsa::Signature::from_der(sig)
            .map_err(|_| DecodeError::InvalidDer(InvalidDerError))?;
        Ok(Self { signature, sighash_type })
    }

    /// Serializes an ECDSA signature (inner secp256k1 signature in DER format).
    ///
    /// This does **not** perform extra heap allocation.
    #[inline]
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
    #[cfg(feature = "alloc")]
    pub fn to_vec(self) -> Vec<u8> {
        self.signature
            .serialize_der()
            .iter()
            .copied()
            .chain(iter::once(self.sighash_type as u8))
            .collect()
    }
}

#[cfg(feature = "hex")]
impl fmt::Display for Signature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.signature.serialize_der().as_hex(), f)?;
        fmt::LowerHex::fmt(&[self.sighash_type as u8].as_hex(), f)
    }
}

#[cfg(feature = "hex")]
#[cfg(feature = "alloc")]
impl FromStr for Signature {
    type Err = ParseSignatureError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode_to_vec(s).map_err(ParseSignatureError::Hex)?;
        Self::from_slice(&bytes).map_err(ParseSignatureError::Decode)
    }
}

/// Holds signature serialized in-line (not in `Vec`).
///
/// This avoids allocation and allows proving maximum size of the signature (73 bytes).
/// The type can be used largely as a byte slice. It implements all standard traits one would
/// expect and has familiar methods.
///
/// However, the usual use case is to push it into a script. This can be done directly passing it
/// into a `ScriptBuf` with `push_slice`.
#[derive(Copy, Clone)]
pub struct SerializedSignature {
    data: [u8; MAX_SIG_LEN],
    len: usize,
}

impl SerializedSignature {
    /// Constructs a new `SerializedSignature` from a Signature.
    ///
    /// In other words this serializes a `Signature` into a `SerializedSignature`.
    #[inline]
    pub fn from_signature(sig: Signature) -> Self { sig.serialize() }

    /// Converts the serialized signature into the [`Signature`] struct.
    ///
    /// In other words this deserializes the `SerializedSignature`.
    ///
    /// # Errors
    ///
    /// See [`from_slice`]
    ///
    /// [`from_slice`]: Signature::from_slice
    #[inline]
    pub fn to_signature(self) -> Result<Signature, DecodeError> { Signature::from_slice(&self) }

    /// Returns the length of the serialized signature data.
    #[inline]
    // `len` is never 0, so `is_empty` would always return `false`.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize { self.len }

    /// Returns an iterator over bytes of the signature.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, u8> { self.into_iter() }

    /// Gets the hex representation of this type.
    #[cfg(feature = "hex")]
    #[cfg(feature = "alloc")]
    #[deprecated(since = "TBD", note = "use `format!(\"{var:x}\")` instead")]
    pub fn to_hex(&self) -> String { alloc::format!("{:x}", self) }
}

impl fmt::Debug for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        #[cfg(feature = "hex")]
        {
            fmt::Display::fmt(self, f)
        }
        #[cfg(not(feature = "hex"))]
        {
            for b in self {
                write!(f, "{:02x}", b)?;
            }
            Ok(())
        }
    }
}

#[cfg(feature = "hex")]
impl fmt::Display for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

#[cfg(feature = "hex")]
impl fmt::LowerHex for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&(**self).as_hex(), f)
    }
}

#[cfg(feature = "hex")]
impl fmt::UpperHex for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&(**self).as_hex(), f)
    }
}

impl PartialEq for SerializedSignature {
    #[inline]
    fn eq(&self, other: &Self) -> bool { **self == **other }
}

impl PartialEq<[u8]> for SerializedSignature {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool { **self == *other }
}

impl PartialEq<SerializedSignature> for [u8] {
    #[inline]
    fn eq(&self, other: &SerializedSignature) -> bool { *self == **other }
}

impl PartialOrd for SerializedSignature {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> { Some(self.cmp(other)) }
}

impl Ord for SerializedSignature {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering { (**self).cmp(&**other) }
}

impl PartialOrd<[u8]> for SerializedSignature {
    #[inline]
    fn partial_cmp(&self, other: &[u8]) -> Option<core::cmp::Ordering> {
        (**self).partial_cmp(other)
    }
}

impl PartialOrd<SerializedSignature> for [u8] {
    #[inline]
    fn partial_cmp(&self, other: &SerializedSignature) -> Option<core::cmp::Ordering> {
        self.partial_cmp(&**other)
    }
}

impl Eq for SerializedSignature {}

impl core::hash::Hash for SerializedSignature {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) { core::hash::Hash::hash(&**self, state) }
}

impl AsRef<[u8]> for SerializedSignature {
    #[inline]
    fn as_ref(&self) -> &[u8] { &self.data[..self.len] }
}

impl Borrow<[u8]> for SerializedSignature {
    #[inline]
    fn borrow(&self) -> &[u8] { &self.data[..self.len] }
}

impl Deref for SerializedSignature {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target { &self.data[..self.len] }
}

impl<'a> IntoIterator for &'a SerializedSignature {
    type IntoIter = core::slice::Iter<'a, u8>;
    type Item = &'a u8;

    #[inline]
    fn into_iter(self) -> Self::IntoIter { (**self).iter() }
}

/// Error types for ECDSA
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    use internals::write_err;

    use crate::sighash::NonStandardSighashTypeError;

    /// Error encountered while parsing an ECDSA signature from a byte slice.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum DecodeError {
        /// Non-standard sighash type.
        SighashType(NonStandardSighashTypeError),
        /// Signature was empty.
        EmptySignature,
        /// Bad DER encoding for ECDSA signature.
        InvalidDer(InvalidDerError),
    }

    impl From<Infallible> for DecodeError {
        #[inline]
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for DecodeError {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::SighashType(ref e) => write_err!(f, "non-standard signature hash type"; e),
                Self::EmptySignature => write!(f, "empty ECDSA signature"),
                Self::InvalidDer(ref e) => write_err!(f, "bad DER encoding for ECDSA signature"; e),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for DecodeError {
        #[inline]
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::InvalidDer(ref e) => Some(e),
                Self::SighashType(ref e) => Some(e),
                Self::EmptySignature => None,
            }
        }
    }

    /// The DER encoding of an ECDSA signature is not valid.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct InvalidDerError;

    impl From<Infallible> for InvalidDerError {
        #[inline]
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for InvalidDerError {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "invalid DER encoding") }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for InvalidDerError {
        #[inline]
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            let Self {} = self;
            None
        }
    }

    /// Error encountered while parsing an ECDSA signature from a string.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    #[cfg(feature = "hex")]
    pub enum ParseSignatureError {
        /// Hex string decoding error.
        Hex(hex::DecodeVariableLengthBytesError),
        /// Signature byte slice decoding error.
        Decode(DecodeError),
    }

    #[cfg(feature = "hex")]
    impl From<Infallible> for ParseSignatureError {
        #[inline]
        fn from(never: Infallible) -> Self { match never {} }
    }

    #[cfg(feature = "hex")]
    impl fmt::Display for ParseSignatureError {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::Hex(ref e) => write_err!(f, "signature hex decoding error"; e),
                Self::Decode(ref e) => write_err!(f, "signature byte slice decoding error"; e),
            }
        }
    }

    #[cfg(feature = "hex")]
    #[cfg(feature = "std")]
    impl std::error::Error for ParseSignatureError {
        #[inline]
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Hex(ref e) => Some(e),
                Self::Decode(ref e) => Some(e),
            }
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Signature {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // The valid range of r and s should be between 0 and n-1 where
        // n = 0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        let high_min = 0x0u128;
        let high_max = 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFEu128;
        let low_min = 0x0u128;
        let low_max = 0xBAAE_DCE6_AF48_A03B_BFD2_5E8C_D036_4140u128;

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

        Ok(Self {
            signature: secp256k1::ecdsa::Signature::from_compact(&signature_bytes).unwrap(),
            sighash_type: EcdsaSighashType::arbitrary(u)?,
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "hex")]
    #[cfg(feature = "alloc")]
    use super::*;

    #[cfg(feature = "hex")]
    #[cfg(feature = "alloc")]
    const TEST_SIGNATURE_HEX: &str = "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45";

    #[test]
    #[cfg(feature = "hex")]
    #[cfg(feature = "alloc")]
    fn iterate_serialized_signature() {
        let sig = Signature {
            signature: secp256k1::ecdsa::Signature::from_str(TEST_SIGNATURE_HEX).unwrap(),
            sighash_type: EcdsaSighashType::All,
        };

        assert_eq!(sig.serialize().iter().copied().collect::<Vec<u8>>(), sig.to_vec());
    }
}
