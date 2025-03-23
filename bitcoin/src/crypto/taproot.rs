// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Taproot keys.
//!
//! This module provides Taproot keys used in Bitcoin (including reexporting secp256k1 keys).

use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use internals::array::ArrayExt;
use internals::write_err;
use io::Write;

use crate::prelude::Vec;
use crate::sighash::{InvalidSighashTypeError, TapSighashType};
use crate::taproot::serialized_signature::{self, SerializedSignature};

/// A BIP340-341 serialized Taproot signature with the corresponding hash type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signature {
    /// The underlying schnorr signature.
    pub signature: secp256k1::schnorr::Signature,
    /// The corresponding hash type.
    pub sighash_type: TapSighashType,
}

impl Signature {
    /// Deserializes the signature from a slice.
    pub fn from_slice(sl: &[u8]) -> Result<Self, SigFromSliceError> {
        if let Ok(signature) = <[u8; 64]>::try_from(sl) {
            // default type
            let signature = secp256k1::schnorr::Signature::from_byte_array(signature);
            Ok(Signature { signature, sighash_type: TapSighashType::Default })
        } else if let Ok(signature) = <[u8; 65]>::try_from(sl) {
            let (sighash_type, signature) = signature.split_last();
            let sighash_type = TapSighashType::from_consensus_u8(*sighash_type)?;
            let signature = secp256k1::schnorr::Signature::from_byte_array(*signature);
            Ok(Signature { signature, sighash_type })
        } else {
            Err(SigFromSliceError::InvalidSignatureSize(sl.len()))
        }
    }

    /// Serializes the signature.
    ///
    /// Note: this allocates on the heap, prefer [`serialize`](Self::serialize) if vec is not needed.
    pub fn to_vec(self) -> Vec<u8> {
        let mut ser_sig = self.signature.as_ref().to_vec();
        // If default sighash type, don't add extra sighash byte
        if self.sighash_type != TapSighashType::Default {
            ser_sig.push(self.sighash_type as u8);
        }
        ser_sig
    }

    /// Serializes the signature to `writer`.
    #[inline]
    pub fn serialize_to_writer<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
        let sig = self.serialize();
        sig.write_to(writer)
    }

    /// Serializes the signature (without heap allocation).
    ///
    /// This returns a type with an API very similar to that of `Box<[u8]>`.
    /// You can get a slice from it using deref coercions or turn it into an iterator.
    pub fn serialize(self) -> SerializedSignature {
        let mut buf = [0; serialized_signature::MAX_LEN];
        let ser_sig = self.signature.to_byte_array();
        buf[..64].copy_from_slice(&ser_sig);
        let len = if self.sighash_type == TapSighashType::Default {
            // default sighash type, don't add extra sighash byte
            64
        } else {
            buf[64] = self.sighash_type as u8;
            65
        };
        SerializedSignature::from_raw_parts(buf, len)
    }
}

/// An error constructing a [`taproot::Signature`] from a byte slice.
///
/// [`taproot::Signature`]: crate::crypto::taproot::Signature
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigFromSliceError {
    /// Invalid signature hash type.
    SighashType(InvalidSighashTypeError),
    /// A secp256k1 error.
    Secp256k1(secp256k1::Error),
    /// Invalid Taproot signature size
    InvalidSignatureSize(usize),
}

impl From<Infallible> for SigFromSliceError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for SigFromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use SigFromSliceError::*;

        match *self {
            SighashType(ref e) => write_err!(f, "sighash"; e),
            Secp256k1(ref e) => write_err!(f, "secp256k1"; e),
            InvalidSignatureSize(sz) => write!(f, "invalid Taproot signature size: {}", sz),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SigFromSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use SigFromSliceError::*;

        match *self {
            Secp256k1(ref e) => Some(e),
            SighashType(ref e) => Some(e),
            InvalidSignatureSize(_) => None,
        }
    }
}

impl From<secp256k1::Error> for SigFromSliceError {
    fn from(e: secp256k1::Error) -> Self { Self::Secp256k1(e) }
}

impl From<InvalidSighashTypeError> for SigFromSliceError {
    fn from(err: InvalidSighashTypeError) -> Self { Self::SighashType(err) }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Signature {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let arbitrary_bytes: [u8; secp256k1::constants::SCHNORR_SIGNATURE_SIZE] = u.arbitrary()?;

        Ok(Signature {
            signature: secp256k1::schnorr::Signature::from_byte_array(arbitrary_bytes),
            sighash_type: TapSighashType::arbitrary(u)?,
        })
    }
}
