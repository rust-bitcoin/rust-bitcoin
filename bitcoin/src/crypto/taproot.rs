// SPDX-License-Identifier: CC0-1.0

//! Bitcoin taproot keys.
//!
//! This module provides taproot keys used in Bitcoin (including reexporting secp256k1 keys).
//!

use core::fmt;

use internals::write_err;
pub use secp256k1::{self, constants, KeyPair, Parity, Secp256k1, Verification, XOnlyPublicKey};

use crate::prelude::*;
use crate::sighash::TapSighashType;

/// A BIP340-341 serialized taproot signature with the corresponding hash type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Signature {
    /// The underlying schnorr signature
    pub sig: secp256k1::schnorr::Signature,
    /// The corresponding hash type
    pub hash_ty: TapSighashType,
}

impl Signature {
    /// Deserialize from slice
    pub fn from_slice(sl: &[u8]) -> Result<Self, SigFromSliceError> {
        match sl.len() {
            64 => {
                // default type
                let sig = secp256k1::schnorr::Signature::from_slice(sl)?;
                Ok(Signature { sig, hash_ty: TapSighashType::Default })
            }
            65 => {
                let (hash_ty, sig) = sl.split_last().expect("Slice len checked == 65");
                let hash_ty = TapSighashType::from_consensus_u8(*hash_ty)
                    .map_err(|_| SigFromSliceError::InvalidSighashType(*hash_ty))?;
                let sig = secp256k1::schnorr::Signature::from_slice(sig)?;
                Ok(Signature { sig, hash_ty })
            }
            len => Err(SigFromSliceError::InvalidSignatureSize(len)),
        }
    }

    /// Serialize Signature
    pub fn to_vec(self) -> Vec<u8> {
        // TODO: add support to serialize to a writer to SerializedSig
        let mut ser_sig = self.sig.as_ref().to_vec();
        if self.hash_ty == TapSighashType::Default {
            // default sighash type, don't add extra sighash byte
        } else {
            ser_sig.push(self.hash_ty as u8);
        }
        ser_sig
    }
}

/// An error constructing a [`taproot::Signature`] from a byte slice.
///
/// [`taproot::Signature`]: crate::crypto::taproot::Signature
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub enum SigFromSliceError {
    /// Invalid signature hash type.
    InvalidSighashType(u8),
    /// Signature has valid size but does not parse correctly
    Secp256k1(secp256k1::Error),
    /// Invalid taproot signature size
    InvalidSignatureSize(usize),
}

impl fmt::Display for SigFromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use SigFromSliceError::*;

        match *self {
            InvalidSighashType(hash_ty) => write!(f, "invalid signature hash type {}", hash_ty),
            Secp256k1(ref e) =>
                write_err!(f, "taproot signature has correct len but is malformed"; e),
            InvalidSignatureSize(sz) => write!(f, "invalid taproot signature size: {}", sz),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SigFromSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use SigFromSliceError::*;

        match self {
            Secp256k1(e) => Some(e),
            InvalidSighashType(_) | InvalidSignatureSize(_) => None,
        }
    }
}

impl From<secp256k1::Error> for SigFromSliceError {
    fn from(e: secp256k1::Error) -> Self { SigFromSliceError::Secp256k1(e) }
}
