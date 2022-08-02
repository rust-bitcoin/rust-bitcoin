// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! ECDSA Bitcoin signatures.
//!
//! This module provides ECDSA signatures used Bitcoin that can be roundtrip (de)serialized.

use crate::prelude::*;
use core::str::FromStr;
use core::{fmt, iter};
use crate::hashes::hex::{self, FromHex};
use crate::blockdata::transaction::NonStandardSighashType;
use secp256k1;
use crate::EcdsaSighashType;
use crate::internal_macros::write_err;

/// An ECDSA signature with the corresponding hash type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct EcdsaSig {
    /// The underlying ECDSA Signature
    pub sig: secp256k1::ecdsa::Signature,
    /// The corresponding hash type
    pub hash_ty: EcdsaSighashType,
}

impl EcdsaSig {
    /// Constructs an ECDSA bitcoin signature for [`EcdsaSighashType::All`].
    pub fn sighash_all(sig: secp256k1::ecdsa::Signature) -> EcdsaSig {
        EcdsaSig {
            sig,
            hash_ty: EcdsaSighashType::All
        }
    }

    /// Deserializes from slice following the standardness rules for [`EcdsaSighashType`].
    pub fn from_slice(sl: &[u8]) -> Result<Self, EcdsaSigError> {
        let (hash_ty, sig) = sl.split_last()
            .ok_or(EcdsaSigError::EmptySignature)?;
        let hash_ty = EcdsaSighashType::from_standard(*hash_ty as u32)
            .map_err(|_| EcdsaSigError::NonStandardSighashType(*hash_ty as u32))?;
        let sig = secp256k1::ecdsa::Signature::from_der(sig)
            .map_err(EcdsaSigError::Secp256k1)?;
        Ok(EcdsaSig { sig, hash_ty })
    }

    /// Serializes an ECDSA signature (inner secp256k1 signature in DER format).
    pub fn to_vec(self) -> Vec<u8> {
        // TODO: add support to serialize to a writer to SerializedSig
        self.sig.serialize_der()
            .iter().copied()
            .chain(iter::once(self.hash_ty as u8))
            .collect()
    }
}

impl fmt::Display for EcdsaSig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::format_hex(&self.sig.serialize_der(), f)?;
        hex::format_hex(&[self.hash_ty as u8], f)
    }
}

impl FromStr for EcdsaSig {
    type Err = EcdsaSigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = Vec::from_hex(s)?;
        let (sighash_byte, signature) = bytes.split_last()
            .ok_or(EcdsaSigError::EmptySignature)?;
        Ok(EcdsaSig {
            sig: secp256k1::ecdsa::Signature::from_der(signature)?,
            hash_ty: EcdsaSighashType::from_standard(*sighash_byte as u32)?
        })
    }
}

/// A key-related error.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub enum EcdsaSigError {
    /// Hex encoding error
    HexEncoding(hex::Error),
    /// Base58 encoding error
    NonStandardSighashType(u32),
    /// Empty Signature
    EmptySignature,
    /// secp256k1-related error
    Secp256k1(secp256k1::Error),
}


impl fmt::Display for EcdsaSigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EcdsaSigError::HexEncoding(ref e) =>
                write_err!(f, "EcdsaSig hex encoding error"; e),
            EcdsaSigError::NonStandardSighashType(hash_ty) =>
                write!(f, "Non standard signature hash type {}", hash_ty),
            EcdsaSigError::EmptySignature =>
                write!(f, "Empty ECDSA signature"),
            EcdsaSigError::Secp256k1(ref e) =>
                write_err!(f, "invalid ECDSA signature"; e),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for EcdsaSigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::EcdsaSigError::*;

        match self {
            HexEncoding(e) => Some(e),
            Secp256k1(e) => Some(e),
            NonStandardSighashType(_) | EmptySignature => None,
        }
    }
}

impl From<secp256k1::Error> for EcdsaSigError {
    fn from(e: secp256k1::Error) -> EcdsaSigError {
        EcdsaSigError::Secp256k1(e)
    }
}

impl From<NonStandardSighashType> for EcdsaSigError {
    fn from(err: NonStandardSighashType) -> Self {
        EcdsaSigError::NonStandardSighashType(err.0)
    }
}

impl From<hex::Error> for EcdsaSigError {
    fn from(err: hex::Error) -> Self {
        EcdsaSigError::HexEncoding(err)
    }
}
