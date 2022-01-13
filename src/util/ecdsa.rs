// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! ECDSA Bitcoin signatures.
//!
//! This module provides ECDSA signatures used Bitcoin that can be roundtrip (de)serialized.

use prelude::*;
use core::str::FromStr;
use core::{fmt, iter};
use hashes::hex::{self, FromHex};
use blockdata::transaction::NonStandardSigHashType;
use secp256k1;
use EcdsaSigHashType;

/// An ECDSA signature with the corresponding hash type.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EcdsaSig {
    /// The underlying ECDSA Signature
    pub sig: secp256k1::ecdsa::Signature,
    /// The corresponding hash type
    pub hash_ty: EcdsaSigHashType,
}

impl EcdsaSig {
    /// Constructs ECDSA bitcoin signature for [`EcdsaSigHashType::All`]
    pub fn sighash_all(sig: secp256k1::ecdsa::Signature) -> EcdsaSig {
        EcdsaSig {
            sig,
            hash_ty: EcdsaSigHashType::All
        }
    }

    /// Deserialize from slice following the standardness rules for [`EcdsaSigHashType`]
    pub fn from_slice(sl: &[u8]) -> Result<Self, EcdsaSigError> {
        let (hash_ty, sig) = sl.split_last()
            .ok_or(EcdsaSigError::EmptySignature)?;
        let hash_ty = EcdsaSigHashType::from_u32_standard(*hash_ty as u32)
            .map_err(|_| EcdsaSigError::NonStandardSigHashType(*hash_ty as u32))?;
        let sig = secp256k1::ecdsa::Signature::from_der(sig)
            .map_err(EcdsaSigError::Secp256k1)?;
        Ok(EcdsaSig { sig, hash_ty })
    }

    /// Serialize EcdsaSig
    pub fn to_vec(&self) -> Vec<u8> {
        // TODO: add support to serialize to a writer to SerializedSig
        self.sig.serialize_der()
            .iter().map(|x| *x)
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
            hash_ty: EcdsaSigHashType::from_u32_standard(*sighash_byte as u32)?
        })
    }
}

/// A key-related error.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum EcdsaSigError {
    /// Hex encoding error
    HexEncoding(hex::Error),
    /// Base58 encoding error
    NonStandardSigHashType(u32),
    /// Empty Signature
    EmptySignature,
    /// secp256k1-related error
    Secp256k1(secp256k1::Error),
}


impl fmt::Display for EcdsaSigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EcdsaSigError::NonStandardSigHashType(hash_ty) =>
                write!(f, "Non standard signature hash type {}", hash_ty),
            EcdsaSigError::Secp256k1(ref e) =>
                write!(f, "Invalid Ecdsa signature: {}", e),
            EcdsaSigError::EmptySignature =>
                write!(f, "Empty ECDSA signature"),
            EcdsaSigError::HexEncoding(e) => write!(f, "EcdsaSig hex encoding error: {}", e)
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl ::std::error::Error for EcdsaSigError {}

impl From<secp256k1::Error> for EcdsaSigError {
    fn from(e: secp256k1::Error) -> EcdsaSigError {
        EcdsaSigError::Secp256k1(e)
    }
}

impl From<NonStandardSigHashType> for EcdsaSigError {
    fn from(err: NonStandardSigHashType) -> Self {
        EcdsaSigError::NonStandardSigHashType(err.0)
    }
}

impl From<hex::Error> for EcdsaSigError {
    fn from(err: hex::Error) -> Self {
        EcdsaSigError::HexEncoding(err)
    }
}
