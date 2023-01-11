// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! ECDSA Bitcoin signatures.
//!
//! This module provides ECDSA signatures used Bitcoin that can be roundtrip (de)serialized.

use core::str::FromStr;
use core::{fmt, iter};

use bitcoin_internals::write_err;
use secp256k1;

use crate::prelude::*;
use crate::hashes::hex::{self, FromHex};
use crate::sighash::{EcdsaSighashType, NonStandardSighashType};

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
