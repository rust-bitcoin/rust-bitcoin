// SPDX-License-Identifier: CC0-1.0

//! Error code for ECDSA Bitcoin signatures.

use core::fmt;

use internals::write_err;
use secp256k1;

use crate::sighash::NonStandardSighashTypeError;

/// An ECDSA signature-related error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Hex decoding error.
    Hex(hex::HexToBytesError),
    /// Non-standard sighash type.
    SighashType(NonStandardSighashTypeError),
    /// Signature was empty.
    EmptySignature,
    /// A secp256k1 error.
    Secp256k1(secp256k1::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            Hex(ref e) => write_err!(f, "signature hex decoding error"; e),
            SighashType(ref e) => write_err!(f, "non-standard signature hash type"; e),
            EmptySignature => write!(f, "empty ECDSA signature"),
            Secp256k1(ref e) => write_err!(f, "secp256k1"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            Hex(e) => Some(e),
            Secp256k1(e) => Some(e),
            SighashType(e) => Some(e),
            EmptySignature => None,
        }
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error { Error::Secp256k1(e) }
}

impl From<NonStandardSighashTypeError> for Error {
    fn from(err: NonStandardSighashTypeError) -> Self { Error::SighashType(err) }
}

impl From<hex::HexToBytesError> for Error {
    fn from(err: hex::HexToBytesError) -> Self { Error::Hex(err) }
}
