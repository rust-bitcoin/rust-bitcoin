// SPDX-License-Identifier: CC0-1.0

//! Error code for Bitcoin keys.

use core::fmt;

use internals::write_err;

use crate::base58;

/// A key-related error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A base58 error.
    Base58(base58::Error),
    /// A secp256k1 error.
    Secp256k1(secp256k1::Error),
    /// Invalid key prefix error.
    InvalidKeyPrefix(u8),
    /// Hex decoding error.
    Hex(hex::HexToArrayError),
    /// `PublicKey` hex should be 66 or 130 digits long.
    InvalidHexLength(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            Base58(ref e) => write_err!(f, "base58"; e),
            Secp256k1(ref e) => write_err!(f, "secp256k1"; e),
            InvalidKeyPrefix(ref b) => write!(f, "key prefix invalid: {}", b),
            Hex(ref e) => write_err!(f, "hex"; e),
            InvalidHexLength(got) =>
                write!(f, "pubkey hex should be 66 or 130 digits long, got: {}", got),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            Base58(e) => Some(e),
            Secp256k1(e) => Some(e),
            Hex(e) => Some(e),
            InvalidKeyPrefix(_) | InvalidHexLength(_) => None,
        }
    }
}

impl From<base58::Error> for Error {
    fn from(e: base58::Error) -> Error { Error::Base58(e) }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error { Error::Secp256k1(e) }
}

impl From<hex::HexToArrayError> for Error {
    fn from(e: hex::HexToArrayError) -> Self { Error::Hex(e) }
}
