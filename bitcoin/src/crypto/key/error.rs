//! Error code for the key module.

use core::fmt;

use internals::write_err;

use crate::base58;

/// A key-related error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Base58 encoding error
    Base58(base58::Error),
    /// secp256k1-related error
    Secp256k1(secp256k1::Error),
    /// Invalid key prefix error
    InvalidKeyPrefix(u8),
    /// Hex decoding error
    Hex(hex::HexToArrayError),
    /// `PublicKey` hex should be 66 or 130 digits long.
    InvalidHexLength(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Base58(ref e) => write_err!(f, "key base58 error"; e),
            Error::Secp256k1(ref e) => write_err!(f, "key secp256k1 error"; e),
            Error::InvalidKeyPrefix(ref b) => write!(f, "key prefix invalid: {}", b),
            Error::Hex(ref e) => write_err!(f, "key hex decoding error"; e),
            Error::InvalidHexLength(got) =>
                write!(f, "PublicKey hex should be 66 or 130 digits long, got: {}", got),
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

secp256k1::impl_from_for_all_crate_errors_for!(Error);

impl From<base58::Error> for Error {
    fn from(e: base58::Error) -> Error { Error::Base58(e) }
}

impl From<hex::HexToArrayError> for Error {
    fn from(e: hex::HexToArrayError) -> Self { Error::Hex(e) }
}
