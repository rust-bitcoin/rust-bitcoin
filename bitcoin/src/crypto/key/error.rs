// SPDX-License-Identifier: CC0-1.0

//! Error code for Bitcoin keys.

use core::fmt;

use internals::write_err;

use crate::base58;
#[cfg(doc)]
use crate::crypto::key::PublicKey;

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

secp256k1::impl_from_for_all_crate_errors_for!(Error);

impl From<base58::Error> for Error {
    fn from(e: base58::Error) -> Error { Error::Base58(e) }
}

impl From<hex::HexToArrayError> for Error {
    fn from(e: hex::HexToArrayError) -> Self { Error::Hex(e) }
}

/// An error while parsing a [`PublicKey`] from a slice.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublicKeyFromSliceError {
    /// Invalid slice length for a public key.
    InvalidLength(usize),
    /// A secp256k1 error.
    Secp256k1(secp256k1::PublicKeyError),
    /// Invalid prefix for public key.
    InvalidPrefix(u8),
}

impl fmt::Display for PublicKeyFromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use PublicKeyFromSliceError::*;

        match *self {
            InvalidLength(len) => write!(f, "invalid slice length for a public key: {}", len),
            Secp256k1(ref e) => write_err!(f, "secp256k1 pubkey invalid"; e),
            InvalidPrefix(byte) => write!(f, "invalid prefix for a pubic key: {}", byte),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PublicKeyFromSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::PublicKeyFromSliceError::*;

        match *self {
            Secp256k1(ref e) => Some(e),
            InvalidLength(_) | InvalidPrefix(_) => None,
        }
    }
}

impl From<secp256k1::PublicKeyError> for PublicKeyFromSliceError {
    fn from(e: secp256k1::PublicKeyError) -> Self { Self::Secp256k1(e) }
}

/// An error while parsing a [`PublicKey`] from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublicKeyFromStrError {
    /// Error parsing hex string.
    Hex(hex::HexToArrayError),
    /// `PublicKey` hex should be 66 or 130 digits long.
    InvalidHexLength(usize),
    /// Invalid slice for public key.
    FromSlice(PublicKeyFromSliceError),
}

impl fmt::Display for PublicKeyFromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use PublicKeyFromStrError::*;

        match *self {
            Hex(ref e) => write_err!(f, "hex"; e),
            InvalidHexLength(len) => write!(f, "hex length invalid for public key: {}", len),
            FromSlice(ref e) => write_err!(f, "from slice"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PublicKeyFromStrError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::PublicKeyFromStrError::*;

        match *self {
            Hex(ref e) => Some(e),
            InvalidHexLength(_) => None,
            FromSlice(ref e) => Some(e),
        }
    }
}

impl From<PublicKeyFromSliceError> for PublicKeyFromStrError {
    fn from(e: PublicKeyFromSliceError) -> Self { Self::FromSlice(e) }
}

impl From<hex::HexToArrayError> for PublicKeyFromStrError {
    fn from(e: hex::HexToArrayError) -> Self { Self::Hex(e) }
}

/// An error while parsing a [`PrivateKey`] from a WIFI string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrivateKeyFromWifiError {
    /// A base58 error.
    Base58(base58::Error),
    /// Invalid slice length for a private key.
    InvalidLength(usize),
    /// Network prefix byte not valid for WIFI private key.
    InvalidPrefix(u8),
    /// A secp256k1 error.
    Secp256k1(secp256k1::SecretKeyError),
}

impl fmt::Display for PrivateKeyFromWifiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use PrivateKeyFromWifiError::*;

        match *self {
            Base58(ref e) => write_err!(f, "base58"; e),
            InvalidLength(len) => write!(f, "invalid slice length for a public key: {}", len),
            InvalidPrefix(byte) =>
                write!(f, "network byte not valid for WIFI private key: {}", byte),
            Secp256k1(ref e) => write_err!(f, "secp256k1 pubkey invalid"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrivateKeyFromWifiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::PrivateKeyFromWifiError::*;

        match *self {
            Base58(ref e) => Some(e),
            Secp256k1(ref e) => Some(e),
            InvalidLength(_) | InvalidPrefix(_) => None,
        }
    }
}

impl From<base58::Error> for PrivateKeyFromWifiError {
    fn from(e: base58::Error) -> Self { Self::Base58(e) }
}

impl From<secp256k1::SecretKeyError> for PrivateKeyFromWifiError {
    fn from(e: secp256k1::SecretKeyError) -> Self { Self::Secp256k1(e) }
}
