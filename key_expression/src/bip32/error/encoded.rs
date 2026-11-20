// SPDX-License-Identifier: CC0-1.0

use core::convert::Infallible;
use core::fmt;

use crypto::secp256k1;
use internals::write_err;

use super::InvalidXkeyPartsError;

/// Error decoding a binary BIP-0032 extended public key without checking its version.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodedXpubDecodeError {
    /// Invalid extended key metadata.
    Xkey(InvalidXkeyPartsError),
    /// Invalid compressed public key.
    Secp256k1(secp256k1::Error),
}

impl From<Infallible> for EncodedXpubDecodeError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for EncodedXpubDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Xkey(e) => write_err!(f, "invalid extended key metadata"; e),
            Self::Secp256k1(e) => write_err!(f, "invalid compressed public key"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EncodedXpubDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Xkey(e) => Some(e),
            Self::Secp256k1(e) => Some(e),
        }
    }
}

/// Error decoding a binary BIP-0032 extended private key without checking its version.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodedXprivDecodeError {
    /// Invalid extended key metadata.
    Xkey(InvalidXkeyPartsError),
    /// Invalid secret key.
    Secp256k1(secp256k1::Error),
    /// Invalid private key prefix (byte 45 must be zero).
    InvalidPrivateKeyPrefix,
}

impl From<Infallible> for EncodedXprivDecodeError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for EncodedXprivDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Xkey(e) => write_err!(f, "invalid extended key metadata"; e),
            Self::Secp256k1(e) => write_err!(f, "invalid secret key"; e),
            Self::InvalidPrivateKeyPrefix =>
                f.write_str("invalid private key prefix, byte 45 must be zero"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EncodedXprivDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Xkey(e) => Some(e),
            Self::Secp256k1(e) => Some(e),
            Self::InvalidPrivateKeyPrefix => None,
        }
    }
}

/// Error parsing a base58check BIP-0032 extended public key without checking its version.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseEncodedXpubError {
    /// Base58 encoding error.
    Base58(base58::DecodeCheckArrayError),
    /// Binary extended public key decoding error.
    Decode(EncodedXpubDecodeError),
}

impl From<Infallible> for ParseEncodedXpubError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for ParseEncodedXpubError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Base58(e) => write_err!(f, "Base58Check decoding error"; e),
            Self::Decode(e) => write_err!(f, "invalid encoded extended public key"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseEncodedXpubError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Base58(e) => Some(e),
            Self::Decode(e) => Some(e),
        }
    }
}

/// Error parsing a base58check BIP-0032 extended private key without checking its version.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseEncodedXprivError {
    /// Base58 encoding error.
    Base58(base58::DecodeCheckArrayError),
    /// Binary extended private key decoding error.
    Decode(EncodedXprivDecodeError),
}

impl From<Infallible> for ParseEncodedXprivError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for ParseEncodedXprivError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Base58(e) => write_err!(f, "Base58Check decoding error"; e),
            Self::Decode(e) => write_err!(f, "invalid encoded extended private key"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseEncodedXprivError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Base58(e) => Some(e),
            Self::Decode(e) => Some(e),
        }
    }
}

/// The version bytes are not recognized for this kind of BIP-0032 extended key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownXkeyVersionError {
    version: [u8; 4],
}

impl UnknownXkeyVersionError {
    pub(in crate::bip32) fn new(version: [u8; 4]) -> Self { Self { version } }

    /// Returns the unrecognized version bytes.
    pub fn version_bytes(&self) -> [u8; 4] { self.version }
}

impl From<Infallible> for UnknownXkeyVersionError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for UnknownXkeyVersionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unknown extended key version bytes: {:02x?}", self.version)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownXkeyVersionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let Self { version: _ } = self;
        None
    }
}
