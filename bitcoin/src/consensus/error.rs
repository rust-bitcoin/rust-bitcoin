// SPDX-License-Identifier: CC0-1.0

//! Consensus encoding errors.

use core::fmt;

use hex::error::{InvalidCharError, OddLengthStringError};
use hex::DisplayHex as _;
use internals::write_err;

#[cfg(doc)]
use super::IterReader;

/// Error deserializing from a slice.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeserError {
    /// Invalid encoding.
    Invalid(InvalidError),
    /// Data unconsumed error.
    Unconsumed,
}

internals::impl_from_infallible!(DeserError);

impl fmt::Display for DeserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DeserError::*;

        match *self {
            Invalid(ref e) => write_err!(f, "invalid encoding"; e),
            Unconsumed => write!(f, "data not consumed entirely when deserializing"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DeserError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DeserError::*;

        match *self {
            Invalid(ref e) => Some(e),
            Unconsumed => None,
        }
    }
}

impl From<InvalidError> for DeserError {
    fn from(e: InvalidError) -> Self { Self::Invalid(e) }
}

/// Error when consensus decoding from an `[IterReader]`.
#[derive(Debug)]
pub enum DecodeError<E> {
    /// Attempted to decode an object from an iterator that yielded too many bytes.
    TooManyBytes,
    /// Invalid consensus encoding.
    Consensus(Error),
    /// Other decoding error.
    Other(E),
}

internals::impl_from_infallible!(DecodeError<E>);

impl<E: fmt::Debug> fmt::Display for DecodeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DecodeError::*;

        match *self {
            TooManyBytes =>
                write!(f, "attempted to decode object from an iterator that yielded too many bytes"),
            Consensus(ref e) => write_err!(f, "invalid consensus encoding"; e),
            Other(ref other) => write!(f, "other decoding error: {:?}", other),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + std::error::Error + 'static> std::error::Error for DecodeError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DecodeError::*;

        match *self {
            TooManyBytes => None,
            Consensus(ref e) => Some(e),
            Other(ref e) => Some(e),
        }
    }
}

/// Encoding error.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// And I/O error.
    Io(io::Error),
    /// Invalid encoding.
    Invalid(InvalidError),
}

internals::impl_from_infallible!(Error);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            Io(ref e) => write_err!(f, "IO error"; e),
            Invalid(ref e) => write_err!(f, "invalid encoding"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            Io(ref e) => Some(e),
            Invalid(ref e) => Some(e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        use io::ErrorKind;

        match e.kind() {
            ErrorKind::UnexpectedEof => Error::Invalid(InvalidError::MissingData),
            _ => Error::Io(e),
        }
    }
}

impl From<InvalidError> for Error {
    fn from(e: InvalidError) -> Self { Error::Invalid(e) }
}

/// Encoding is invalid.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidError {
    /// Missing data (early end of file or slice too short).
    MissingData, // TODO: Can we add more context?
    /// Tried to allocate an oversized vector.
    OversizedVectorAllocation {
        /// The capacity requested.
        requested: usize,
        /// The maximum capacity.
        max: usize,
    },
    /// Checksum was invalid.
    InvalidChecksum {
        /// The expected checksum.
        expected: [u8; 4],
        /// The invalid checksum.
        actual: [u8; 4],
    },
    /// VarInt was encoded in a non-minimal way.
    NonMinimalVarInt,
    /// Parsing error.
    ParseFailed(&'static str),
    /// Unsupported Segwit flag.
    UnsupportedSegwitFlag(u8),
}

internals::impl_from_infallible!(InvalidError);

impl fmt::Display for InvalidError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InvalidError::*;

        match *self {
            MissingData => write!(f, "missing data (early end of file or slice too short)"),
            OversizedVectorAllocation { requested: ref r, max: ref m } =>
                write!(f, "allocation of oversized vector: requested {}, maximum {}", r, m),
            InvalidChecksum { expected: ref e, actual: ref a } =>
                write!(f, "invalid checksum: expected {:x}, actual {:x}", e.as_hex(), a.as_hex()),
            NonMinimalVarInt => write!(f, "non-minimal varint"),
            ParseFailed(ref s) => write!(f, "parse failed: {}", s),
            UnsupportedSegwitFlag(ref swflag) =>
                write!(f, "unsupported segwit version: {}", swflag),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InvalidError::*;

        match self {
            MissingData
            | OversizedVectorAllocation { .. }
            | InvalidChecksum { .. }
            | NonMinimalVarInt
            | ParseFailed(_)
            | UnsupportedSegwitFlag(_) => None,
        }
    }
}

/// Hex deserialization error.
#[derive(Debug)]
pub enum FromHexError {
    /// Purported hex string had odd length.
    OddLengthString(OddLengthStringError),
    /// Decoding error.
    Decode(DecodeError<InvalidCharError>),
}

impl fmt::Display for FromHexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use FromHexError::*;

        match *self {
            OddLengthString(ref e) =>
                write_err!(f, "odd length, failed to create bytes from hex"; e),
            Decode(ref e) => write_err!(f, "decoding error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromHexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use FromHexError::*;

        match *self {
            OddLengthString(ref e) => Some(e),
            Decode(ref e) => Some(e),
        }
    }
}

impl From<OddLengthStringError> for FromHexError {
    #[inline]
    fn from(e: OddLengthStringError) -> Self { Self::OddLengthString(e) }
}

/// Constructs a `Error::ParseFailed` error.
// This whole variant should go away because of the inner string.
pub(crate) fn parse_failed_error(msg: &'static str) -> Error {
    Error::Invalid(InvalidError::ParseFailed(msg))
}
