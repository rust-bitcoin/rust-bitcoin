// SPDX-License-Identifier: CC0-1.0

//! Consensus encoding errors.

use core::convert::Infallible;
use core::fmt;

use hex::error::{InvalidCharError, OddLengthStringError};
use hex::DisplayHex as _;
use internals::error::ParseErrorContext;
use internals::write_err;

#[cfg(doc)]
use super::IterReader;

/// Error deserializing from a slice.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeserializeError {
    /// Error parsing encoded object.
    Parse(ParseError),
    /// Data unconsumed error.
    Unconsumed,
}

impl From<Infallible> for DeserializeError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DeserializeError::*;

        match *self {
            Parse(ref e) => write_err!(f, "error parsing encoded object"; e),
            Unconsumed => write!(f, "data not consumed entirely when deserializing"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DeserializeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DeserializeError::*;

        match *self {
            Parse(ref e) => Some(e),
            Unconsumed => None,
        }
    }
}

impl From<ParseError> for DeserializeError {
    fn from(e: ParseError) -> Self { Self::Parse(e) }
}

/// Error when consensus decoding from an `[IterReader]`.
///
/// This is the same as a `DeserializeError` with an additional variant to return any error yealded
/// by the inner bytes iterator.
#[derive(Debug)]
pub enum DecodeError<E> {
    /// Invalid consensus encoding.
    Parse(ParseError),
    /// Data unconsumed error.
    Unconsumed,
    /// Other decoding error.
    Other(E), // Yielded by the inner iterator.
}

impl<E> From<Infallible> for DecodeError<E> {
    fn from(never: Infallible) -> Self { match never {} }
}

impl<E: fmt::Debug> fmt::Display for DecodeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DecodeError::*;

        match *self {
            Parse(ref e) => write_err!(f, "error parsing encoded object"; e),
            Unconsumed => write!(f, "data not consumed entirely when deserializing"),
            Other(ref other) => write!(f, "other decoding error: {:?}", other),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + std::error::Error + 'static> std::error::Error for DecodeError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DecodeError::*;

        match *self {
            Parse(ref e) => Some(e),
            Unconsumed => None,
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
    /// Error parsing encoded object.
    Parse(ParseError),
}

impl From<Infallible> for Error {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            Io(ref e) => write_err!(f, "I/O error"; e),
            Parse(ref e) => write_err!(f, "error parsing encoded object"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            Io(ref e) => Some(e),
            Parse(ref e) => Some(e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        use io::ErrorKind;

        match e.kind() {
            ErrorKind::UnexpectedEof => Error::Parse(ParseError::MissingData),
            _ => Error::Io(e),
        }
    }
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self { Error::Parse(e) }
}

/// Encoding is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
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
    /// Unsupported SegWit flag.
    UnsupportedSegwitFlag(u8),
}

impl From<Infallible> for ParseError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseError::*;

        match *self {
            MissingData => write!(f, "missing data (early end of file or slice too short)"),
            OversizedVectorAllocation { requested: ref r, max: ref m } =>
                write!(f, "allocation of oversized vector: requested {}, maximum {}", r, m),
            InvalidChecksum { expected: ref e, actual: ref a } =>
                write!(f, "invalid checksum: expected {:x}, actual {:x}", e.as_hex(), a.as_hex()),
            NonMinimalVarInt => write!(f, "non-minimal varint"),
            ParseFailed(ref s) => write!(f, "parse failed: {}", s),
            UnsupportedSegwitFlag(ref swflag) =>
                write!(f, "unsupported SegWit version: {}", swflag),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseError::*;

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

impl ParseErrorContext for ParseError {
    fn expecting(&self) -> Box<dyn fmt::Display + '_> {
        use ParseError::*;
        match self {
            MissingData => Box::new("more bytes"),
            OversizedVectorAllocation { max, .. } => {
                // Helper struct to capture max value for display
                struct MaxDisplay(usize);
                impl fmt::Display for MaxDisplay {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "a vector size less than or equal to {}", self.0)
                    }
                }
                Box::new(MaxDisplay(*max))
            }
            InvalidChecksum { .. } => Box::new("a correct checksum"),
            NonMinimalVarInt => Box::new("a minimally encoded VarInt"),
            ParseFailed(s) => {
                // Helper struct to capture string ref for display
                struct StrDisplay(&'static str);
                impl fmt::Display for StrDisplay {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        // The ParseFailed message often *is* the expectation
                        write!(f, "valid data for: {}", self.0)
                    }
                }
                Box::new(StrDisplay(s))
            }
            UnsupportedSegwitFlag(_) => Box::new("a supported SegWit version flag"),
        }
    }

    fn help(&self) -> Option<Box<dyn fmt::Display + '_>> {
        use ParseError::*;
        match self {
            MissingData => Some(Box::new("Unexpected end of input data.")),
            OversizedVectorAllocation { requested, max } => {
                struct HelpDisplay(usize, usize);
                impl fmt::Display for HelpDisplay {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "Requested vector size {} exceeds maximum allowed {}.", self.0, self.1)
                    }
                }
                Some(Box::new(HelpDisplay(*requested, *max)))
            }
            InvalidChecksum { expected, actual } => {
                struct HelpDisplay([u8;4], [u8;4]);
                impl fmt::Display for HelpDisplay {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "Checksum mismatch: expected {:x?}, got {:x?}. Data may be corrupted.", self.0, self.1)
                    }
                }
                Some(Box::new(HelpDisplay(*expected, *actual)))
            }
            NonMinimalVarInt => Some(Box::new("VarInts must be encoded using the shortest possible representation.")),
            ParseFailed(s) => Some(Box::new(format!("Parsing failed: {}", s))),
            UnsupportedSegwitFlag(flag) => {
                struct HelpDisplay(u8);
                impl fmt::Display for HelpDisplay {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "SegWit flag {} is not supported.", self.0)
                    }
                }
                Some(Box::new(HelpDisplay(*flag)))
            }
        }
    }

    fn note(&self) -> Option<&'static str> {
        use ParseError::*;
        match self {
            NonMinimalVarInt => Some("See BIP62 (Rule 5) for VarInt encoding rules."),
            UnsupportedSegwitFlag(_) => Some("Supported SegWit versions depend on network rules (e.g., v0 for BIP141, v1 for BIP341 Taproot). Ensure the version used is active."),
            _ => None,
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

/// Constructs a new `Error::ParseFailed` error.
// This whole variant should go away because of the inner string.
pub(crate) fn parse_failed_error(msg: &'static str) -> Error {
    Error::Parse(ParseError::ParseFailed(msg))
}
