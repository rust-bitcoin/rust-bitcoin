// SPDX-License-Identifier: CC0-1.0

//! Error code for the `base58` crate.

use core::convert::Infallible;
use core::fmt;

use internals::write_err;

/// An error occurred during base58 decoding (with checksum).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub(super) ErrorInner);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ErrorInner {
    /// Invalid character while decoding.
    Decode(InvalidCharacterError),
    /// Checksum was not correct.
    IncorrectChecksum(IncorrectChecksumError),
    /// Checked data was too short.
    TooShort(TooShortError),
}

impl Error {
    /// Returns the invalid base58 character, if encountered.
    pub fn invalid_character(&self) -> Option<u8> {
        match self.0 {
            ErrorInner::Decode(ref e) => Some(e.invalid_character()),
            _ => None,
        }
    }

    /// Returns the incorrect checksum along with the expected checksum, if encountered.
    pub fn incorrect_checksum(&self) -> Option<(u32, u32)> {
        match self.0 {
            ErrorInner::IncorrectChecksum(ref e) => Some((e.incorrect, e.expected)),
            _ => None,
        }
    }

    /// Returns the invalid base58 string length (require at least 4 bytes for checksum), if encountered.
    pub fn invalid_length(&self) -> Option<usize> {
        match self.0 {
            ErrorInner::TooShort(ref e) => Some(e.length),
            _ => None,
        }
    }
}

impl From<Infallible> for Error {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ErrorInner::{Decode, IncorrectChecksum, TooShort};

        match self.0 {
            Decode(ref e) => write_err!(f, "decode"; e),
            IncorrectChecksum(ref e) => write_err!(f, "incorrect checksum"; e),
            TooShort(ref e) => write_err!(f, "too short"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ErrorInner::{Decode, IncorrectChecksum, TooShort};

        match self.0 {
            Decode(ref e) => Some(e),
            IncorrectChecksum(ref e) => Some(e),
            TooShort(ref e) => Some(e),
        }
    }
}

impl From<InvalidCharacterError> for Error {
    fn from(e: InvalidCharacterError) -> Self { Self(ErrorInner::Decode(e)) }
}

impl From<IncorrectChecksumError> for Error {
    fn from(e: IncorrectChecksumError) -> Self { Self(ErrorInner::IncorrectChecksum(e)) }
}

impl From<TooShortError> for Error {
    fn from(e: TooShortError) -> Self { Self(ErrorInner::TooShort(e)) }
}

/// Checksum was not correct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IncorrectChecksumError {
    /// The incorrect checksum.
    pub(super) incorrect: u32,
    /// The expected checksum.
    pub(super) expected: u32,
}

impl From<Infallible> for IncorrectChecksumError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for IncorrectChecksumError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "base58 checksum {:#x} does not match expected {:#x}",
            self.incorrect, self.expected
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IncorrectChecksumError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let Self { incorrect: _, expected: _ } = self;
        None
    }
}

/// The decoded base58 data was too short (require at least 4 bytes for checksum).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TooShortError {
    /// The length of the decoded data.
    pub(super) length: usize,
}

impl From<Infallible> for TooShortError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for TooShortError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "base58 decoded data was not long enough, must be at least 4 bytes: {}",
            self.length
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TooShortError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let Self { length: _ } = self;
        None
    }
}

/// The input was too long to be encoded into the fixed-size buffer.
///
/// Without `alloc` any encoded base58check string must fit in 128 characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputTooLongError(pub(super) InputTooLongErrorInner);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InputTooLongErrorInner {
    /// The length of the un-encoded input data in bytes (excluding the 4 checksum bytes).
    pub(super) input_len: usize,
}

impl InputTooLongError {
    /// Returns the length of the input data in bytes (excluding the 4 checksum bytes).
    pub fn input_length(&self) -> usize { self.0.input_len }
}

impl From<Infallible> for InputTooLongError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for InputTooLongError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "base58check encoding of {} bytes of data exceeds the 128 character buffer",
            self.0.input_len
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InputTooLongError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let InputTooLongErrorInner { input_len: _ } = self.0;
        None
    }
}

/// Found an invalid ASCII byte while decoding base58 string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidCharacterError(pub(super) InvalidCharacterErrorInner);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InvalidCharacterErrorInner {
    pub(super) invalid: u8,
}

impl InvalidCharacterError {
    #[cfg(feature = "alloc")]
    pub(super) fn new(invalid: u8) -> Self { Self(InvalidCharacterErrorInner { invalid }) }

    /// Returns the invalid base58 character.
    pub fn invalid_character(&self) -> u8 { self.0.invalid }
}

impl From<Infallible> for InvalidCharacterError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for InvalidCharacterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid base58 character {:#x}", self.0.invalid)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidCharacterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let Self(_) = self;
        None
    }
}
