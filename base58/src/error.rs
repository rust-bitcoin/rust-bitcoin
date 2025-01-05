// SPDX-License-Identifier: CC0-1.0

//! Error code for the `base58` crate.

use core::fmt;
use core::convert::Infallible;

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

impl From<Infallible> for Error {
    fn from(never: Infallible) -> Self { match never {} }
}

impl From<Infallible> for ErrorInner {
    fn from(never: Infallible) -> Self { match never {} }
}

impl Error {
    /// Returns the invalid base58 ssscharacter, if encountered.
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ErrorInner::*;

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
        use ErrorInner::*;

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
impl std::error::Error for IncorrectChecksumError {}

/// The decode base58 data was too short (require at least 4 bytes for checksum).
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
            "base58 decoded data was not long enough, must be at least 4 byte: {}",
            self.length
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TooShortError {}

/// Found a invalid ASCII byte while decoding base58 string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidCharacterError(pub(super) InvalidCharacterErrorInner);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InvalidCharacterErrorInner {
    pub(super) invalid: u8,
}

impl From<Infallible> for InvalidCharacterError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl From<Infallible> for InvalidCharacterErrorInner {
    fn from(never: Infallible) -> Self { match never {} }
}

impl InvalidCharacterError {
    pub(super) fn new(invalid: u8) -> Self { Self(InvalidCharacterErrorInner { invalid }) }

    /// Returns the invalid base58 character.
    pub fn invalid_character(&self) -> u8 { self.0.invalid }
}

impl fmt::Display for InvalidCharacterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid base58 character {:#x}", self.0.invalid)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidCharacterError {}
