// SPDX-License-Identifier: CC0-1.0

//! Error code for the `base58` crate.

use core::fmt;

use internals::write_err;

/// An error occurred during base58 decoding (with checksum).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Invalid character while decoding.
    Decode(InvalidCharacterError),
    /// Checksum was not correct.
    IncorrectChecksum(IncorrectChecksumError),
    /// Checked data was too short.
    TooShort(TooShortError),
}

internals::impl_from_infallible!(Error);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            Decode(ref e) => write_err!(f, "decode"; e),
            IncorrectChecksum(ref e) => write_err!(f, "incorrect checksum"; e),
            TooShort(ref e) => write_err!(f, "too short"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            Decode(ref e) => Some(e),
            IncorrectChecksum(ref e) => Some(e),
            TooShort(ref e) => Some(e),
        }
    }
}

impl From<InvalidCharacterError> for Error {
    #[inline]
    fn from(e: InvalidCharacterError) -> Self { Self::Decode(e) }
}

impl From<IncorrectChecksumError> for Error {
    #[inline]
    fn from(e: IncorrectChecksumError) -> Self { Self::IncorrectChecksum(e) }
}

impl From<TooShortError> for Error {
    #[inline]
    fn from(e: TooShortError) -> Self { Self::TooShort(e) }
}

/// Checksum was not correct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncorrectChecksumError {
    /// The incorrect checksum.
    pub(super) incorrect: u32,
    /// The expected checksum.
    pub(super) expected: u32,
}

impl IncorrectChecksumError {
    /// Returns the incorrect checksum along with the expected checksum.
    pub fn incorrect_checksum(&self) -> (u32, u32) { (self.incorrect, self.expected) }
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
pub struct TooShortError {
    /// The length of the decoded data.
    pub(super) length: usize,
}

impl TooShortError {
    /// Returns the invalid base58 string length (require at least 4 bytes for checksum).
    pub fn invalid_base58_length(&self) -> usize { self.length }
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
pub struct InvalidCharacterError {
    pub(super) invalid: u8,
}

impl InvalidCharacterError {
    /// Returns the ASCII byte that is not a valid base58 character.
    pub fn invalid_base58_character(&self) -> u8 { self.invalid }
}

impl fmt::Display for InvalidCharacterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid base58 character {:#x}", self.invalid)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidCharacterError {}
