// SPDX-License-Identifier: CC0-1.0

//! Error code for the `base58` crate.

use core::fmt;

use internals::write_err;

/// An error that might occur during base58 decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Invalid character while decoding.
    Decode(InvalidCharacterError),
    /// Checksum was not correct (expected, actual).
    BadChecksum(u32, u32),
    /// Checked data was less than 4 bytes.
    TooShort(usize),
}

internals::impl_from_infallible!(Error);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            Decode(ref e) => write_err!(f, "decode"; e),
            BadChecksum(exp, actual) =>
                write!(f, "base58ck checksum {:#x} does not match expected {:#x}", actual, exp),
            TooShort(_) => write!(f, "base58ck data not even long enough for a checksum"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match self {
            Decode(ref e) => Some(e),
            BadChecksum(_, _)
            | TooShort(_) => None,
        }
    }
}

impl From<InvalidCharacterError> for Error {
    #[inline]
    fn from(e: InvalidCharacterError) -> Self { Self::Decode(e) }
}

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
