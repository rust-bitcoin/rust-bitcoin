// SPDX-License-Identifier: CC0-1.0

//! Error code for the `base58` crate.

use alloc::boxed::Box;
use core::convert::Infallible;
use core::fmt;

use internals::error::ParseErrorContext;
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

impl ParseErrorContext for Error {
    fn expecting<'a>(&'a self) -> Box<dyn fmt::Display + 'a> {
        struct ExpectingDisplay<D: fmt::Display>(D);
        impl<D: fmt::Display> fmt::Display for ExpectingDisplay<D> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        match &self.0 {
            ErrorInner::Decode(e) => Box::new(ExpectingDisplay(e.expecting())),
            ErrorInner::IncorrectChecksum(_) => Box::new("a correct checksum"),
            ErrorInner::TooShort(_) => Box::new("at least 4 bytes of data"),
        }
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        match &self.0 {
            ErrorInner::IncorrectChecksum(_) => Some(Box::new("Data might be corrupted or belong to a different network.")),
            ErrorInner::Decode(e) => e.help(),
            ErrorInner::TooShort(e) => {
                struct HelpDisplay(usize);
                impl fmt::Display for HelpDisplay {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "Data is too short: {} bytes (minimum required is 4).", self.0)
                    }
                }
                Some(Box::new(HelpDisplay(e.length)))
            },
        }
    }

    fn change_suggestion(&self) -> Option<&'static str> {
        match &self.0 {
            ErrorInner::Decode(e) => e.change_suggestion(),
            _ => None,
        }
    }

    fn note(&self) -> Option<&'static str> {
        None
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

/// Found an invalid ASCII byte while decoding base58 string.
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

impl ParseErrorContext for InvalidCharacterError {
    fn expecting<'a>(&'a self) -> Box<dyn fmt::Display + 'a> {
        Box::new("only valid base58 characters (123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz)")
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        struct HelpDisplay(u8);
        impl fmt::Display for HelpDisplay {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "Character '{}' (byte value {}) is not valid in Base58.", self.0 as char, self.0)
            }
        }
        Some(Box::new(HelpDisplay(self.0.invalid)))
    }

    fn change_suggestion(&self) -> Option<&'static str> {
        None
    }

    fn note(&self) -> Option<&'static str> {
        Some("Base58 uses a restricted character set to avoid visual ambiguity.")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidCharacterError {}
