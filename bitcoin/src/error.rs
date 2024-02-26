// SPDX-License-Identifier: CC0-1.0

//! Contains error types and other error handling tools.

use core::fmt;

use internals::write_err;

use crate::prelude::*;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use crate::parse::ParseIntError;

/// Error returned when parsing integer from an supposedly prefixed hex string for
/// a type that can be created infallibly from an integer.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PrefixedHexError {
    /// Hex string is missing prefix.
    MissingPrefix(MissingPrefixError),
    /// Error parsing integer from hex string.
    ParseInt(ParseIntError),
}

impl fmt::Display for PrefixedHexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use PrefixedHexError::*;

        match *self {
            MissingPrefix(ref e) => write_err!(f, "hex string is missing prefix"; e),
            ParseInt(ref e) => write_err!(f, "prefixed hex string invalid int"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrefixedHexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use PrefixedHexError::*;

        match *self {
            MissingPrefix(ref e) => Some(e),
            ParseInt(ref e) => Some(e),
        }
    }
}

impl From<MissingPrefixError> for PrefixedHexError {
    fn from(e: MissingPrefixError) -> Self { Self::MissingPrefix(e) }
}

impl From<ParseIntError> for PrefixedHexError {
    fn from(e: ParseIntError) -> Self { Self::ParseInt(e) }
}

/// Error returned when parsing integer from an supposedly un-prefixed hex string.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum UnprefixedHexError {
    /// Hex string contains prefix.
    ContainsPrefix(ContainsPrefixError),
    /// Error parsing integer from string.
    ParseInt(ParseIntError),
}

impl fmt::Display for UnprefixedHexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use UnprefixedHexError::*;

        match *self {
            ContainsPrefix(ref e) => write_err!(f, "hex string is contains prefix"; e),
            ParseInt(ref e) => write_err!(f, "hex string parse int"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnprefixedHexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use UnprefixedHexError::*;

        match *self {
            ContainsPrefix(ref e) => Some(e),
            ParseInt(ref e) => Some(e),
        }
    }
}

impl From<ContainsPrefixError> for UnprefixedHexError {
    fn from(e: ContainsPrefixError) -> Self { Self::ContainsPrefix(e) }
}

impl From<ParseIntError> for UnprefixedHexError {
    fn from(e: ParseIntError) -> Self { Self::ParseInt(e) }
}

/// Error when hex string is missing a prefix (e.g. 0x).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MissingPrefixError {
    hex: String,
}

impl MissingPrefixError {
    pub(crate) fn new(s: &str) -> Self { Self { hex: s.into() } }
}

impl fmt::Display for MissingPrefixError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "hex string is missing a prefix (e.g. 0x): {}", self.hex)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MissingPrefixError {}

/// Error when hex string contains a prefix (e.g. 0x).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ContainsPrefixError {
    hex: String,
}

impl ContainsPrefixError {
    pub(crate) fn new(s: &str) -> Self { Self { hex: s.into() } }
}

impl fmt::Display for ContainsPrefixError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "hex string contains a prefix: {}", self.hex)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ContainsPrefixError {}
