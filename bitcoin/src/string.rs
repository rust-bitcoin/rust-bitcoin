// SPDX-License-Identifier: CC0-1.0

//! Bitcoin string parsing utilities.
//!
//! This module provides utility types and traits
//! to support handling and parsing strings within `rust-bitcoin`.

use core::fmt;

use bitcoin_internals::write_err;

use crate::prelude::String;

/// Trait that allows types to be initialized from hex strings
pub trait FromHexStr: Sized {
    /// An error occurred while parsing the hex string.
    type Error;

    /// Parses provided string as hex requiring 0x prefix.
    ///
    /// This is intended for user-supplied inputs or already-existing protocols in which 0x prefix is used.
    fn from_hex_str<S: AsRef<str> + Into<String>>(s: S) -> Result<Self, FromHexError<Self::Error>> {
        if !s.as_ref().starts_with("0x") {
            Err(FromHexError::MissingPrefix(s.into()))
        } else {
            Ok(Self::from_hex_str_no_prefix(s.as_ref().trim_start_matches("0x"))?)
        }
    }

    /// Parses provided string as hex without requiring 0x prefix.
    ///
    /// This is **not** recommended for user-supplied inputs because of possible confusion with decimals.
    /// It should be only used for existing protocols which always encode values as hex without 0x prefix.
    fn from_hex_str_no_prefix<S: AsRef<str> + Into<String>>(s: S) -> Result<Self, Self::Error>;
}

/// Hex parsing error
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum FromHexError<E> {
    /// The input was not a valid hex string, contains the error that occurred while parsing.
    ParseHex(E),
    /// The input is missing `0x` prefix, contains the invalid input.
    MissingPrefix(String),
}

impl<E> From<E> for FromHexError<E> {
    fn from(e: E) -> Self { FromHexError::ParseHex(e) }
}

impl<E: fmt::Display> fmt::Display for FromHexError<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::FromHexError::*;

        match *self {
            ParseHex(ref e) => write_err!(f, "failed to parse hex string"; e),
            MissingPrefix(ref value) =>
                write_err!(f, "the input value `{}` is missing the `0x` prefix", value; self),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<E> std::error::Error for FromHexError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::FromHexError::*;

        match *self {
            ParseHex(ref e) => Some(e),
            MissingPrefix(_) => None,
        }
    }
}
