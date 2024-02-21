// SPDX-License-Identifier: CC0-1.0

//! Error code for the `base58` crate.

use core::fmt;

/// An error that might occur during base58 decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Invalid character encountered.
    BadByte(u8),
    /// Checksum was not correct (expected, actual).
    BadChecksum(u32, u32),
    /// The length (in bytes) of the object was not correct.
    ///
    /// Note that if the length is excessively long the provided length may be an estimate (and the
    /// checksum step may be skipped).
    InvalidLength(usize),
    /// Extended Key version byte(s) were not recognized.
    InvalidExtendedKeyVersion([u8; 4]),
    /// Address version byte were not recognized.
    InvalidAddressVersion(u8),
    /// Checked data was less than 4 bytes.
    TooShort(usize),
}

internals::impl_from_infallible!(Error);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            BadByte(b) => write!(f, "invalid base58 character {:#x}", b),
            BadChecksum(exp, actual) =>
                write!(f, "base58ck checksum {:#x} does not match expected {:#x}", actual, exp),
            InvalidLength(ell) => write!(f, "length {} invalid for this base58 type", ell),
            InvalidExtendedKeyVersion(ref v) =>
                write!(f, "extended key version {:#04x?} is invalid for this base58 type", v),
            InvalidAddressVersion(ref v) =>
                write!(f, "address version {} is invalid for this base58 type", v),
            TooShort(_) => write!(f, "base58ck data not even long enough for a checksum"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match self {
            BadByte(_)
            | BadChecksum(_, _)
            | InvalidLength(_)
            | InvalidExtendedKeyVersion(_)
            | InvalidAddressVersion(_)
            | TooShort(_) => None,
        }
    }
}
