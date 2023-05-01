// SPDX-License-Identifier: CC0-1.0

//! Crate error type.
//!

use core::fmt;

/// Crate error type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Error {
    /// Tried to create a fixed-length hash from a slice with the wrong size (expected, got).
    InvalidLength(usize, usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            InvalidLength(ref ell, ref ell2) =>
                write!(f, "invalid slice length {} (expected {})", ell2, ell),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            InvalidLength(_, _) => None,
        }
    }
}
