// SPDX-License-Identifier: CC0-1.0

//! Error code for the `hashes` crate.

use core::convert::Infallible;
use core::fmt;

/// Attempted to create a hash from an invalid length slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromSliceError(pub(crate) FromSliceErrorInner);

impl From<Infallible> for FromSliceError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl FromSliceError {
    /// Returns the expected slice length.
    pub fn expected_length(&self) -> usize { self.0.expected }

    /// Returns the invalid slice length.
    pub fn invalid_length(&self) -> usize { self.0.got }

    /// Returns `true` if the slice was invalid due to containing no non-zero
    /// bytes.
    pub fn invalid_all_zeros(&self) -> bool {
        matches!(self.0.invalid_all_zeros, Some(true))
    }
}

/// Attempted to create a hash from an invalid slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FromSliceErrorInner {
    pub(crate) expected: usize,
    pub(crate) got: usize,
    /// `Some(true)` if the slice is invalid due to containing no non-zero
    /// bytes.
    /// `None` if an all-zero slice is valid.
    pub(crate) invalid_all_zeros: Option<bool>,
}

impl From<Infallible> for FromSliceErrorInner {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for FromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let invalid_length = self.0.expected != self.0.got;
        let show_invalid_length =
            |f: &mut fmt::Formatter| write!(f, "invalid slice length {} (expected {})", self.0.got, self.0.expected);
        let show_invalid_all_zeros =
            |f: &mut fmt::Formatter| write!(f, "invalid slice (all zeros)");
        match (invalid_length, self.0.invalid_all_zeros) {
            (true, Some(true)) => {
                show_invalid_length(f)?;
                write!(f, ",")?;
                show_invalid_all_zeros(f)
            },
            (true, Some(false) | None) => show_invalid_length(f),
            (false, Some(true)) => show_invalid_all_zeros(f),
            (false, Some(false) | None) => {
                write!(f, "unknown error")
            }
        }

    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromSliceError {}
