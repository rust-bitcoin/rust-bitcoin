// SPDX-License-Identifier: CC0-1.0

//! Error code for the `hashes` crate.

use core::fmt;

/// Attempted to create a hash from an invalid length slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromSliceError(pub(crate) FromSliceErrorInner);

impl FromSliceError {
    /// Returns the expected slice length.
    pub fn expected_length(&self) -> usize { self.0.expected }

    /// Returns the invalid slice length.
    pub fn invalid_length(&self) -> usize { self.0.got }
}

/// Attempted to create a hash from an invalid length slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FromSliceErrorInner {
    pub(crate) expected: usize,
    pub(crate) got: usize,
}

impl fmt::Display for FromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid slice length {} (expected {})", self.0.got, self.0.expected)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromSliceError {}
