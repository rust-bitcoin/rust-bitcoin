// SPDX-License-Identifier: CC0-1.0

//! Contains error types and other error handling tools.

use core::fmt;

use internals::write_err;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use crate::parse::ParseIntError;

/// Error converting hex to bytes.
// Intentionally opaque so as to hide `hex` from the public API - do not make the inner error pub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexToBytesError(pub(crate) hex::HexToBytesError);

impl fmt::Display for HexToBytesError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write_err!(f, "hex to bytes"; self.0) }
}

#[cfg(feature = "std")]
impl std::error::Error for HexToBytesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// Error converting hex to an array.
// Intentionally opaque so as to hide `hex` from the public API - do not make the inner error pub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexToArrayError(pub(crate) hex::HexToArrayError);

impl fmt::Display for HexToArrayError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write_err!(f, "hex to array"; self.0) }
}

#[cfg(feature = "std")]
impl std::error::Error for HexToArrayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}
