// SPDX-License-Identifier: CC0-1.0

//! Contains error types and other error handling tools.

use core::fmt;

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

/// Formats error.
///
/// If `std` feature is OFF appends error source (delimited by `: `). We do this because
/// `e.source()` is only available in std builds, without this macro the error source is lost for
/// no-std builds.
macro_rules! write_err {
    ($writer:expr, $string:literal $(, $args:expr)*; $source:expr) => {
        {
            #[cfg(feature = "std")]
            {
                let _ = &$source;   // Prevents clippy warnings.
                write!($writer, $string $(, $args)*)
            }
            #[cfg(not(feature = "std"))]
            {
                write!($writer, concat!($string, ": {}") $(, $args)*, $source)
            }
        }
    }
}
pub(crate) use write_err;
