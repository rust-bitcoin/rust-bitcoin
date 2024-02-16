// SPDX-License-Identifier: CC0-1.0

//! Contains error types and other error handling tools.

use core::fmt;

use internals::write_err;

#[deprecated(since = "TBD", note = "use bitcoin::units::ParseIntError instead")]
#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use units::parse::ParseIntError;

/// Hex decoding error.
// Intentionally opaque so as to hide `hex` from the public API - do not make the inner error pub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromHexInvalidCharError(pub(crate) hex::FromHexError<hex::InvalidCharError>);

impl fmt::Display for FromHexInvalidCharError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write_err!(f, "from hex"; self.0) }
}

#[cfg(feature = "std")]
impl std::error::Error for FromHexInvalidCharError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// Hex decoding error.
// Intentionally opaque so as to hide `hex` from the public API - do not make the inner error pub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromHexHexToArrayError(pub(crate) hex::FromHexError<hex::InvalidCharError>);

impl fmt::Display for FromHexHexToArrayError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write_err!(f, "from hex"; self.0) }
}

#[cfg(feature = "std")]
impl std::error::Error for FromHexHexToArrayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// Error decoding a hex string that explicitly excludes a prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
// Intentionally opaque so as to hide `hex` from the public API - do not make the inner error pub.
pub struct FromNoPrefixHexInvalidCharError(pub(crate) hex::FromNoPrefixHexError<hex::InvalidCharError>);

impl fmt::Display for FromNoPrefixHexInvalidCharError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write_err!(f, "from no prefix hex"; self.0) }
}

#[cfg(feature = "std")]
impl std::error::Error for FromNoPrefixHexInvalidCharError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// Error decoding a hex string that explicitly excludes a prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
// Intentionally opaque so as to hide `hex` from the public API - do not make the inner error pub.
pub struct FromNoPrefixHexHexToArrayError(pub(crate) hex::FromNoPrefixHexError<hex::HexToArrayError>);

impl fmt::Display for FromNoPrefixHexHexToArrayError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write_err!(f, "from no prefix hex"; self.0) }
}

#[cfg(feature = "std")]
impl std::error::Error for FromNoPrefixHexHexToArrayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// Invalid hex character.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct InvalidCharError(pub(crate) hex::InvalidCharError);

impl fmt::Display for InvalidCharError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write_err!(f, "invalid char"; self.0) }
}


#[cfg(feature = "std")]
impl std::error::Error for InvalidCharError {
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

