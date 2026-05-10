// SPDX-License-Identifier: CC0-1.0

//! Error types for Bitcoin scripts.

use core::convert::Infallible;
use core::fmt;

use encoding::ByteVecDecoderError;
use internals::write_err;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use crate::hash_types::{RedeemScriptSizeError, WitnessScriptSizeError};
#[doc(inline)]
pub use super::push_bytes::PushBytesError;

/// An error consensus decoding a `ScriptBuf<T>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptBufDecoderError(pub(super) ByteVecDecoderError);

impl From<Infallible> for ScriptBufDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for ScriptBufDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write_err!(f, "decoder error"; self.0) }
}

#[cfg(feature = "std")]
impl std::error::Error for ScriptBufDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// An error parsing a script from hex.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg(feature = "hex")]
pub enum FromHexError {
    /// Error parsing the hex input string.
    Hex(hex::DecodeVariableLengthBytesError),
    /// Error when decoding the script.
    Decoder(encoding::DecodeError<ScriptBufDecoderError>),
}

#[cfg(feature = "hex")]
impl From<Infallible> for FromHexError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "hex")]
impl fmt::Display for FromHexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Hex(ref e) => write_err!(f, "script hex"; e),
            Self::Decoder(ref e) => write_err!(f, "script decoder"; e),
        }
    }
}

#[cfg(feature = "hex")]
#[cfg(feature = "std")]
impl std::error::Error for FromHexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::Hex(ref e) => Some(e),
            Self::Decoder(ref e) => Some(e),
        }
    }
}

#[cfg(feature = "hex")]
impl From<hex::DecodeVariableLengthBytesError> for FromHexError {
    fn from(e: hex::DecodeVariableLengthBytesError) -> Self { Self::Hex(e) }
}

#[cfg(feature = "hex")]
impl From<encoding::DecodeError<ScriptBufDecoderError>> for FromHexError {
    fn from(e: encoding::DecodeError<ScriptBufDecoderError>) -> Self { Self::Decoder(e) }
}
