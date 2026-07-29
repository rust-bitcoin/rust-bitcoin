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
