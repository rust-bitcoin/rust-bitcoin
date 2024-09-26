// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use crate::consensus::encode;
use crate::psbt::map::global::{self, UnsignedTxError};
use crate::psbt::map::{input, output};

/// Error while deserializing a PSBT.
///
/// This error is returned when deserializing a complete PSBT, not for deserializing parts
/// of it or individual data types.
#[derive(Debug)]
#[non_exhaustive]
pub enum DeserializeError {
    /// Invalid magic bytes, expected the ASCII for "psbt" serialized in most significant byte order.
    // TODO: Consider adding the invalid bytes.
    InvalidMagic,
    /// The separator for a PSBT must be `0xff`.
    // TODO: Consider adding the invalid separator byte.
    InvalidSeparator,
    /// Signals that there are no more key-value pairs in a key-value map.
    NoMorePairs,
    /// Unsigned transaction error.
    UnsignedTx(UnsignedTxError),
    /// Error deserializaing a consensus-encoded structure.
    ConsensusDecode(encode::Error),
    /// Error decoding the global map.
    DecodeGlobal(global::DecodeError),
    /// Error decoding an input map.
    DecodeInput(input::DecodeError),
    /// Error decoding an output map.
    DecodeOutput(output::DecodeError),
}

impl fmt::Display for DeserializeError {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result { todo!() }
}

#[cfg(feature = "std")]
impl std::error::Error for DeserializeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { todo!() }
}

impl From<UnsignedTxError> for DeserializeError {
    fn from(e: UnsignedTxError) -> Self { Self::UnsignedTx(e) }
}

impl From<encode::Error> for DeserializeError {
    fn from(e: encode::Error) -> Self { Self::ConsensusDecode(e) }
}

impl From<global::DecodeError> for DeserializeError {
    fn from(e: global::DecodeError) -> Self { Self::DecodeGlobal(e) }
}

impl From<input::DecodeError> for DeserializeError {
    fn from(e: input::DecodeError) -> Self { Self::DecodeInput(e) }
}

impl From<output::DecodeError> for DeserializeError {
    fn from(e: output::DecodeError) -> Self { Self::DecodeOutput(e) }
}

/// Enum for marking psbt hash error.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum PsbtHash {
    Ripemd,
    Sha256,
    Hash160,
    Hash256,
}
