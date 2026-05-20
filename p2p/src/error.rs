// SPDX-License-Identifier: CC0-1.0

//! Error types for the p2p crate root.

use alloc::string::String;
use core::convert::Infallible;
use core::fmt;

use internals::write_err;
use network::Network;

use crate::Magic;

/// An error consensus decoding a [`ProtocolVersion`].
///
/// [`ProtocolVersion`]: crate::ProtocolVersion
#[derive(Debug, PartialEq, Eq)]
pub struct ProtocolVersionDecoderError(
    pub(super) <encoding::ArrayDecoder<4> as encoding::Decoder>::Error,
);

impl From<Infallible> for ProtocolVersionDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for ProtocolVersionDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "protocolversion error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProtocolVersionDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// An error consensus decoding a [`ServiceFlags`].
///
/// [`ServiceFlags`]: crate::ServiceFlags
#[derive(Debug, PartialEq, Eq)]
pub struct ServiceFlagsDecoderError(
    pub(super) <encoding::ArrayDecoder<8> as encoding::Decoder>::Error,
);

impl From<Infallible> for ServiceFlagsDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for ServiceFlagsDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "serviceflags error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ServiceFlagsDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// Errors occuring when decoding a network [`Magic`].
#[derive(Debug, PartialEq, Eq)]
pub struct MagicDecoderError(pub(super) <super::MagicInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for MagicDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for MagicDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "magic error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MagicDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// An error in parsing magic bytes.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseMagicError {
    /// The error that occurred when parsing the string.
    pub(super) error: hex::DecodeFixedLengthBytesError,
    /// The byte string that failed to parse.
    pub(super) magic: String,
}

impl fmt::Display for ParseMagicError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "failed to parse {} as network magic", self.magic)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseMagicError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.error) }
}

/// Error in creating a Network from Magic bytes.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownMagicError(pub(super) Magic);

impl fmt::Display for UnknownMagicError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unknown network magic {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownMagicError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Error in creating a Magic from a Network.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownNetworkError(pub(super) Network);

impl fmt::Display for UnknownNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "unknown network {}", self.0) }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownNetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}
