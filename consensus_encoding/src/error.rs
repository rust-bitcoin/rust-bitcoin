// SPDX-License-Identifier: CC0-1.0

//! Error types for the whole crate.
//!
//! All error types are publicly available at the crate root.
// We separate them into a module so the HTML docs are less cluttered.

use core::convert::Infallible;
use core::fmt;

use internals::write_err;

#[cfg(doc)]
use crate::{ArrayDecoder, Decoder2, Decoder3, Decoder4, Decoder6};
#[cfg(feature = "alloc")]
#[cfg(doc)]
use crate::{ByteVecDecoder, VecDecoder};

/// An error that can occur when reading and decoding from a buffered reader.
#[cfg(feature = "std")]
#[derive(Debug)]
pub enum ReadError<D> {
    /// An I/O error occurred while reading from the reader.
    Io(std::io::Error),
    /// The decoder encountered an error while parsing the data.
    Decode(D),
}

#[cfg(feature = "std")]
impl<D: core::fmt::Display> core::fmt::Display for ReadError<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Decode(e) => write!(f, "decode error: {}", e),
        }
    }
}

#[cfg(feature = "std")]
impl<D> std::error::Error for ReadError<D>
where
    D: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Decode(e) => Some(e),
        }
    }
}

#[cfg(feature = "std")]
impl<D> From<std::io::Error> for ReadError<D> {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}

/// An error that can occur when decoding from a byte slice.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DecodeError<Err> {
    /// Provided slice failed to correctly decode as a type.
    Parse(Err),
    /// Bytes remained unconsumed after completing decoding.
    Unconsumed(UnconsumedError),
}

impl<Err> From<Infallible> for DecodeError<Err> {
    fn from(never: Infallible) -> Self { match never {} }
}

impl<Err> fmt::Display for DecodeError<Err>
where
    Err: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Parse(ref e) => write_err!(f, "error parsing encoded object"; e),
            Self::Unconsumed(ref e) => write_err!(f, "unconsumed"; e),
        }
    }
}

#[cfg(feature = "std")]
impl<Err> std::error::Error for DecodeError<Err>
where
    Err: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(ref e) => Some(e),
            Self::Unconsumed(ref e) => Some(e),
        }
    }
}

/// Bytes remained unconsumed after completing decoding.
// This is just to give us the ability to add details in a
// non-breaking way if we want to at some stage.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnconsumedError();

impl From<Infallible> for UnconsumedError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for UnconsumedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "data not consumed entirely when decoding")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnconsumedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// An error consensus decoding a compact size encoded integer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactSizeDecoderError(pub(crate) CompactSizeDecoderErrorInner);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompactSizeDecoderErrorInner {
    /// Returned when the decoder reaches end of stream (EOF).
    UnexpectedEof {
        /// How many bytes were required.
        required: usize,
        /// How many bytes were received.
        received: usize,
    },
    /// Returned when the encoding is not minimal
    NonMinimal {
        /// The encoded value.
        value: u64,
    },
    /// Returned when the encoded value exceeds the decoder's limit.
    ValueExceedsLimit(LengthPrefixExceedsMaxError),
}

impl From<Infallible> for CompactSizeDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl core::fmt::Display for CompactSizeDecoderError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use CompactSizeDecoderErrorInner as E;

        match self.0 {
            E::UnexpectedEof { required: 1, received: 0 } => {
                write!(f, "required at least one byte but the input is empty")
            }
            E::UnexpectedEof { required, received: 0 } => {
                write!(f, "required at least {} bytes but the input is empty", required)
            }
            E::UnexpectedEof { required, received } => write!(
                f,
                "required at least {} bytes but only {} bytes were received",
                required, received
            ),
            E::NonMinimal { value } => write!(f, "the value {} was not encoded minimally", value),
            E::ValueExceedsLimit(ref e) => write_err!(f, "value exceeds limit"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CompactSizeDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use CompactSizeDecoderErrorInner as E;

        match self {
            Self(E::ValueExceedsLimit(ref e)) => Some(e),
            _ => None,
        }
    }
}

/// The error returned when a compact size value exceeds a configured limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LengthPrefixExceedsMaxError {
    /// The limit that was exceeded.
    pub(crate) limit: usize,
    /// The value that exceeded the limit.
    pub(crate) value: u64,
}

impl From<Infallible> for LengthPrefixExceedsMaxError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl core::fmt::Display for LengthPrefixExceedsMaxError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "decoded length {} exceeds maximum allowed {}", self.value, self.limit)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LengthPrefixExceedsMaxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// The error returned by the [`ByteVecDecoder`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteVecDecoderError(pub(crate) ByteVecDecoderErrorInner);

#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ByteVecDecoderErrorInner {
    /// Error decoding the byte vector length prefix.
    LengthPrefixDecode(CompactSizeDecoderError),
    /// Not enough bytes given to decoder.
    UnexpectedEof(UnexpectedEofError),
}

#[cfg(feature = "alloc")]
impl From<Infallible> for ByteVecDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
impl fmt::Display for ByteVecDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ByteVecDecoderErrorInner as E;

        match self.0 {
            E::LengthPrefixDecode(ref e) => write_err!(f, "byte vec decoder error"; e),
            E::UnexpectedEof(ref e) => write_err!(f, "byte vec decoder error"; e),
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "std")]
impl std::error::Error for ByteVecDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ByteVecDecoderErrorInner as E;

        match self.0 {
            E::LengthPrefixDecode(ref e) => Some(e),
            E::UnexpectedEof(ref e) => Some(e),
        }
    }
}

/// The error returned by the [`VecDecoder`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VecDecoderError<Err>(pub(crate) VecDecoderErrorInner<Err>);

#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VecDecoderErrorInner<Err> {
    /// Error decoding the vector length prefix.
    LengthPrefixDecode(CompactSizeDecoderError),
    /// Error while decoding an item.
    Item(Err),
    /// Not enough bytes given to decoder.
    UnexpectedEof(UnexpectedEofError),
}

#[cfg(feature = "alloc")]
impl<Err> From<Infallible> for VecDecoderError<Err> {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
impl<Err> fmt::Display for VecDecoderError<Err>
where
    Err: fmt::Display + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use VecDecoderErrorInner as E;

        match self.0 {
            E::LengthPrefixDecode(ref e) => write_err!(f, "vec decoder error"; e),
            E::Item(ref e) => write_err!(f, "vec decoder error"; e),
            E::UnexpectedEof(ref e) => write_err!(f, "vec decoder error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl<Err> std::error::Error for VecDecoderError<Err>
where
    Err: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use VecDecoderErrorInner as E;

        match self.0 {
            E::LengthPrefixDecode(ref e) => Some(e),
            E::Item(ref e) => Some(e),
            E::UnexpectedEof(ref e) => Some(e),
        }
    }
}

/// Not enough bytes given to decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnexpectedEofError {
    /// Number of bytes missing to complete decoder.
    pub(crate) missing: usize,
}

impl From<Infallible> for UnexpectedEofError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for UnexpectedEofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not enough bytes for decoder, {} more bytes required", self.missing)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnexpectedEofError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Helper macro to define an error type for a `DecoderN`.
macro_rules! define_decoder_n_error {
    (
        $(#[$attr:meta])*
        $name:ident;
        $(
            $(#[$err_attr:meta])*
            ($err_wrap:ident, $err_type:ident, $err_msg:literal),
        )*
    ) => {
        $(#[$attr])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $name<$($err_type,)*> {
            $(
                $(#[$err_attr])*
                $err_wrap($err_type),
            )*
        }

        impl<$($err_type,)*> fmt::Display for $name<$($err_type,)*>
        where
            $($err_type: fmt::Display,)*
        {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match self {
                    $(Self::$err_wrap(ref e) => write_err!(f, $err_msg; e),)*
                }
            }
        }

        #[cfg(feature = "std")]
        impl<$($err_type,)*> std::error::Error for $name<$($err_type,)*>
        where
            $($err_type: std::error::Error + 'static,)*
        {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    $(Self::$err_wrap(ref e) => Some(e),)*
                }
            }
        }
    };
}

define_decoder_n_error! {
    /// Error type for [`Decoder2`].
    Decoder2Error;
    /// Error from the first decoder.
    (First, A, "first decoder error."),
    /// Error from the second decoder.
    (Second, B, "second decoder error."),
}

define_decoder_n_error! {
    /// Error type for [`Decoder3`].
    Decoder3Error;
    /// Error from the first decoder.
    (First, A, "first decoder error."),
    /// Error from the second decoder.
    (Second, B, "second decoder error."),
    /// Error from the third decoder.
    (Third, C, "third decoder error."),
}

define_decoder_n_error! {
    /// Error type for [`Decoder4`].
    Decoder4Error;
    /// Error from the first decoder.
    (First, A, "first decoder error."),
    /// Error from the second decoder.
    (Second, B, "second decoder error."),
    /// Error from the third decoder.
    (Third, C, "third decoder error."),
    /// Error from the fourth decoder.
    (Fourth, D, "fourth decoder error."),
}

define_decoder_n_error! {
    /// Error type for [`Decoder6`].
    Decoder6Error;
    /// Error from the first decoder.
    (First, A, "first decoder error."),
    /// Error from the second decoder.
    (Second, B, "second decoder error."),
    /// Error from the third decoder.
    (Third, C, "third decoder error."),
    /// Error from the fourth decoder.
    (Fourth, D, "fourth decoder error."),
    /// Error from the fifth decoder.
    (Fifth, E, "fifth decoder error."),
    /// Error from the sixth decoder.
    (Sixth, F, "sixth decoder error."),
}
