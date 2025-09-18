// SPDX-License-Identifier: CC0-1.0

//! Consensus Decoding Traits

use core::convert::Infallible;
use core::fmt;

pub mod decoders;

/// A Bitcoin object which can be consensus-decoded using a push decoder.
///
/// To decode something, create a [`Self::Decoder`] and push byte slices
/// into it with [`Decoder::push_bytes`], then call [`Decoder::end`] to get the result.
pub trait Decodable {
    /// Associated decoder for the type.
    type Decoder: Decoder<Output = Self>;
    /// Constructs a "default decoder" for the type.
    fn decoder() -> Self::Decoder;
}

/// A push decoder for a consensus-decodable object.
pub trait Decoder: Sized {
    /// The type that this decoder produces when decoding is complete.
    type Output;
    /// The error type that this decoder can produce.
    type Error;

    /// Push bytes into the decoder, consuming as much as possible.
    ///
    /// The slice reference will be advanced to point to the unconsumed portion.
    /// Returns `Ok(true)` if more bytes are needed to complete decoding,
    /// `Ok(false)` if the decoder is ready to finalize with [`Self::end`],
    /// or `Err(error)` if parsing failed.
    ///
    /// # Errors
    ///
    /// Returns an error if the provided bytes are invalid or malformed according
    /// to the decoder's validation rules. Insufficient data (needing more
    /// bytes) is *not* an error for this method, the decoder will simply consume
    /// what it can and return `true` to indicate more data is needed.
    ///
    /// # Panics
    ///
    /// May panic if called after a previous call to [`Self::push_bytes`] errored.
    #[must_use = "must check result to avoid panics on subsequent calls"]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error>;

    /// Complete the decoding process and return the final result.
    ///
    /// This consumes the decoder and should be called when no more input
    /// data is available.
    ///
    /// # Errors
    ///
    /// Returns an error if the decoder has not received sufficient data to
    /// complete decoding, or if the accumulated data is invalid when considered
    /// as a complete object.
    ///
    /// # Panics
    ///
    /// May panic if called after a previous call to [`Self::push_bytes`] errored.
    #[must_use = "must check result to avoid panics on subsequent calls"]
    fn end(self) -> Result<Self::Output, Self::Error>;
}

/// Gets the compact size encoded value from `slice` and moves slice past the encoding.
///
/// Allows decoding both minimal and non-minimal encoding.
///
/// # Errors
///
/// Errors if `slice` is empty or encoding is invalid.
pub fn decode_compact_size(slice: &mut &[u8]) -> Result<u64, CompactSizeDecodeError> {
    use CompactSizeDecodeError as E;

    if slice.is_empty() {
        return Err(E(CompactSizeDecodeErrorInner { expected: 1, got: 0 }));
    }

    match slice[0] {
        0xFF => {
            const SIZE: usize = 9;
            if slice.len() < SIZE {
                return Err(E(CompactSizeDecodeErrorInner { expected: 9, got: slice.len() }));
            };

            let mut bytes = [0_u8; SIZE - 1];
            bytes.copy_from_slice(&slice[1..SIZE]);

            let v = u64::from_le_bytes(bytes);
            *slice = &slice[SIZE..];
            Ok(v)
        }
        0xFE => {
            const SIZE: usize = 5;
            if slice.len() < SIZE {
                return Err(E(CompactSizeDecodeErrorInner { expected: 5, got: slice.len() }));
            };

            let mut bytes = [0_u8; SIZE - 1];
            bytes.copy_from_slice(&slice[1..SIZE]);

            let v = u32::from_le_bytes(bytes);
            *slice = &slice[SIZE..];
            Ok(u64::from(v))
        }
        0xFD => {
            const SIZE: usize = 3;
            if slice.len() < SIZE {
                return Err(E(CompactSizeDecodeErrorInner { expected: 3, got: slice.len() }));
            };

            let mut bytes = [0_u8; SIZE - 1];
            bytes.copy_from_slice(&slice[1..SIZE]);

            let v = u16::from_le_bytes(bytes);
            *slice = &slice[SIZE..];
            Ok(u64::from(v))
        }
        n => {
            *slice = &slice[1..];
            Ok(u64::from(n))
        }
    }
}

/// Attempted to decode a compact size integer from an invalid length slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactSizeDecodeError(pub(crate) CompactSizeDecodeErrorInner);

impl From<Infallible> for CompactSizeDecodeError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl CompactSizeDecodeError {
    /// Returns the expected slice length.
    ///
    /// If `self.invalid_length()` returns 0 then this function will
    /// return 1 since that is the minimum required slice length.
    pub fn expected_length(&self) -> usize { self.0.expected }

    /// Returns the invalid slice length.
    pub fn invalid_length(&self) -> usize { self.0.got }
}

/// Attempted to create a hash from an invalid length slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompactSizeDecodeErrorInner {
    pub(crate) expected: usize,
    pub(crate) got: usize,
}

impl From<Infallible> for CompactSizeDecodeErrorInner {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for CompactSizeDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid slice length {} (expected {})", self.0.got, self.0.expected)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CompactSizeDecodeError {}
