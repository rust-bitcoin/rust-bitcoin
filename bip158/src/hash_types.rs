// SPDX-License-Identifier: CC0-1.0

//! Compact-filter hash types.

use encoding::{ArrayDecoder, ArrayRefEncoder};
use hashes::{sha256d, HashEngine};

pub use self::error::{FilterHashDecoderError, FilterHeaderDecoderError};

hashes::hash_newtype! {
    /// The double-SHA256 hash of a serialized compact filter.
    pub struct FilterHash(pub sha256d::Hash);
    /// A BIP-0157 filter header committing to one filter and all preceding filters.
    pub struct FilterHeader(pub sha256d::Hash);
}

hashes::impl_hex_for_newtype!(FilterHash, FilterHeader);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(FilterHash, FilterHeader);

impl FilterHash {
    /// Computes a filter header from this hash and the preceding filter header.
    pub fn filter_header(&self, previous: FilterHeader) -> FilterHeader {
        let mut engine = sha256d::Hash::engine();
        engine.input(self.as_ref());
        engine.input(previous.as_ref());
        FilterHeader(sha256d::Hash::from_engine(engine))
    }
}

encoding::encoder_newtype_exact! {
    /// Encoder for the [`FilterHash`] type.
    pub struct FilterHashEncoder<'e>(ArrayRefEncoder<'e, 32>);
}

impl encoding::Encode for FilterHash {
    type Encoder<'e> = FilterHashEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        FilterHashEncoder::new(ArrayRefEncoder::without_length_prefix(self.as_byte_array()))
    }
}

/// Decoder for the [`FilterHash`] type.
#[derive(Debug, Clone, Default)]
pub struct FilterHashDecoder(ArrayDecoder<32>);

impl encoding::Decoder for FilterHashDecoder {
    type Output = FilterHash;
    type Error = FilterHashDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<encoding::DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes).map_err(FilterHashDecoderError)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        self.0.end().map(FilterHash::from_byte_array).map_err(FilterHashDecoderError)
    }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decode for FilterHash {
    type Decoder = FilterHashDecoder;
}

encoding::encoder_newtype_exact! {
    /// Encoder for the [`FilterHeader`] type.
    #[derive(Debug, Clone)]
    pub struct FilterHeaderEncoder<'e>(ArrayRefEncoder<'e, 32>);
}

impl encoding::Encode for FilterHeader {
    type Encoder<'e> = FilterHeaderEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        FilterHeaderEncoder::new(ArrayRefEncoder::without_length_prefix(self.as_byte_array()))
    }
}

/// Decoder for the [`FilterHeader`] type.
#[derive(Debug, Clone, Default)]
pub struct FilterHeaderDecoder(ArrayDecoder<32>);

impl encoding::Decoder for FilterHeaderDecoder {
    type Output = FilterHeader;
    type Error = FilterHeaderDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<encoding::DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes).map_err(FilterHeaderDecoderError)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        self.0.end().map(FilterHeader::from_byte_array).map_err(FilterHeaderDecoderError)
    }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decode for FilterHeader {
    type Decoder = FilterHeaderDecoder;
}

pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    use encoding::UnexpectedEofError;
    use internals::write_err;

    /// An error consensus decoding a [`FilterHash`](super::FilterHash).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FilterHashDecoderError(pub(crate) UnexpectedEofError);

    impl From<Infallible> for FilterHashDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for FilterHashDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_err!(f, "filter hash decoder error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for FilterHashDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }

    /// An error consensus decoding a [`FilterHeader`](super::FilterHeader).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FilterHeaderDecoderError(pub(crate) UnexpectedEofError);

    impl From<Infallible> for FilterHeaderDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for FilterHeaderDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_err!(f, "filter header decoder error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for FilterHeaderDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }
}
