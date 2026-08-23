// SPDX-License-Identifier: CC0-1.0

//! BIP-0157 compact-filter hash and filter-header types.

use encoding::{ArrayDecoder, ArrayRefEncoder};
use hashes::{sha256d, HashEngine};

pub use self::error::{FilterHashDecoderError, FilterHeaderDecoderError};

hashes::hash_newtype! {
    /// The BIP-0157 double-SHA256 hash of a serialized compact filter.
    pub struct FilterHash(sha256d::Hash);
    /// A BIP-0157 filter header committing to one filter and the preceding filter-header chain.
    pub struct FilterHeader(sha256d::Hash);
}

#[cfg(feature = "hex")]
hashes::impl_hex_for_newtype!(FilterHash, FilterHeader);
#[cfg(not(feature = "hex"))]
hashes::impl_debug_only_for_newtype!(FilterHash, FilterHeader);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(FilterHash, FilterHeader);

impl FilterHash {
    /// Computes the filter header from this hash and the preceding filter header.
    pub fn filter_header(&self, previous: FilterHeader) -> FilterHeader {
        let mut engine = sha256d::Hash::engine();
        engine.input(self.as_ref());
        engine.input(previous.as_ref());
        FilterHeader(sha256d::Hash::from_engine(engine))
    }
}

encoding::encoder_newtype_exact! {
    /// Encoder for the [`FilterHash`] type.
    #[derive(Debug, Clone)]
    pub struct FilterHashEncoder<'e>(ArrayRefEncoder<'e, 32>);
}

impl encoding::Encode for FilterHash {
    type Encoder<'e> = FilterHashEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        FilterHashEncoder::new(ArrayRefEncoder::without_length_prefix(self.as_byte_array()))
    }
}

crate::decoder_newtype! {
    /// Decoder for the [`FilterHash`] type.
    #[derive(Debug, Clone)]
    pub struct FilterHashDecoder(ArrayDecoder<32>);

    /// Constructs a new [`FilterHash`] decoder.
    pub const fn new() -> Self {Self(ArrayDecoder::new())}

    fn end(result: Result<[u8;32], encoding::UnexpectedEofError>) -> Result<FilterHash, FilterHashDecoderError> {
        let bytes = result.map_err(FilterHashDecoderError)?;
        Ok(FilterHash::from_byte_array(bytes))
    }
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

crate::decoder_newtype! {
    /// Decoder for the [`FilterHeader`] type.
    #[derive(Debug, Clone)]
    pub struct FilterHeaderDecoder(ArrayDecoder<32>);

    /// Constructs a new [`FilterHash`] decoder.
    pub const fn new() -> Self {Self(ArrayDecoder::new())}

    fn end(result: Result<[u8; 32], encoding::UnexpectedEofError>) -> Result<FilterHeader, FilterHeaderDecoderError> {
        let bytes = result.map_err(FilterHeaderDecoderError)?;
        Ok(FilterHeader::from_byte_array(bytes))
    }
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
