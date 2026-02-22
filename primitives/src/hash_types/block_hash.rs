// SPDX-License-Identifier: CC0-1.0

//! The `BlockHash` type.

use core::convert::Infallible;
use core::fmt;
#[cfg(feature = "hex")]
use core::str;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::Encodable;
use hashes::sha256d;
use internals::write_err;

/// A bitcoin block hash.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockHash(sha256d::Hash);

super::impl_debug!(BlockHash);

impl BlockHash {
    /// Dummy hash used as the previous blockhash of the genesis block.
    pub const GENESIS_PREVIOUS_BLOCK_HASH: Self = Self::from_byte_array([0; 32]);
}

// The new hash wrapper type.
type HashType = BlockHash;
// The inner hash type from `hashes`.
type Inner = sha256d::Hash;

include!("./generic.rs");

encoding::encoder_newtype_exact! {
    /// The encoder for the [`BlockHash`] type.
    pub struct BlockHashEncoder<'e>(encoding::ArrayRefEncoder<'e, 32>);
}

impl Encodable for BlockHash {
    type Encoder<'e> = BlockHashEncoder<'e>;
    fn encoder(&self) -> Self::Encoder<'_> {
        BlockHashEncoder::new(encoding::ArrayRefEncoder::without_length_prefix(
            self.as_byte_array(),
        ))
    }
}

/// The decoder for the [`BlockHash`] type.
pub struct BlockHashDecoder(encoding::ArrayDecoder<32>);

impl BlockHashDecoder {
    /// Constructs a new [`BlockHash`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
}

impl Default for BlockHashDecoder {
    fn default() -> Self { Self::new() }
}

impl encoding::Decoder for BlockHashDecoder {
    type Output = BlockHash;
    type Error = BlockHashDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(BlockHashDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let a = self.0.end().map_err(BlockHashDecoderError)?;
        Ok(BlockHash::from_byte_array(a))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for BlockHash {
    type Decoder = BlockHashDecoder;
    fn decoder() -> Self::Decoder { BlockHashDecoder(encoding::ArrayDecoder::<32>::new()) }
}

/// An error consensus decoding an `BlockHash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHashDecoderError(encoding::UnexpectedEofError);

impl From<Infallible> for BlockHashDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for BlockHashDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "sequence decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BlockHashDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[cfg(test)]
mod tests {
    use encoding::Decoder as _;

    use super::*;

    #[test]
    fn decoder_full_read_limit() {
        assert_eq!(BlockHashDecoder::default().read_limit(), 32);
        assert_eq!(<BlockHash as encoding::Decodable>::decoder().read_limit(), 32);
    }

    #[test]
    #[cfg(feature = "std")]
    fn decoder_error_display() {
        use std::error::Error as _;
        use std::string::ToString as _;

        let mut decoder = BlockHashDecoder::new();
        let mut bytes = &[0u8; 31][..];

        assert!(decoder.push_bytes(&mut bytes).unwrap());

        let err = decoder.end().unwrap_err();

        assert!(!err.to_string().is_empty());
        assert!(err.source().is_some());
    }
}
