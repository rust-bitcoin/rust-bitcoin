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

impl BlockHash {
    /// Dummy hash used as the previous blockhash of the genesis block.
    pub const GENESIS_PREVIOUS_BLOCK_HASH: Self = Self::from_byte_array([0; 32]);
}

// The new hash wrapper type.
type HashType = BlockHash;
// The inner hash type from `hashes`.
type Inner = sha256d::Hash;

include!("./generic.rs");

encoding::encoder_newtype! {
    /// The encoder for the [`BlockHash`] type.
    pub struct BlockHashEncoder(encoding::ArrayEncoder<32>);
}

impl Encodable for BlockHash {
    type Encoder<'e> = BlockHashEncoder;
    fn encoder(&self) -> Self::Encoder<'_> {
        BlockHashEncoder(encoding::ArrayEncoder::without_length_prefix(self.to_byte_array()))
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
        Ok(self.0.push_bytes(bytes)?)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let a = self.0.end()?;
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

impl From<encoding::UnexpectedEofError> for BlockHashDecoderError {
    fn from(e: encoding::UnexpectedEofError) -> Self { Self(e) }
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
