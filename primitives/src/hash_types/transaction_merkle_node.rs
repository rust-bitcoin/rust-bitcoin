// SPDX-License-Identifier: CC0-1.0

//! The `TxMerkleNode` type.

use core::convert::Infallible;
use core::fmt;
#[cfg(feature = "hex")]
use core::str;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::sha256d;
use internals::write_err;

/// A hash of the Merkle tree branch or root for transactions.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxMerkleNode(sha256d::Hash);

// The new hash wrapper type.
type HashType = TxMerkleNode;
// The inner hash type from `hashes`.
type Inner = sha256d::Hash;

include!("./generic.rs");

encoding::encoder_newtype! {
    /// The encoder for the [`TxMerkleNode`] type.
    pub struct TxMerkleNodeEncoder(encoding::ArrayEncoder<32>);
}

impl encoding::Encodable for TxMerkleNode {
    type Encoder<'e> = TxMerkleNodeEncoder;
    fn encoder(&self) -> Self::Encoder<'_> {
        TxMerkleNodeEncoder(encoding::ArrayEncoder::without_length_prefix(self.to_byte_array()))
    }
}

/// The decoder for the [`TxMerkleNode`] type.
pub struct TxMerkleNodeDecoder(encoding::ArrayDecoder<32>);

impl TxMerkleNodeDecoder {
    /// Constructs a new [`TxMerkleNode`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
}

impl Default for TxMerkleNodeDecoder {
    fn default() -> Self { Self::new() }
}

impl encoding::Decoder for TxMerkleNodeDecoder {
    type Output = TxMerkleNode;
    type Error = TxMerkleNodeDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        Ok(self.0.push_bytes(bytes)?)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let a = self.0.end()?;
        Ok(TxMerkleNode::from_byte_array(a))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for TxMerkleNode {
    type Decoder = TxMerkleNodeDecoder;
    fn decoder() -> Self::Decoder { TxMerkleNodeDecoder(encoding::ArrayDecoder::<32>::new()) }
}

/// An error consensus decoding an `TxMerkleNode`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxMerkleNodeDecoderError(encoding::UnexpectedEofError);

impl From<Infallible> for TxMerkleNodeDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl From<encoding::UnexpectedEofError> for TxMerkleNodeDecoderError {
    fn from(e: encoding::UnexpectedEofError) -> Self { Self(e) }
}

impl fmt::Display for TxMerkleNodeDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "sequence decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TxMerkleNodeDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}
