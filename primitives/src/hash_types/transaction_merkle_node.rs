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

use crate::merkle_tree::MerkleNode;
use crate::Txid;

/// A hash of the Merkle tree branch or root for transactions.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxMerkleNode(sha256d::Hash);

// The new hash wrapper type.
type HashType = TxMerkleNode;
// The inner hash type from `hashes`.
type Inner = sha256d::Hash;

include!("./generic.rs");

impl TxMerkleNode {
    /// Convert a [`Txid`] hash to a leaf node of the tree.
    pub fn from_leaf(leaf: Txid) -> Self { MerkleNode::from_leaf(leaf) }

    /// Combine two nodes to get a single node. The final node of a tree is called the "root".
    #[must_use]
    pub fn combine(&self, other: &Self) -> Self { MerkleNode::combine(self, other) }

    /// Given an iterator of leaves, compute the Merkle root.
    ///
    /// Returns `None` if the iterator was empty, or if the transaction list contains
    /// consecutive duplicates which would trigger CVE 2012-2459. Blocks with duplicate
    /// transactions will always be invalid, so there is no harm in us refusing to
    /// compute their merkle roots.
    ///
    /// Unless you are certain your transaction list is nonempty and has no duplicates,
    /// you should not unwrap the `Option` returned by this method!
    pub fn calculate_root<I: Iterator<Item = Txid>>(iter: I) -> Option<Self> {
        MerkleNode::calculate_root(iter)
    }
}

encoding::encoder_newtype_exact! {
    /// The encoder for the [`TxMerkleNode`] type.
    pub struct TxMerkleNodeEncoder<'e>(encoding::ArrayEncoder<32>);
}

impl encoding::Encodable for TxMerkleNode {
    type Encoder<'e> = TxMerkleNodeEncoder<'e>;
    fn encoder(&self) -> Self::Encoder<'_> {
        TxMerkleNodeEncoder::new(encoding::ArrayEncoder::without_length_prefix(
            self.to_byte_array(),
        ))
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

#[cfg(test)]
mod tests {
    use encoding::Decoder as _;

    use super::*;

    #[test]
    fn decoder_full_read_limit() {
        assert_eq!(TxMerkleNodeDecoder::default().read_limit(), 32);
        assert_eq!(<TxMerkleNode as encoding::Decodable>::decoder().read_limit(), 32);
    }

    #[test]
    #[cfg(feature = "std")]
    fn decoder_error_display() {
        use std::error::Error as _;
        use std::string::ToString as _;

        const NODE_LEN: usize = 32;

        let mut decoder = TxMerkleNodeDecoder::new();
        let mut bytes = &[0u8; NODE_LEN - 1][..];
        assert!(decoder.push_bytes(&mut bytes).unwrap());

        let err = decoder.end().unwrap_err();
        assert!(!err.to_string().is_empty());
        assert!(err.source().is_some());
    }
}
