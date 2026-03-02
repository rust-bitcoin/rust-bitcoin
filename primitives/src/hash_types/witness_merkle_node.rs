// SPDX-License-Identifier: CC0-1.0

//! The `WitnessMerkleNode` type.

use core::convert::Infallible;
use core::fmt;
use core::marker::PhantomData;
#[cfg(feature = "hex")]
use core::str;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::sha256d;
use internals::write_err;

use crate::merkle_tree::MerkleNode;
use crate::Wtxid;

/// A hash corresponding to the Merkle tree root for witness data.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WitnessMerkleNode(sha256d::Hash);

super::impl_debug!(WitnessMerkleNode);

// The new hash wrapper type.
type HashType = WitnessMerkleNode;
// The inner hash type from `hashes`.
type Inner = sha256d::Hash;

include!("./generic.rs");

impl WitnessMerkleNode {
    /// Convert a [`Wtxid`] hash to a leaf node of the tree.
    pub fn from_leaf(leaf: Wtxid) -> Self { MerkleNode::from_leaf(leaf) }

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
    pub fn calculate_root<I: Iterator<Item = Wtxid>>(iter: I) -> Option<Self> {
        MerkleNode::calculate_root(iter)
    }
}

encoding::encoder_newtype_exact! {
    /// The encoder for the [`WitnessMerkleNode`] type.
    pub struct WitnessMerkleNodeEncoder<'e>(encoding::ArrayEncoder<32>);
}

impl encoding::Encodable for WitnessMerkleNode {
    type Encoder<'e> = WitnessMerkleNodeEncoder<'e>;
    fn encoder(&self) -> Self::Encoder<'_> {
        WitnessMerkleNodeEncoder(
            encoding::ArrayEncoder::without_length_prefix(self.to_byte_array()),
            PhantomData,
        )
    }
}

/// The decoder for the [`WitnessMerkleNode`] type.
pub struct WitnessMerkleNodeDecoder(encoding::ArrayDecoder<32>);

impl WitnessMerkleNodeDecoder {
    /// Constructs a new [`WitnessMerkleNode`] decoder.
    pub fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
}

impl Default for WitnessMerkleNodeDecoder {
    fn default() -> Self { Self::new() }
}

impl encoding::Decoder for WitnessMerkleNodeDecoder {
    type Output = WitnessMerkleNode;
    type Error = WitnessMerkleNodeDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(WitnessMerkleNodeDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let a = self.0.end().map_err(WitnessMerkleNodeDecoderError)?;
        Ok(WitnessMerkleNode::from_byte_array(a))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for WitnessMerkleNode {
    type Decoder = WitnessMerkleNodeDecoder;
    fn decoder() -> Self::Decoder { WitnessMerkleNodeDecoder(encoding::ArrayDecoder::<32>::new()) }
}

/// An error consensus decoding an `WitnessMerkleNode`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessMerkleNodeDecoderError(encoding::UnexpectedEofError);

impl From<Infallible> for WitnessMerkleNodeDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for WitnessMerkleNodeDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "sequence decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WitnessMerkleNodeDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[cfg(test)]
mod tests {
    use encoding::Decoder as _;

    use super::*;

    #[test]
    fn combine_delegates_to_merkle_node_trait() {
        let a = WitnessMerkleNode::from_leaf(Wtxid::from_byte_array([1; 32]));
        let b = WitnessMerkleNode::from_leaf(Wtxid::from_byte_array([2; 32]));

        assert_eq!(a.combine(&b), MerkleNode::combine(&a, &b));
    }

    #[test]
    fn decoder_full_read_limit() {
        assert_eq!(WitnessMerkleNodeDecoder::new().read_limit(), 32);
        // These two are the same decoder but we want 100% coverage.
        assert_eq!(WitnessMerkleNodeDecoder::default().read_limit(), 32);
        assert_eq!(<WitnessMerkleNode as encoding::Decodable>::decoder().read_limit(), 32);
    }

    #[test]
    fn decoder_successfully_decodes() {
        let expected = WitnessMerkleNode::from_byte_array([0x55; 32]);
        let mut decoder = WitnessMerkleNodeDecoder::new();
        let mut bytes = &[0x55u8; 32][..];

        let _done = decoder.push_bytes(&mut bytes).unwrap();

        assert_eq!(decoder.end().unwrap(), expected);
    }

    #[test]
    #[cfg(feature = "std")]
    fn decoder_error_display() {
        use std::error::Error as _;
        use std::string::ToString as _;

        let mut decoder = WitnessMerkleNodeDecoder::new();
        let mut bytes = &[0u8; 31][..];

        assert!(decoder.push_bytes(&mut bytes).unwrap());

        let err = decoder.end().unwrap_err();
        assert!(!err.to_string().is_empty());
        assert!(err.source().is_some());
    }
}
