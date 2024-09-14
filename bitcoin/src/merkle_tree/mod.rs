// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Merkle tree functions.
//!
//! # Examples
//!
//! ```
//! # use bitcoin::Txid;
//! # use bitcoin::merkle_tree::{MerkleNode as _, TxMerkleNode};
//! # let tx1 = Txid::from_byte_array([0xAA; 32]);  // Arbitrary dummy hash values.
//! # let tx2 = Txid::from_byte_array([0xFF; 32]);
//! let tx_hashes = [tx1, tx2]; // All the hashes we wish to merkelize.
//! let root = TxMerkleNode::calculate_root(tx_hashes.into_iter());
//! assert!(root.is_some());
//! ```

mod block;

use hashes::{sha256d, HashEngine as _};

use crate::internal_macros::impl_hashencode;
use crate::prelude::Vec;
use crate::transaction::TxIdentifier;
use crate::{Txid, Wtxid};

#[rustfmt::skip]
#[doc(inline)]
pub use self::block::{MerkleBlock, MerkleBlockError, PartialMerkleTree};

hashes::hash_newtype! {
    /// A hash of the Merkle tree branch or root for transactions.
    pub struct TxMerkleNode(sha256d::Hash);
    /// A hash corresponding to the Merkle tree root for witness data.
    pub struct WitnessMerkleNode(sha256d::Hash);
}
impl_hashencode!(TxMerkleNode);
impl_hashencode!(WitnessMerkleNode);

/// A node in a Merkle tree of transactions or witness data within a block.
///
/// This trait is used to compute the transaction Merkle root contained in
/// a block header. This is a particularly weird algorithm -- it interprets
/// the list of transactions as a balanced binary tree, duplicating branches
/// as needed to fill out the tree to a power of two size.
///
/// Other Merkle trees in Bitcoin, such as those used in Taproot commitments,
/// do not use this algorithm and cannot use this trait.
pub trait MerkleNode: Copy {
    /// The hash (TXID or WTXID) of a transaciton in the tree.
    type Leaf: TxIdentifier;

    /// Convert a hash to a leaf node of the tree.
    fn from_leaf(leaf: Self::Leaf) -> Self;
    /// Combine two nodes to get a single node. The final node of a tree is called the "root".
    fn combine(&self, other: &Self) -> Self;

    /// Given an iterator of leaves, compute the Merkle root.
    ///
    /// Returns `None` iff the iterator was empty.
    fn calculate_root<I: Iterator<Item = Self::Leaf>>(iter: I) -> Option<Self> {
        let mut stack = Vec::<(usize, Self)>::with_capacity(32);
        // Start with a standard Merkle tree root computation...
        for (mut n, leaf) in iter.enumerate() {
            stack.push((0, Self::from_leaf(leaf)));

            while n & 1 == 1 {
                let right = stack.pop().unwrap();
                let left = stack.pop().unwrap();
                debug_assert_eq!(left.0, right.0);
                stack.push((left.0 + 1, left.1.combine(&right.1)));
                n >>= 1;
            }
        }
        // ...then, deal with incomplete trees. Bitcoin does a weird thing in
        // which it doubles-up nodes of the tree to fill out the tree, rather
        // than treating incomplete branches specially. This, along with its
        // conflation of leaves with leaf hashes, makes its Merkle tree
        // construction theoretically (though probably not practically)
        // vulnerable to collisions. This is consensus logic so we just have
        // to accept it.
        while stack.len() > 1 {
            let mut right = stack.pop().unwrap();
            let left = stack.pop().unwrap();
            while right.0 != left.0 {
                assert!(right.0 < left.0);
                right = (right.0 + 1, right.1.combine(&right.1)); // combine with self
            }
            stack.push((left.0 + 1, left.1.combine(&right.1)));
        }

        stack.pop().map(|(_, h)| h)
    }
}

// These two impl blocks are identical. FIXME once we have nailed down
// our hash traits, it should be possible to put bounds on `MerkleNode`
// and `MerkleNode::Leaf` which are sufficient to turn both methods into
// provided methods in the trait definition.
impl MerkleNode for TxMerkleNode {
    type Leaf = Txid;
    fn from_leaf(leaf: Self::Leaf) -> Self { Self::from_byte_array(leaf.to_byte_array()) }

    fn combine(&self, other: &Self) -> Self {
        let mut encoder = sha256d::Hash::engine();
        encoder.input(self.as_byte_array());
        encoder.input(other.as_byte_array());
        Self(sha256d::Hash::from_engine(encoder))
    }
}
impl MerkleNode for WitnessMerkleNode {
    type Leaf = Wtxid;
    fn from_leaf(leaf: Self::Leaf) -> Self { Self::from_byte_array(leaf.to_byte_array()) }

    fn combine(&self, other: &Self) -> Self {
        let mut encoder = sha256d::Hash::engine();
        encoder.input(self.as_byte_array());
        encoder.input(other.as_byte_array());
        Self(sha256d::Hash::from_engine(encoder))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Block;
    use crate::consensus::encode::deserialize;

    #[test]
    fn static_vector() {
        // testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
        let segwit_block = include_bytes!("../../tests/data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw");
        let block: Block = deserialize(&segwit_block[..]).expect("failed to deserialize block");

        assert!(block.check_merkle_root());

        // Same as `block.check_merkle_root` but do it explicitly.
        let hashes_iter = block.txdata.iter().map(|obj| obj.compute_txid());
        let from_iter = TxMerkleNode::calculate_root(hashes_iter.clone());
        assert_eq!(from_iter, Some(block.header.merkle_root));
    }
}
