// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Merkle tree functions.

// This module is unusual in that it exists because of a bunch of (krufty) reasons:
//
// - We based the name off of the original `bitcoin` module.
// - We want the API to be the same here as in `bitcoin`.
// - We define all the other hash types in some module so the merkle tree hash types need a module.
//
// C'est la vie.
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use hashes::{HashEngine, sha256d};

#[cfg(feature = "alloc")]
use crate::hash_types::{Txid, Wtxid};
#[cfg(feature = "alloc")]
use crate::transaction::TxIdentifier;

#[doc(inline)]
pub use crate::hash_types::{TxMerkleNode, TxMerkleNodeEncoder, WitnessMerkleNode};

/// A node in a Merkle tree of transactions or witness data within a block.
///
/// This trait is used to compute the transaction Merkle root contained in
/// a block header. This is a particularly weird algorithm -- it interprets
/// the list of transactions as a balanced binary tree, duplicating branches
/// as needed to fill out the tree to a power of two size.
///
/// Other Merkle trees in Bitcoin, such as those used in Taproot commitments,
/// do not use this algorithm and cannot use this trait.
#[cfg(feature = "alloc")]
pub trait MerkleNode: Copy + PartialEq {
    /// The hash (TXID or WTXID) of a transaction in the tree.
    type Leaf: TxIdentifier;

    /// Convert a hash to a leaf node of the tree.
    fn from_leaf(leaf: Self::Leaf) -> Self;
    /// Combine two nodes to get a single node. The final node of a tree is called the "root".
    #[must_use]
    fn combine(&self, other: &Self) -> Self;

    /// Given an iterator of leaves, compute the Merkle root.
    ///
    /// Returns `None` if the iterator was empty, or if the transaction list contains
    /// consecutive duplicates which would trigger CVE 2012-2459. Blocks with duplicate
    /// transactions will always be invalid, so there is no harm in us refusing to
    /// compute their merkle roots.
    ///
    /// Unless you are certain your transaction list is nonempty and has no duplicates,
    /// you should not unwrap the `Option` returned by this method!
    fn calculate_root<I: Iterator<Item = Self::Leaf>>(iter: I) -> Option<Self> {
        {
            let mut stack = Vec::<(usize, Self)>::with_capacity(32);
            // Start with a standard Merkle tree root computation...
            for (mut n, leaf) in iter.enumerate() {
                stack.push((0, Self::from_leaf(leaf)));

                while n & 1 == 1 {
                    let right = stack.pop().unwrap();
                    let left = stack.pop().unwrap();
                    if left.1 == right.1 {
                        // Reject duplicate trees since they are guaranteed-invalid (Bitcoin does
                        // not allow duplicate transactions in block) but can be used to confuse
                        // nodes about legitimate blocks. See CVE 2012-2459 and the block comment
                        // below.
                        return None;
                    }
                    debug_assert_eq!(left.0, right.0);
                    stack.push((left.0 + 1, left.1.combine(&right.1)));
                    n >>= 1;
                }
            }
            // ...then, deal with incomplete trees. Bitcoin does a weird thing in
            // which it doubles-up nodes of the tree to fill out the tree, rather
            // than treating incomplete branches specially. This makes this tree
            // construction vulnerable to collisions (see CVE 2012-2459).
            //
            // (It is also vulnerable to collisions because it does not distinguish
            // between internal nodes and transactions, but this collisions of this
            // form are probably impractical. It is likely that 64-byte transactions
            // will be forbidden in the future which will close this for good.)
            //
            // This is consensus logic so we cannot fix the Merkle tree construction.
            // Instead we just have to reject the clearly-invalid half of the collision
            // (see previous comment).
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
}

// These two impl blocks are identical. FIXME once we have nailed down
// our hash traits, it should be possible to put bounds on `MerkleNode`
// and `MerkleNode::Leaf` which are sufficient to turn both methods into
// provided methods in the trait definition.
#[cfg(feature = "alloc")]
impl MerkleNode for TxMerkleNode {
    type Leaf = Txid;
    fn from_leaf(leaf: Self::Leaf) -> Self { Self::from_byte_array(leaf.to_byte_array()) }

    fn combine(&self, other: &Self) -> Self {
        let mut encoder = sha256d::Hash::engine();
        encoder.input(self.as_byte_array());
        encoder.input(other.as_byte_array());
        Self::from_byte_array(sha256d::Hash::from_engine(encoder).to_byte_array())
    }
}
#[cfg(feature = "alloc")]
impl MerkleNode for WitnessMerkleNode {
    type Leaf = Wtxid;
    fn from_leaf(leaf: Self::Leaf) -> Self { Self::from_byte_array(leaf.to_byte_array()) }

    fn combine(&self, other: &Self) -> Self {
        let mut encoder = sha256d::Hash::engine();
        encoder.input(self.as_byte_array());
        encoder.input(other.as_byte_array());
        Self::from_byte_array(sha256d::Hash::from_engine(encoder).to_byte_array())
    }
}
