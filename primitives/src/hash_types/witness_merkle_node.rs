// SPDX-License-Identifier: CC0-1.0

//! The `WitnessMerkleNode` type.

#[cfg(not(feature = "hex"))]
use core::fmt;
#[cfg(feature = "hex")]
use core::str;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::sha256d;

#[cfg(feature = "alloc")]
use crate::merkle_tree::MerkleNode;
#[cfg(feature = "alloc")]
use crate::Wtxid;

/// A hash corresponding to the Merkle tree root for witness data.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WitnessMerkleNode(sha256d::Hash);

// The new hash wrapper type.
type HashType = WitnessMerkleNode;
// The inner hash type from `hashes`.
type Inner = sha256d::Hash;

include!("./generic.rs");

#[cfg(feature = "alloc")]
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
    pub fn calculate_root<I: Iterator<Item = Wtxid>>(iter: I) -> Option<Self> { MerkleNode::calculate_root(iter) }
}
