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

use hashes::{sha256d, HashEngine};
#[cfg(not(feature = "alloc"))]
use internals::array_vec::ArrayVec;

#[doc(inline)]
pub use crate::hash_types::{
    TxMerkleNode, TxMerkleNodeDecoder, TxMerkleNodeEncoder, TxMerkleNodeDecoderError, WitnessMerkleNode
};
use crate::hash_types::{Txid, Wtxid};
use crate::transaction::TxIdentifier;

/// A node in a Merkle tree of transactions or witness data within a block.
///
/// This trait is used to compute the transaction Merkle root contained in
/// a block header. This is a particularly weird algorithm -- it interprets
/// the list of transactions as a balanced binary tree, duplicating branches
/// as needed to fill out the tree to a power of two size.
///
/// Other Merkle trees in Bitcoin, such as those used in Taproot commitments,
/// do not use this algorithm and cannot use this trait.
pub(crate) trait MerkleNode: Copy + PartialEq {
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
    /// Also returns `None` if the `alloc` feature is disabled and `iter` has more than
    /// 32,767 transactions.
    ///
    /// Unless you are certain your transaction list is nonempty and has no duplicates,
    /// you should not unwrap the `Option` returned by this method!
    fn calculate_root<I: Iterator<Item = Self::Leaf>>(iter: I) -> Option<Self> {
        {
            #[cfg(feature = "alloc")]
            let mut stack = Vec::<(usize, Self)>::with_capacity(32);
            #[cfg(not(feature = "alloc"))]
            let mut stack = ArrayVec::<(usize, Self), 15>::new();

            // Start with a standard Merkle tree root computation...
            for (mut n, leaf) in iter.enumerate() {
                #[cfg(not(feature = "alloc"))]
                // This is the only time that the stack actually grows, rather than being combined.
                if stack.len() == 15 {
                    return None;
                }
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

#[cfg(test)]
mod tests {
    use crate::hash_types::*;

    // Helper to make a Txid, TxMerkleNode pair with a single number byte array
    fn make_leaf_node(byte: u8) -> (Txid, TxMerkleNode) {
        let leaf = Txid::from_byte_array([byte; 32]);
        let node = TxMerkleNode::from_leaf(leaf);
        (leaf, node)
    }

    #[test]
    fn tx_merkle_node_single_leaf() {
        let (leaf, node) = make_leaf_node(1);
        let root = TxMerkleNode::calculate_root([leaf].into_iter());
        assert!(root.is_some(), "Root should exist for a single leaf");
        assert_eq!(root.unwrap(), node, "Root should equal the leaf node");
    }

    #[test]
    fn tx_merkle_node_two_leaves() {
        let (leaf1, node1) = make_leaf_node(1);
        let (leaf2, node2) = make_leaf_node(2);
        let combined = node1.combine(&node2);

        let root = TxMerkleNode::calculate_root([leaf1, leaf2].into_iter());
        assert_eq!(
            root.unwrap(),
            combined,
            "Root of two leaves should equal combine of the two leaf nodes"
        );
    }

    #[test]
    fn tx_merkle_node_duplicate_leaves() {
        let leaf = Txid::from_byte_array([3; 32]);
        // Duplicate transaction list should be rejected (CVE 2012‑2459).
        let root = TxMerkleNode::calculate_root([leaf, leaf].into_iter());
        assert!(root.is_none(), "Duplicate leaves should return None");
    }

    #[test]
    fn tx_merkle_node_empty() {
        assert!(
            TxMerkleNode::calculate_root([].into_iter()).is_none(),
            "Empty iterator should return None"
        );
    }

    #[test]
    fn tx_merkle_node_2n_minus_1_unbalanced_tree() {
        // Test a tree with 2^n - 1 unique nodes and at least 3 layers deep.
        let (leaf1, node1) = make_leaf_node(1);
        let (leaf2, node2) = make_leaf_node(2);
        let (leaf3, node3) = make_leaf_node(3);
        let (leaf4, node4) = make_leaf_node(4);
        let (leaf5, node5) = make_leaf_node(5);
        let (leaf6, node6) = make_leaf_node(6);
        let (leaf7, node7) = make_leaf_node(7);

        // Combine leaf nodes
        let subtree_a = node1.combine(&node2);
        let subtree_b = node3.combine(&node4);
        let subtree_c = node5.combine(&node6);
        let subtree_d = node7.combine(&node7); // doubled

        // Combine the subtrees
        let subtree_ab = subtree_a.combine(&subtree_b);
        let subtree_cd = subtree_c.combine(&subtree_d);
        let expected = subtree_ab.combine(&subtree_cd);

        let root = TxMerkleNode::calculate_root(
            [leaf1, leaf2, leaf3, leaf4, leaf5, leaf6, leaf7].into_iter(),
        );
        assert_eq!(root, Some(expected));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn tx_merkle_node_balanced_multi_level_tree() {
        use alloc::vec::Vec;

        let leaves: Vec<_> = (0..16).map(|i| Txid::from_byte_array([i; 32])).collect();

        // Create nodes for the txids.
        let mut level = leaves.iter().map(|l| TxMerkleNode::from_leaf(*l)).collect::<Vec<_>>();

        // Combine the leaves into a tree, ordered from left-to-right in the initial vector.
        while level.len() > 1 {
            level = level.chunks(2).map(|chunk| chunk[0].combine(&chunk[1])).collect();
        }

        // Take the final node, which should be the root of the full tree.
        let expected = level.pop().unwrap();

        let root = TxMerkleNode::calculate_root(leaves.into_iter());
        assert_eq!(root, Some(expected));
    }

    #[test]
    fn tx_merkle_node_oversize_tree() {
        // Confirm that with no-alloc, we return None for iter length >= 32768
        let root = TxMerkleNode::calculate_root((0..32768u32).map(|i| {
            let mut buf = [0u8; 32];
            buf[..4].copy_from_slice(&i.to_le_bytes());
            Txid::from_byte_array(buf)
        }));

        // We just want to confirm that we return None at the 32768 element boundary.
        #[cfg(feature = "alloc")]
        assert_ne!(root, None);
        #[cfg(not(feature = "alloc"))]
        assert_eq!(root, None);

        // Check just under the boundary
        let root = TxMerkleNode::calculate_root((0..32767u32).map(|i| {
            let mut buf = [0u8; 32];
            buf[..4].copy_from_slice(&i.to_le_bytes());
            Txid::from_byte_array(buf)
        }));
        assert_ne!(root, None);
    }

    #[test]
    fn witness_merkle_node_single_leaf() {
        let leaf = Wtxid::from_byte_array([1; 32]);
        let root = WitnessMerkleNode::calculate_root([leaf].into_iter());
        assert!(root.is_some(), "Root should exist for a single witness leaf");
        let node = WitnessMerkleNode::from_leaf(leaf);
        assert_eq!(root.unwrap(), node, "Root should equal the leaf node");
    }

    #[test]
    fn witness_merkle_node_duplicate_leaves() {
        let leaf = Wtxid::from_byte_array([2; 32]);
        let root = WitnessMerkleNode::calculate_root([leaf, leaf].into_iter());
        assert!(root.is_none(), "Duplicate witness leaves should return None");
    }
}
