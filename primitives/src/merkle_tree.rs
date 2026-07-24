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

#[doc(no_inline)]
pub use self::error::TxMerkleNodeDecoderError;
#[doc(inline)]
pub use crate::hash_types::{
    TxMerkleNode, TxMerkleNodeDecoder, TxMerkleNodeEncoder, WitnessMerkleNode,
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
            // between internal nodes and transactions, but collisions of this
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

    /// Given a leaf, its position and an iterator of nodes forming a proof, compute the Merkle root.
    ///
    /// TODO
    fn calculate_root_from_proof<I: Iterator<Item = Self>>(
        leaf: Self::Leaf,
        pos: u64,
        proof: I,
    ) -> Self {
        {
            let mut node = Self::from_leaf(leaf);
            let mut pos = pos;
            for sibling in proof {
                let (left, right) = if pos % 2 == 0 { (node, sibling) } else { (sibling, node) };
                node = left.combine(&right);
                pos /= 2;
            }
            debug_assert_eq!(pos, 0);
            node
        }
    }
}

#[cfg(feature = "std")]
#[cfg(any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64"))]
fn calculate_root_batched(mut nodes: Vec<[u8; 32]>) -> Option<[u8; 32]> {
    if nodes.is_empty() {
        return None;
    }

    while nodes.len() > 1 {
        // check consecutive duplicates which would trigger CVE 2012-245
        for pair in nodes.chunks_exact(2) {
            if pair[0] == pair[1] {
                return None;
            }
        }

        // if odd count, duplicate last element
        if nodes.len() % 2 != 0 {
            let last = *nodes.last().expect("nodes is not empty");
            nodes.push(last);
        }

        let pair_count = nodes.len() / 2;
        let inputs: Vec<[u8; 64]> = nodes
            .chunks_exact(2)
            .map(|pair| {
                let mut block = [0u8; 64];
                block[..32].copy_from_slice(&pair[0]);
                block[32..].copy_from_slice(&pair[1]);
                block
            })
            .collect();

        let mut outputs = alloc::vec![[0u8; 32]; pair_count];
        sha256d::Hash::hash_64_many(&mut outputs, &inputs);
        nodes = outputs;
    }

    Some(nodes[0])
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

    #[cfg(feature = "std")]
    #[cfg(any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64"))]
    fn calculate_root<I: Iterator<Item = Self::Leaf>>(iter: I) -> Option<Self> {
        let nodes: Vec<[u8; 32]> = iter.map(Txid::to_byte_array).collect();
        calculate_root_batched(nodes).map(Self::from_byte_array)
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

    #[cfg(feature = "std")]
    #[cfg(any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64"))]
    fn calculate_root<I: Iterator<Item = Self::Leaf>>(iter: I) -> Option<Self> {
        let nodes: Vec<[u8; 32]> = iter.map(Wtxid::to_byte_array).collect();
        calculate_root_batched(nodes).map(Self::from_byte_array)
    }
}

/// Error types for the merkle tree module.
pub mod error {
    #[doc(inline)]
    pub use crate::hash_types::TxMerkleNodeDecoderError;
}

#[cfg(test)]
mod tests {
    use hashes::HashEngine;

    use super::MerkleNode;
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
    #[cfg(feature = "alloc")]
    fn test_merkle_root_batched() {
        use alloc::vec::Vec;

        // copy of `MerkleNode::calculate_root` (stack-based) implementation to test against the new batched approach
        fn stack_based_root<I: Iterator<Item = Txid>>(iter: I) -> Option<TxMerkleNode> {
            let mut stack = Vec::<(usize, TxMerkleNode)>::with_capacity(32);

            for (mut n, leaf) in iter.enumerate() {
                stack.push((0, TxMerkleNode::from_leaf(leaf)));

                while n & 1 == 1 {
                    let right = stack.pop().unwrap();
                    let left = stack.pop().unwrap();
                    if left.1 == right.1 {
                        return None;
                    }
                    debug_assert_eq!(left.0, right.0);
                    stack.push((left.0 + 1, left.1.combine(&right.1)));
                    n >>= 1;
                }
            }

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

        fn make_leaves(count: usize) -> Vec<Txid> {
            (0..count as u32)
                .map(|i| {
                    let mut buf = [0u8; 32];
                    buf[..4].copy_from_slice(&i.to_le_bytes());
                    Txid::from_byte_array(buf)
                })
                .collect()
        }

        // test odd and even count
        for size in [32, 33] {
            let leaves = make_leaves(size);
            let got = TxMerkleNode::calculate_root(leaves.iter().copied());
            let expected = stack_based_root(leaves.iter().copied());
            assert_eq!(got, expected);
        }
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

    #[test]
    fn calculate_root_from_proof() {
        let leaf1 = Wtxid::from_byte_array([1; 32]);
        let leaf2 = Wtxid::from_byte_array([2; 32]);
        let leaves = [leaf1, leaf2];
        //tree of height 1
        let root1 = WitnessMerkleNode::calculate_root(leaves.into_iter()).unwrap();
        let root_from_proof_1 = WitnessMerkleNode::calculate_root_from_proof(
            leaf1,
            leaves.iter().position(|l| l == &leaf1).unwrap() as u64,
            [WitnessMerkleNode::from_leaf(leaf2)].into_iter(),
        );
        assert_eq!(root1, root_from_proof_1);
        let root_from_proof_2 = WitnessMerkleNode::calculate_root_from_proof(
            leaf2,
            leaves.iter().position(|l| l == &leaf2).unwrap() as u64,
            [WitnessMerkleNode::from_leaf(leaf1)].into_iter(),
        );
        assert_eq!(root1, root_from_proof_2);
        //tree of height 2
        let leaf3 = Wtxid::from_byte_array([3; 32]);
        let leaf4 = Wtxid::from_byte_array([4; 32]);
        let leaves = [leaf1, leaf2, leaf3, leaf4];
        let root2 = WitnessMerkleNode::calculate_root(leaves.into_iter()).unwrap();
        let root_from_proof_3 = WitnessMerkleNode::calculate_root_from_proof(
            leaf3,
            leaves.iter().position(|l| l == &leaf3).unwrap() as u64,
            [WitnessMerkleNode::from_leaf(leaf4), root1].into_iter(),
        );
        assert_eq!(root2, root_from_proof_3);
        let root_from_proof_4 = WitnessMerkleNode::calculate_root_from_proof(
            leaf4,
            leaves.iter().position(|l| l == &leaf4).unwrap() as u64,
            [WitnessMerkleNode::from_leaf(leaf3), root1].into_iter(),
        );
        assert_eq!(root2, root_from_proof_4);
    }

    #[cfg(feature = "hex")]
    #[test]
    fn calculate_root_from_proof_mainnet_tx() {
        // Data retrieved from Esplora for tx at block 951404, position 19.
        let txid: Txid =
            "d3887ab7972fb890b995972399a14f4b68436ad8e18b8e49690ac16f1c714f07".parse().unwrap();
        // curl 'https://blockstream.info/api/block/00000000000000000001a53ac26c662a3cb22109286cf7833adc1d27cd659334' | jq -r .merkle_root
        let expected_root: TxMerkleNode =
            "a7b4151d177c913b897c2d31f18707021cfeefbe61a46d016f7d66dee2752ee6".parse().unwrap();
        // curl 'https://blockstream.info/api/tx/d3887ab7972fb890b995972399a14f4b68436ad8e18b8e49690ac16f1c714f07/merkle-proof'
        let siblings: [TxMerkleNode; 12] = [
            "9503de88d658c2b60206cf3e98a787088e5bcdc0d53616db50c5c71f3be58466".parse().unwrap(),
            "641f3c169e308b90a5fe250a9243b529a6a833b09ffd225b10bc340d5a8eb2a0".parse().unwrap(),
            "29c2ef1dea7e7218cd1cfc955d17f5ce09242e12e5dd6883eafe77fef33e48d8".parse().unwrap(),
            "c91e6412281a7fc394511be31be7cff43a745bc885a9bb6acce9b7fb9f0c93ea".parse().unwrap(),
            "54ee7685d3634682da1d35eea599514601416b5bf31ea3ac7c9dc1473427c2c5".parse().unwrap(),
            "2cf35bb43956396015b69b94ff8937de359f320a4cb49a3fb24a79560bfd5a46".parse().unwrap(),
            "b3f63ba740798f412167f96b479fb2b451e347a62abd7a40e307f385b3062b6a".parse().unwrap(),
            "75f79362378d3cdf41b278c51cba2fbb048eb1495b8ceb884f67f8d6f7569199".parse().unwrap(),
            "3e245b1795fb26513f818cd5ae9ab0144941cd0b1b005a2a7e8ba3e2e7ea0b4e".parse().unwrap(),
            "baa02baaf437b99410919393f8d5c9ee73d620331a4a209c5ebe81b55b9185b9".parse().unwrap(),
            "e00015e03c591e1da415ba7f081f238b20aac986df13fd7893a58e6664527744".parse().unwrap(),
            "3545330459012524405f7eafd66af86940323c5badfd42ab2a858335e0f57a84".parse().unwrap(),
        ];
        let root = TxMerkleNode::calculate_root_from_proof(txid, 19, siblings.into_iter());
        assert_eq!(root, expected_root);
    }

    #[test]
    fn calculate_root_from_proof_truncated_tree() {
        // Last (pos 8) transaction in block 13b8a
        //
        // esplora merkle proof for this transaction:
        // curl 'https://blockstream.info/api/tx/74d681e0e03bafa802c8aa084379aa98d9fcd632ddc2ed9782b586ec87451f20/merkle-proof'
        let txid: Txid =
            "74d681e0e03bafa802c8aa084379aa98d9fcd632ddc2ed9782b586ec87451f20".parse().unwrap();
        let expected_root: TxMerkleNode =
            "2fda58e5959b0ee53c5253da9b9f3c0c739422ae04946966991cf55895287552".parse().unwrap();

        let siblings: [TxMerkleNode; 4] = [
            "74d681e0e03bafa802c8aa084379aa98d9fcd632ddc2ed9782b586ec87451f20".parse().unwrap(),
            "bb8db5f1d687839cc15a875e321ffb910d1c62d9280c1e4089122544c3528a13".parse().unwrap(),
            "e7413bdf2c1215c3983536a62b1e210d9006a789cdc1427ccb4bb347745e52fc".parse().unwrap(),
            "660af9921e9e17eba1106409c93aeec1b390bff99b0c25499da1b9c0e9aa56bc".parse().unwrap(),
        ];
        // last txid gets duplicated in odd-width merkle trees
        assert_eq!(siblings[0], TxMerkleNode::from_leaf(txid));

        let root = TxMerkleNode::calculate_root_from_proof(txid, 8, siblings.into_iter());
        assert_eq!(root, expected_root);
    }

    // The tests below exercise the default trait `MerkleNode::calculate_root`
    // implementation. On std+x86_64/aarch64, both `TxMerkleNode` and
    // `WitnessMerkleNode` override `calculate_root` with the batched version,
    // this is a test-only impl that uses the default `calculate_root` to kill
    // mutants
    #[derive(Clone, Copy, Eq, PartialEq)]
    struct TestLeaf([u8; 32]);

    impl AsRef<[u8]> for TestLeaf {
        fn as_ref(&self) -> &[u8] { &self.0 }
    }

    impl crate::transaction::TxIdentifier for TestLeaf {}

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestNode([u8; 32]);

    impl super::MerkleNode for TestNode {
        type Leaf = TestLeaf;

        fn from_leaf(leaf: Self::Leaf) -> Self { Self(leaf.0) }

        fn combine(&self, other: &Self) -> Self {
            let mut engine = hashes::sha256d::Hash::engine();
            engine.input(&self.0);
            engine.input(&other.0);
            Self(hashes::sha256d::Hash::from_engine(engine).to_byte_array())
        }
    }

    // Asserts the default (stack-based) `TestNode::calculate_root` produces
    // the same result as the optimized `TxMerkleNode::calculate_root`.
    #[track_caller]
    fn assert_roots_match(leaf_bytes: &[u8]) {
        let test_root = TestNode::calculate_root(leaf_bytes.iter().map(|&b| TestLeaf([b; 32])));
        let tx_root = TxMerkleNode::calculate_root(
            leaf_bytes.iter().map(|&b| Txid::from_byte_array([b; 32])),
        );
        assert_eq!(test_root.map(|n| n.0), tx_root.map(TxMerkleNode::to_byte_array));
    }

    #[test]
    fn calculate_root_empty() { assert_roots_match(&[]); }

    #[test]
    fn calculate_root_single_leaf() { assert_roots_match(&[1]); }

    #[test]
    fn calculate_root_two_leaves() { assert_roots_match(&[1, 2]); }

    #[test]
    fn calculate_root_duplicate_leaves() { assert_roots_match(&[3, 3]); }

    #[test]
    fn calculate_root_four_leaves() { assert_roots_match(&[1, 2, 3, 4]); }

    #[test]
    fn calculate_root_three_leaves_unbalanced() { assert_roots_match(&[1, 2, 3]); }

    #[test]
    fn calculate_root_five_leaves_unbalanced() { assert_roots_match(&[1, 2, 3, 4, 5]); }

    #[test]
    fn calculate_root_seven_leaves_unbalanced() { assert_roots_match(&[1, 2, 3, 4, 5, 6, 7]); }

    #[test]
    fn calculate_root_correct_root_value() {
        assert_roots_match(&[10, 20]);
        // Verify ordering matters: combine(a, b) != combine(b, a).
        let (_, node1) = make_leaf_node(10);
        let (_, node2) = make_leaf_node(20);
        assert_ne!(node1.combine(&node2), node2.combine(&node1));
    }
}
