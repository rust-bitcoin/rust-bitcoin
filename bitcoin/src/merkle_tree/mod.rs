// SPDX-License-Identifier: CC0-1.0

//! Bitcoin merkle tree functions.
//!
//! # Examples
//!
//! ```
//! # use bitcoin::{merkle_tree, Txid};
//! # use bitcoin::hashes::Hash;
//! # let tx1 = Txid::all_zeros();  // Dummy hash values.
//! # let tx2 = Txid::all_zeros();
//! let tx_hashes = vec![tx1, tx2]; // All the hashes we wish to merkelize.
//! let root = merkle_tree::calculate_root(tx_hashes.into_iter());
//! ```

mod block;

use core::cmp::min;
use core::iter;

use hashes::{sha256d, Hash};
use io::Write;

use crate::consensus::encode::Encodable;
use crate::internal_macros::impl_hashencode;
use crate::prelude::*;
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

/// A trait that defines a hash that can appear as a node in a Merkle tree.
pub trait MerkleNode: Hash + Encodable {
    /// The root node type produced by this merkle tree.
    type Root: Hash;

    /// Converts a leaf node to the root node type e.g., when a tree has a single node.
    fn to_root(self) -> Self::Root;
}

impl MerkleNode for Txid {
    type Root = TxMerkleNode;

    fn to_root(self) -> Self::Root {
        TxMerkleNode::from_byte_array(self.to_byte_array())
    }
}

impl MerkleNode for Wtxid {
    type Root = WitnessMerkleNode;

    fn to_root(self) -> Self::Root {
        WitnessMerkleNode::from_byte_array(self.to_byte_array())
    }
}

/// Calculates the merkle root of a list of *hashes*, inline (in place) in `hashes`.
///
/// In most cases, you'll want to use [`calculate_root`] instead. Please note, calling this function
/// trashes the data in `hashes` (i.e. the `hashes` is left in an undefined state at conclusion of
/// this method and should not be used again afterwards).
///
/// # Returns
///
/// - `None` if `hashes` is empty. The merkle root of an empty tree of hashes is undefined.
/// - `Some(hash)` if `hashes` contains one element. A single hash is by definition the merkle root.
/// - `Some(merkle_root)` if length of `hashes` is greater than one.
pub fn calculate_root_inline<T>(hashes: &mut [T]) -> Option<T::Root>
where
    T: MerkleNode,
    <T as Hash>::Engine: Write,
{
    match hashes.len() {
        0 => None,
        1 => Some(hashes[0].to_root()),
        _ => Some(merkle_root_r(hashes).to_root()),
    }
}

/// Calculates the merkle root of an iterator of *hashes*.
///
/// # Returns
///
/// - `None` if `hashes` is empty. The merkle root of an empty tree of hashes is undefined.
/// - `Some(hash)` if `hashes` contains one element. A single hash is by definition the merkle root.
/// - `Some(merkle_root)` if length of `hashes` is greater than one.
pub fn calculate_root<T, I>(mut hashes: I) -> Option<T::Root>
where
    T: MerkleNode,
    <T as Hash>::Engine: Write,
    I: Iterator<Item = T>,
{
    let first = hashes.next()?;
    let second = match hashes.next() {
        Some(second) => second,
        None => return Some(first.to_root()),
    };

    let mut hashes = iter::once(first).chain(iter::once(second)).chain(hashes);

    // We need a local copy to pass to `merkle_root_r`. It's more efficient to do the first loop of
    // processing as we make the copy instead of copying the whole iterator.
    let (min, max) = hashes.size_hint();
    let mut alloc = Vec::with_capacity(max.unwrap_or(min) / 2 + 1);

    while let Some(hash1) = hashes.next() {
        // If the size is odd, use the last element twice.
        let hash2 = hashes.next().unwrap_or(hash1);
        let mut encoder = <T as Hash>::engine();
        hash1.consensus_encode(&mut encoder).expect("in-memory writers don't error");
        hash2.consensus_encode(&mut encoder).expect("in-memory writers don't error");
        alloc.push(<T as Hash>::from_engine(encoder));
    }

    Some(merkle_root_r(&mut alloc).to_root())
}

// `hashes` must contain at least one hash.
fn merkle_root_r<T>(hashes: &mut [T]) -> T
where
    T: MerkleNode + Encodable,
    <T as Hash>::Engine: Write,
{
    if hashes.len() == 1 {
        return T::from_byte_array(hashes[0].to_byte_array());
    }

    for idx in 0..((hashes.len() + 1) / 2) {
        let idx1 = 2 * idx;
        let idx2 = min(idx1 + 1, hashes.len() - 1);
        let mut encoder = T::engine();
        hashes[idx1].consensus_encode(&mut encoder).expect("in-memory writers don't error");
        hashes[idx2].consensus_encode(&mut encoder).expect("in-memory writers don't error");
        hashes[idx] = T::from_engine(encoder);
    }
    let half_len = hashes.len() / 2 + hashes.len() % 2;

    merkle_root_r(&mut hashes[0..half_len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockdata::block::Block;
    use crate::consensus::encode::deserialize;

    #[test]
    fn both_merkle_root_functions_return_the_same_result() {
        // testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
        let segwit_block = include_bytes!("../../tests/data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw");
        let block: Block = deserialize(&segwit_block[..]).expect("Failed to deserialize block");
        assert!(block.check_merkle_root()); // Sanity check.

        let hashes_iter = block.txdata.iter().map(|obj| obj.compute_txid());

        let mut hashes_array = [Txid::all_zeros(); 15];
        for (i, hash) in hashes_iter.clone().enumerate() {
            hashes_array[i] = hash;
        }

        let from_iter = calculate_root(hashes_iter);
        let from_array = calculate_root_inline(&mut hashes_array);
        assert_eq!(from_iter, from_array);
    }
}
