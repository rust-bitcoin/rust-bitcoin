// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Merkle tree functions.
//!
//! # Examples
//!
//! ```
//! # use bitcoin::Txid;
//! # use bitcoin::merkle_tree::{MerkleNode as _, TxMerkleNode};
//! # use bitcoin::hashes::Hash;
//! # let tx1 = Txid::all_zeros();  // Dummy hash values.
//! # let tx2 = Txid::all_zeros();
//! let tx_hashes = vec![tx1, tx2]; // All the hashes we wish to merkelize.
//! let root = TxMerkleNode::calculate_root(tx_hashes.into_iter());
//! ```

mod block;

use crate::internal_macros::impl_hashencode;

#[rustfmt::skip]
#[doc(inline)]
pub use self::block::{MerkleBlock, MerkleBlockError, PartialMerkleTree};
#[doc(inline)]
pub use primitives::merkle_tree::*;

impl_hashencode!(TxMerkleNode);
impl_hashencode!(WitnessMerkleNode);

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
