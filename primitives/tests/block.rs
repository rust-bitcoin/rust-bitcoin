#![cfg(feature = "alloc")]

use bitcoin_primitives::block::{Block, Unchecked};
use bitcoin_primitives::merkle_tree::TxMerkleNode;
use bitcoin_primitives::Transaction;

#[test]
fn static_vector() {
    // testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
    let segwit_block = include_bytes!("../tests/data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw");
    let block: Block<Unchecked> =
        encoding::decode_from_slice(&segwit_block[..]).expect("failed to deserialize block");
    assert!(block.check_merkle_root());

    let (header, transactions) = block.into_parts();
    let block = Block::new_unchecked(header, transactions).assume_checked(None);

    // Same as `block.check_merkle_root` but do it explicitly.
    let hashes_iter = block.transactions().iter().map(Transaction::compute_txid);
    let from_iter = TxMerkleNode::calculate_root(hashes_iter.clone());
    assert_eq!(from_iter, Some(block.header().merkle_root));
}
