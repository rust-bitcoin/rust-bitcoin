//! Tests for `MerkleBlock`. Data lives in `tests/data`, which is excluded when publishing.

use bitcoin_p2p_messages::merkle_tree::MerkleBlock;
use hex::DisplayHex;
use primitives::block::{Block, Checked, Unchecked};
use primitives::Txid;

/// Returns a real block (0000000000013b8ab2cd513b0261a14096412195a72a0c4827d229dcc7e0f7af)
/// with 9 txs.
fn get_block_13b8a() -> Block<Checked> {
    let block_hex = include_str!("data/block_13b8a.hex");
    let block: Block<Unchecked> =
        encoding::decode_from_slice(&hex::decode_to_vec(block_hex).unwrap()).unwrap();
    block.validate().expect("block should be valid")
}

#[test]
fn merkleblock_serialization() {
    // Got it by running the rpc call
    // `gettxoutproof '["220ebc64e21abece964927322cba69180ed853bb187fbc6923bac7d010b9d87a"]'`
    let mb_hex = include_str!("data/merkle_block.hex");

    let bytes = hex::decode_to_vec(mb_hex).unwrap();
    let mb: MerkleBlock = encoding::decode_from_slice(&bytes).unwrap();
    assert_eq!(get_block_13b8a().block_hash(), mb.header.block_hash());
    assert_eq!(mb.header.merkle_root, mb.txn.extract_matches(&mut vec![], &mut vec![]).unwrap());
    // Serialize again and check that it matches the original bytes
    assert_eq!(mb_hex, encoding::encode_to_vec(&mb).to_lower_hex_string().as_str());
}

/// Constructs a new [`MerkleBlock`] using a list of txids which will be found in the
/// given block.
#[test]
fn merkleblock_construct_from_txids_found() {
    let block = get_block_13b8a();

    let txids: Vec<Txid> = [
        "74d681e0e03bafa802c8aa084379aa98d9fcd632ddc2ed9782b586ec87451f20",
        "f9fc751cb7dc372406a9f8d738d5e6f8f63bab71986a39cf36ee70ee17036d07",
    ]
    .iter()
    .map(|hex| hex.parse::<Txid>().unwrap())
    .collect();

    let txid1 = txids[0];
    let txid2 = txids[1];
    let txids = [txid1, txid2];

    let merkle_block = MerkleBlock::from_block_with_predicate(&block, |t| txids.contains(t));

    assert_eq!(merkle_block.header.block_hash(), block.block_hash());

    let mut matches: Vec<Txid> = vec![];
    let mut index: Vec<u32> = vec![];

    assert_eq!(
        merkle_block.txn.extract_matches(&mut matches, &mut index).unwrap(),
        block.header().merkle_root
    );
    assert_eq!(matches.len(), 2);

    // Ordered by occurrence in depth-first tree traversal.
    assert_eq!(matches[0], txid2);
    assert_eq!(index[0], 1);

    assert_eq!(matches[1], txid1);
    assert_eq!(index[1], 8);
}

/// Constructs a new [`MerkleBlock`] using a list of txids which will not be found in the given block
#[test]
fn merkleblock_construct_from_txids_not_found() {
    let block = get_block_13b8a();
    let txids: Vec<Txid> = ["c0ffee00003bafa802c8aa084379aa98d9fcd632ddc2ed9782b586ec87451f20"]
        .iter()
        .map(|hex| hex.parse::<Txid>().unwrap())
        .collect();

    let merkle_block = MerkleBlock::from_block_with_predicate(&block, |t| txids.contains(t));

    assert_eq!(merkle_block.header.block_hash(), block.block_hash());

    let mut matches: Vec<Txid> = vec![];
    let mut index: Vec<u32> = vec![];

    assert_eq!(
        merkle_block.txn.extract_matches(&mut matches, &mut index).unwrap(),
        block.header().merkle_root
    );
    assert_eq!(matches.len(), 0);
    assert_eq!(index.len(), 0);
}
