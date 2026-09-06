//! Tests for `Block`. Data lives in `tests/data`, which is excluded when publishing.

use bitcoin::block::{self, Block, Header, Version};
use bitcoin::ext::*;
use bitcoin::network::Params;
use bitcoin::pow::Work;
use bitcoin::{BlockTime, CompactTarget, Network, TestnetVersion, Transaction, Weight};
use encoding::{decode_from_slice, encode_to_vec, CompactSizeEncoder};
use hex::hex;

fn block_base_size(transactions: &[Transaction]) -> usize {
    let mut size = Header::SIZE;

    size += CompactSizeEncoder::encoded_size(transactions.len());
    size += transactions.iter().map(|tx| tx.base_size()).sum::<usize>();

    size
}

// Check testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
#[test]
fn segwit_block() {
    let params = Params::new(Network::Testnet(TestnetVersion::V3));
    let segwit_block = include_bytes!(
        "data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw"
    )
    .to_vec();

    let decode: Result<Block, _> = decode_from_slice(&segwit_block);

    let prevhash = hex!("2aa2f2ca794ccbd40c16e2f3333f6b8b683f9e7179b2c4d74906000000000000");
    let merkle = hex!("10bc26e70a2f672ad420a6153dd0c28b40a6002c55531bfc99bf8994a8e8f67e");
    let work = Work::from_hex("0x257c3becdacc64").unwrap();

    assert!(decode.is_ok());

    let block = decode.unwrap();
    let (witness_commitment_matches, witness_root) = block.check_witness_commitment();
    assert!(witness_commitment_matches);

    let (header, transactions) = block.into_parts();
    let real_decode =
        Block::new_unchecked(header, transactions.clone()).assume_checked(witness_root);

    assert_eq!(real_decode.header().version, Version::from_consensus(0x2000_0000)); // VERSIONBITS but no bits set
    assert_eq!(encode_to_vec(&real_decode.header().prev_blockhash), prevhash);
    assert_eq!(encode_to_vec(&real_decode.header().merkle_root), merkle);
    assert_eq!(
        real_decode.header().merkle_root,
        block::compute_merkle_root(&transactions).unwrap()
    );
    assert_eq!(real_decode.header().time, BlockTime::from_u32(1472004949));
    assert_eq!(real_decode.header().bits, CompactTarget::from_consensus(0x1a06d450));
    assert_eq!(real_decode.header().nonce, 1879759182);
    assert_eq!(real_decode.header().work(), work);
    assert_eq!(real_decode.header().difficulty(&params), 2456598);
    assert_eq!(real_decode.header().difficulty_float(&params), 2456598.4399242126);

    assert_eq!(
        real_decode.header().validate_pow(real_decode.header().target()).unwrap(),
        real_decode.block_hash()
    );
    assert_eq!(real_decode.total_size(), segwit_block.len());
    assert_eq!(block_base_size(real_decode.transactions()), 4283);
    assert_eq!(real_decode.weight(), Weight::from_wu(17168));

    assert_eq!(encode_to_vec(&real_decode), segwit_block);
}
