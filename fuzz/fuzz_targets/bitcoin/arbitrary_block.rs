#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use bitcoin::block::{self, Block, BlockCheckedExt as _};
use bitcoin::encoding::{decode_from_slice, encode_to_vec};
use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(block: Block) {
    let serialized = encode_to_vec(&block);

    // Manually call all compute functions with unchecked block data.
    let (header, transactions) = block.clone().into_parts();
    block::compute_merkle_root(&transactions);
    // Use 32-byte zero array as witness_reserved_value per BIP-0141 requirement.
    block.compute_witness_commitment(&[0u8; 32]);
    block::compute_witness_root(&transactions);

    if let Ok(block) = Block::new_checked(header, transactions) {
        let _ = block.bip34_block_height();
        block.block_hash();
        block.weight();
    }

    let deserialized: Result<Block, _> = decode_from_slice(serialized.as_slice());
    assert_eq!(deserialized.unwrap(), block);
}

fuzz_target!(|data: Block| {
    do_test(data);
});
