#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

use bitcoin::block::{self, Block, BlockCheckedExt as _};
use bitcoin::consensus::{deserialize, serialize};

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let b = Block::arbitrary(&mut u);

    if let Ok(block) = b {
        let serialized = serialize(&block);

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

        let deserialized: Result<Block, _> = deserialize(serialized.as_slice());
        assert_eq!(deserialized.unwrap(), block);
    }
}

fuzz_target!(|data| {
    do_test(data);
});
