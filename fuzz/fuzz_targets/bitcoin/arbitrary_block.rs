use arbitrary::{Arbitrary, Unstructured};
use bitcoin::block::{self, Block, BlockCheckedExt as _};
use bitcoin::consensus::{deserialize, serialize};
use honggfuzz::fuzz;

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let b = Block::arbitrary(&mut u);

    if let Ok(block) = b {
        let serialized = serialize(&block);

        // Manually call all compute functions with unchecked block data.
        let (header, transactions) = block.clone().into_parts();
        block::compute_merkle_root(&transactions);
        // Use 32-byte zero array as witness_reserved_value per BIP-0141 requirement.
        block::compute_witness_commitment(&transactions, &[0u8; 32]);
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

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(all(test, fuzzing))]
mod tests {
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().enumerate() {
            b <<= 4;
            match *c {
                b'A'..=b'F' => b |= c - b'A' + 10,
                b'a'..=b'f' => b |= c - b'a' + 10,
                b'0'..=b'9' => b |= c - b'0',
                _ => panic!("Bad hex"),
            }
            if (idx & 1) == 1 {
                out.push(b);
                b = 0;
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00", &mut a);
        super::do_test(&a);
    }
}
