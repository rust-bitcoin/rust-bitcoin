use bitcoin::block::BlockExt as _;
use honggfuzz::fuzz;

fn do_test(data: &[u8]) {
    let block_result: Result<bitcoin::block::Block, _> =
        bitcoin::consensus::encode::deserialize(data);

    match block_result {
        Err(_) => {}
        Ok(block) => {
            let ser = bitcoin::consensus::encode::serialize(&block);
            assert_eq!(&ser[..], data);
            let _ = block.bip34_block_height();
            block.block_hash();
            block.check_merkle_root();
            block.check_witness_commitment();
            block.weight();
            block.witness_root();
        }
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
