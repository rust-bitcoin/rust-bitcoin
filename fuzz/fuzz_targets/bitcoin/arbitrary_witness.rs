use arbitrary::{Arbitrary, Unstructured};
use honggfuzz::fuzz;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::Witness;
use bitcoin::blockdata::witness::WitnessExt;

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);

    if let Ok(mut witness) = Witness::arbitrary(&mut u) {
        let serialized = serialize(&witness);

        let _ = witness.witness_script();
        let _ = witness.taproot_leaf_script();

        let deserialized: Result<Witness, _> = deserialize(serialized.as_slice());
        assert!(deserialized.is_ok(), "Deserialization error: {:?}", deserialized.err().unwrap());
        assert_eq!(deserialized.unwrap(), witness);

        if let Ok(element_bytes) = Vec::<u8>::arbitrary(&mut u) {
            witness.push(element_bytes.as_slice());
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
