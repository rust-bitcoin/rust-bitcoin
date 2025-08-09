use arbitrary::{Arbitrary, Unstructured};
use honggfuzz::fuzz;
use bitcoin::bip152::PrefilledTransaction;
use bitcoin::consensus::{deserialize, serialize};

fn do_test(data: &[u8]) {
    // We already fuzz Transactions in `./deserialize_transaction.rs`.
    let mut u = Unstructured::new(data);
    let p = PrefilledTransaction::arbitrary(&mut u);

    if let Ok(prefilled_tx) = p {
        let serialized = serialize(&prefilled_tx);
        let deserialized: Result<PrefilledTransaction, _> = deserialize(serialized.as_slice());

        assert!(deserialized.is_ok(), "Fuzz error: {:?}", deserialized.err().unwrap());
        assert_eq!(deserialized.unwrap(), prefilled_tx);
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
        extend_vec_from_hex("00000000", &mut a);
        super::do_test(&a);
    }
}
