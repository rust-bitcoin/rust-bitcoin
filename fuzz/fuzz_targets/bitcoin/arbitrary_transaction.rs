use arbitrary::{Arbitrary, Unstructured};
use honggfuzz::fuzz;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::Transaction;
use bitcoin::transaction::TransactionExt as _;

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let t = Transaction::arbitrary(&mut u);

    if let Ok(mut tx) = t {
        let serialized = serialize(&tx);
        let len = serialized.len();
        let calculated_weight = tx.weight().to_wu() as usize;
        for input in &mut tx.inputs {
            input.witness = bitcoin::witness::Witness::default();
        }
        let no_witness_len = bitcoin::consensus::encode::serialize(&tx).len();
        // For 0-input transactions, `no_witness_len` will be incorrect because
        // we serialize as SegWit even after "stripping the witnesses". We need
        // to drop two bytes (i.e. eight weight). Similarly, calculated_weight is
        // incorrect and needs 2 wu removing for the marker/flag bytes.
        if tx.inputs.is_empty() {
            assert_eq!(no_witness_len * 3 + len - 8, calculated_weight - 2);
        } else {
            assert_eq!(no_witness_len * 3 + len, calculated_weight);
        }

        let deserialized: Result<Transaction, _> = deserialize(serialized.as_slice());
        assert!(deserialized.is_ok(), "Deserialization error: {:?}", deserialized.err().unwrap());
        assert_eq!(deserialized.unwrap(), tx);
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
