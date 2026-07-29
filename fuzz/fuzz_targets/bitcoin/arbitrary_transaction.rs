#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use bitcoin::encoding::{decode_from_slice, encode_to_vec};
use bitcoin::transaction::TransactionExt as _;
use bitcoin::Transaction;
use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(mut tx: Transaction) {
    let serialized = encode_to_vec(&tx);
    let deserialized: Result<Transaction, _> = decode_from_slice(serialized.as_slice());
    assert_eq!(deserialized.unwrap(), tx);

    let len = serialized.len();
    let calculated_weight = tx.weight().to_wu() as usize;
    for input in &mut tx.inputs {
        input.witness = bitcoin::witness::Witness::default();
    }
    let no_witness_len = encode_to_vec(&tx).len();
    // For 0-input transactions, `no_witness_len` will be incorrect because
    // we serialize as SegWit even after "stripping the witnesses". We need
    // to drop two bytes (i.e. eight weight). Similarly, calculated_weight is
    // incorrect and needs 2 wu removing for the marker/flag bytes.
    if tx.inputs.is_empty() {
        assert_eq!(no_witness_len * 3 + len - 8, calculated_weight - 2);
    } else {
        assert_eq!(no_witness_len * 3 + len, calculated_weight);
    }
}

fuzz_target!(|data: Transaction| {
    do_test(data);
});
