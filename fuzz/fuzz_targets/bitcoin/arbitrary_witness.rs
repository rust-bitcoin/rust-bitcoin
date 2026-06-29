#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use bitcoin::blockdata::witness::WitnessExt;
use bitcoin::encoding::{decode_from_slice, encode_to_vec};
use bitcoin::Witness;
use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: (Witness, Vec<u8>)) {
    let mut witness = data.0;
    let element_bytes = data.1;

    let serialized = encode_to_vec(&witness);

    let _ = witness.witness_script();
    let _ = witness.taproot_leaf_script();

    let deserialized: Result<Witness, _> = decode_from_slice(serialized.as_slice());
    assert_eq!(deserialized.unwrap(), witness);

    witness.push(element_bytes.as_slice());
}

fuzz_target!(|data: (Witness, Vec<u8>)| {
    do_test(data);
});
