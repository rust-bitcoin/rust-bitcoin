#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use bitcoin::encoding::{decode_from_slice, encode_to_vec};
use bitcoin::witness::Witness;
use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let witness_result: Result<Witness, _> = decode_from_slice(data);

    match witness_result {
        Err(_) => {}
        Ok(witness) => {
            let ser = encode_to_vec(&witness);
            assert_eq!(&ser[..], data);
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});
