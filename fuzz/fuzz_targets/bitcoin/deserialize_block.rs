#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use bitcoin::encoding::{decode_from_slice, encode_to_vec};
use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let block_result: Result<bitcoin::Block, _> = decode_from_slice(data);

    match block_result {
        Err(_) => {}
        Ok(block) => {
            let ser = encode_to_vec(&block);
            assert_eq!(&ser[..], data);
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});
