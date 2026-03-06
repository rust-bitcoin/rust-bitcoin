#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

use bitcoin::hashes::{sha512_256, HashEngine};

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let mut engine = sha512_256::Hash::engine();
    engine.input(data);
    let eng_hash = sha512_256::Hash::from_engine(engine);

    let hash = sha512_256::Hash::hash(data);
    assert_eq!(hash.as_byte_array(), eng_hash.as_byte_array());
}

fuzz_target!(|data| {
    do_test(data)
});
