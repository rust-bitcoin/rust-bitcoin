#![no_main]

use libfuzzer_sys::fuzz_target;

use bitcoin::hashes::{sha512, HashEngine};

fn do_test(data: &[u8]) {
    let mut engine = sha512::Hash::engine();
    engine.input(data);
    let eng_hash = sha512::Hash::from_engine(engine);

    let hash = sha512::Hash::hash(data);
    assert_eq!(hash.as_byte_array(), eng_hash.as_byte_array());
}

fuzz_target!(|data| {
    do_test(data)
});
