#![no_main]

use libfuzzer_sys::fuzz_target;

use bitcoin::hashes::{ripemd160, HashEngine};

fn do_test(data: &[u8]) {
    let mut engine = ripemd160::Hash::engine();
    engine.input(data);
    let eng_hash = ripemd160::Hash::from_engine(engine);

    let hash = ripemd160::Hash::hash(data);
    assert_eq!(hash.as_byte_array(), eng_hash.as_byte_array());
}

fuzz_target!(|data| {
    do_test(data)
});
