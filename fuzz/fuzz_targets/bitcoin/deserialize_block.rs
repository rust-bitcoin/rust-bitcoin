#![no_main]

use libfuzzer_sys::fuzz_target;

fn do_test(data: &[u8]) {
    let block_result: Result<bitcoin::Block, _> = bitcoin::consensus::encode::deserialize(data);

    match block_result {
        Err(_) => {}
        Ok(block) => {
            let ser = bitcoin::consensus::encode::serialize(&block);
            assert_eq!(&ser[..], data);
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});
