#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let tx_result: Result<bitcoin::Transaction, _> = bitcoin::consensus::encode::deserialize(data);

    match tx_result {
        Err(_) => {}
        Ok(tx) => {
            let ser = bitcoin::consensus::encode::serialize(&tx);
            assert_eq!(&ser[..], data);
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});
