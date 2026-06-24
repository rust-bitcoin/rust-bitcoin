#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let psbt: Result<bitcoin_0_32::psbt::Psbt, _> = bitcoin_0_32::psbt::Psbt::deserialize(data);
    match psbt {
        Err(_) => {}
        Ok(psbt) => {
            let ser = bitcoin_0_32::psbt::Psbt::serialize(&psbt);
            let deser = bitcoin_0_32::psbt::Psbt::deserialize(&ser).unwrap();
            // Since the fuzz data could order psbt fields differently, we compare to our deser/ser instead of data
            assert_eq!(ser, bitcoin_0_32::psbt::Psbt::serialize(&deser));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    do_test(data);
});
