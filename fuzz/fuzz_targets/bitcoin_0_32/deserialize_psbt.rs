#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let psbt: Result<old_bitcoin::psbt::Psbt, _> = old_bitcoin::psbt::Psbt::deserialize(data);
    match psbt {
        Err(_) => {}
        Ok(psbt) => {
            let ser = old_bitcoin::psbt::Psbt::serialize(&psbt);
            let deser = old_bitcoin::psbt::Psbt::deserialize(&ser).unwrap();
            // Since the fuzz data could order psbt fields differently, we compare to our deser/ser instead of data
            assert_eq!(ser, old_bitcoin::psbt::Psbt::serialize(&deser));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    do_test(data);
});
