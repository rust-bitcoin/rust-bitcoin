#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

use bitcoin_fuzz::fuzz_utils::consume_random_bytes;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let mut new_data = data;
    let bytes = consume_random_bytes(&mut new_data);
    let psbt: Result<bitcoin::psbt::Psbt, _> = bitcoin::psbt::Psbt::deserialize(bytes);
    match psbt {
        Err(_) => {}
        Ok(mut psbt) => {
            let ser = bitcoin::psbt::Psbt::serialize(&psbt);
            let deser = bitcoin::psbt::Psbt::deserialize(&ser).unwrap();
            // Since the fuzz data could order psbt fields differently, we compare to our deser/ser instead of data
            assert_eq!(ser, bitcoin::psbt::Psbt::serialize(&deser));

            let new_bytes = consume_random_bytes(&mut new_data);
            let psbt_b: Result<bitcoin::psbt::Psbt, _> =
                bitcoin::psbt::Psbt::deserialize(new_bytes);
            match psbt_b {
                Err(_) => {}
                Ok(mut psbt_b) => {
                    assert_eq!(psbt_b.combine(psbt.clone()).is_ok(), psbt.combine(psbt_b).is_ok());
                }
            }
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});
