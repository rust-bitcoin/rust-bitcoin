#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let script_result: Result<bitcoin::ScriptPubKeyBuf, _> =
        bitcoin::encoding::decode_from_slice(data);

    match script_result {
        Err(_) => {}
        Ok(script) => {
            let ser = bitcoin::encoding::encode_to_vec(script.as_script());
            assert_eq!(&ser[..], data);
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});
