#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use bitcoin_fuzz::check_roundtrip;
use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fuzz_target!(|data: &[u8]| {
    check_roundtrip::<bitcoin::BlockHeight>(data);
});
