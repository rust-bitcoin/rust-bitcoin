#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;
use std::str::FromStr;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);

    // signed
    let samt = match old_bitcoin::amount::SignedAmount::from_str(&data_str) {
        Ok(amt) => amt,
        Err(_) => return,
    };
    let samt_roundtrip = match old_bitcoin::amount::SignedAmount::from_str(&samt.to_string()) {
        Ok(amt) => amt,
        Err(_) => return,
    };
    assert_eq!(samt, samt_roundtrip);

    // unsigned
    let amt = match old_bitcoin::amount::Amount::from_str(&data_str) {
        Ok(amt) => amt,
        Err(_) => return,
    };
    let amt_roundtrip = match old_bitcoin::amount::Amount::from_str(&amt.to_string()) {
        Ok(amt) => amt,
        Err(_) => return,
    };
    assert_eq!(amt, amt_roundtrip);
}

fuzz_target!(|data: &[u8]| {
    do_test(data);
});
