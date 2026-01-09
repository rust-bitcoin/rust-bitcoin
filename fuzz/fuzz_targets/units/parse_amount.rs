#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);

    // signed
    let samt = match data_str.parse::<bitcoin::amount::SignedAmount>() {
        Ok(amt) => amt,
        Err(_) => return,
    };
    let samt_roundtrip = match samt.to_string().parse::<bitcoin::amount::SignedAmount>() {
        Ok(amt) => amt,
        Err(_) => return,
    };
    assert_eq!(samt, samt_roundtrip);

    // unsigned
    let amt = match data_str.parse::<bitcoin::amount::Amount>() {
        Ok(amt) => amt,
        Err(_) => return,
    };
    let amt_roundtrip = match amt.to_string().parse::<bitcoin::amount::Amount>() {
        Ok(amt) => amt,
        Err(_) => return,
    };
    assert_eq!(amt, amt_roundtrip);
}

fuzz_target!(|data| {
    do_test(data);
});
