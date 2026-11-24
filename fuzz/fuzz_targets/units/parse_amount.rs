#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);

    // signed
    if let Ok(samt) = data_str.parse::<bitcoin::amount::SignedAmount>() {
        let samt_roundtrip = samt
            .to_string()
            .parse::<bitcoin::amount::SignedAmount>()
            .expect("display output parses");
        assert_eq!(samt, samt_roundtrip);
    }

    // unsigned
    if let Ok(amt) = data_str.parse::<bitcoin::amount::Amount>() {
        let amt_roundtrip =
            amt.to_string().parse::<bitcoin::amount::Amount>().expect("display output parses");
        assert_eq!(amt, amt_roundtrip);
    }
}

fuzz_target!(|data| {
    do_test(data);
});
