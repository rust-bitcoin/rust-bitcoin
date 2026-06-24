#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    let addr = match data_str.parse::<bitcoin_0_32::address::Address<_>>() {
        Ok(addr) => addr.assume_checked(),
        Err(_) => return,
    };
    assert_eq!(addr.to_string(), data_str);
}

fuzz_target!(|data: &[u8]| {
    do_test(data);
});
