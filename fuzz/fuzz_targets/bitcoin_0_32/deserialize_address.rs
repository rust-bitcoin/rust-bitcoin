#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use bitcoin_fuzz::mutate::address;
use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    let addr = match data_str.parse::<bitcoin_0_32::address::Address<_>>() {
        Ok(addr) => addr.assume_checked(),
        Err(_) => return,
    };
    let encoded = addr.to_string();

    // `Display` writes the canonical encoding. base58 is case-sensitive and so round-trips
    // exactly, but bech32 accepts an all-uppercase address and always writes it back lowercase.
    if encoded != data_str {
        assert_eq!(encoded, data_str.to_lowercase());
    }

    // Whatever it wrote has to parse back to the address it was written from.
    let reparsed = encoded
        .parse::<bitcoin_0_32::address::Address<_>>()
        .expect("an encoded address should parse")
        .assume_checked();
    assert_eq!(reparsed, addr);
}

fuzz_target!(|data: &[u8]| {
    do_test(data);
});

libfuzzer_sys::fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    address::mutate_payload(data, size, max_size, seed, libfuzzer_sys::fuzzer_mutate)
});
