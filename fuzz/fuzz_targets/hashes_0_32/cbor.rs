#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct Hmacs {
    sha1: old_bitcoin::hashes::hmac::Hmac<old_bitcoin::hashes::sha1::Hash>,
    sha512: old_bitcoin::hashes::hmac::Hmac<old_bitcoin::hashes::sha512::Hash>,
}

#[derive(Deserialize, Serialize)]
struct Main {
    hmacs: Hmacs,
    ripemd: old_bitcoin::hashes::ripemd160::Hash,
    sha2d: old_bitcoin::hashes::sha256d::Hash,
}

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    if let Ok(m) = serde_cbor::from_slice::<Main>(data) {
        let vec = serde_cbor::to_vec(&m).unwrap();
        assert_eq!(data, &vec[..]);
    }
}

fuzz_target!(|data: &[u8]| {
    do_test(data);
});
