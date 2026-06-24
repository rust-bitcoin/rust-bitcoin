#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct Hmacs {
    sha1: bitcoin_0_32::hashes::hmac::Hmac<bitcoin_0_32::hashes::sha1::Hash>,
    sha512: bitcoin_0_32::hashes::hmac::Hmac<bitcoin_0_32::hashes::sha512::Hash>,
}

#[derive(Deserialize, Serialize)]
struct Main {
    hmacs: Hmacs,
    ripemd: bitcoin_0_32::hashes::ripemd160::Hash,
    sha2d: bitcoin_0_32::hashes::sha256d::Hash,
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
