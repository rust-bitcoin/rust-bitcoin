#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};

use bitcoin::hashes::{ripemd160, sha1, sha256d, sha512, Hmac};

#[derive(Deserialize, Serialize)]
struct Hmacs {
    sha1: Hmac<sha1::Hash>,
    sha512: Hmac<sha512::Hash>,
}

#[derive(Deserialize, Serialize)]
struct Main {
    hmacs: Hmacs,
    ripemd: ripemd160::Hash,
    sha2d: sha256d::Hash,
}

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    if let Ok(m) = serde_json::from_slice::<Main>(data) {
        let vec = serde_json::to_vec(&m).unwrap();
        assert_eq!(data, &vec[..]);
    }
}

fuzz_target!(|data| {
    do_test(data)
});
