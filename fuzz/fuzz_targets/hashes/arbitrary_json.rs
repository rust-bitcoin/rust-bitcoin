#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use arbitrary::{Arbitrary, Unstructured};
use bitcoin::hashes::{ripemd160, sha1, sha256d, sha512, Hmac};
use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct Hmacs {
    sha1: Hmac<sha1::Hash>,
    sha512: Hmac<sha512::Hash>,
}

impl<'a> Arbitrary<'a> for Hmacs {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { sha1: u.arbitrary()?, sha512: u.arbitrary()? })
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct Main {
    hmacs: Hmacs,
    ripemd: ripemd160::Hash,
    sha2d: sha256d::Hash,
}

impl<'a> Arbitrary<'a> for Main {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { hmacs: u.arbitrary()?, ripemd: u.arbitrary()?, sha2d: u.arbitrary()? })
    }
}

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: Main) {
    let vec = serde_json::to_vec(&data).unwrap();
    let reparsed = serde_json::from_slice::<Main>(&vec).unwrap();
    assert_eq!(reparsed, data);
}

fuzz_target!(|data: Main| { do_test(data) });
