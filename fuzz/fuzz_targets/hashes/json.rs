#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use bitcoin::hashes::{ripemd160, sha1, sha256d, sha512, Hash, Hmac};
use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
struct Hmacs {
    sha1: Hmac<sha1::Hash>,
    sha512: Hmac<sha512::Hash>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
struct Main {
    hmacs: Hmacs,
    ripemd: ripemd160::Hash,
    sha2d: sha256d::Hash,
}

impl<'a> arbitrary::Arbitrary<'a> for Main {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let sha1_bytes: [u8; 20] = u.arbitrary()?;
        let sha512_bytes: [u8; 64] = u.arbitrary()?;
        let ripemd_bytes: [u8; 20] = u.arbitrary()?;
        let sha2d_bytes: [u8; 32] = u.arbitrary()?;

        Ok(Self  {
            hmacs: Hmacs {
                sha1: Hmac::<sha1::Hash>::from_byte_array(sha1_bytes),
                sha512: Hmac::<sha512::Hash>::from_byte_array(sha512_bytes),
            },
            ripemd: ripemd160::Hash::from_byte_array(ripemd_bytes),
            sha2d: sha256d::Hash::from_byte_array(sha2d_bytes),
        })
    }
}

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: Main) {
    let json_string = serde_json::to_string(&data).expect("Serialization failed");
    let decoded: Main = serde_json::from_str(&json_string).expect("Deserialization failed");
    assert_eq!(data, decoded);
}

fuzz_target!(|data: Main| { do_test(data) });
