#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured, Result};

#[derive(Debug)]
struct HashPair {
    a: [u8; 16],
    b: [u8; 16],
}

impl<'a> Arbitrary<'a> for HashPair {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        Ok(Self {
            a: u.arbitrary()?,
            b: u.arbitrary()?,
        })
    }
}

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(pair: HashPair) {
    let result = chacha20_poly1305::constant_time_eq(&pair.a, &pair.b);
    let expected = pair.a == pair.b;
    assert_eq!(result, expected);
}

fuzz_target!(|pair: HashPair| {
    do_test(pair);
});
