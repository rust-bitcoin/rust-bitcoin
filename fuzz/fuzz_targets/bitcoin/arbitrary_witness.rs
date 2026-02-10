#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::Witness;
use bitcoin::blockdata::witness::WitnessExt;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);

    if let Ok(mut witness) = Witness::arbitrary(&mut u) {
        let serialized = serialize(&witness);

        let _ = witness.witness_script();
        let _ = witness.taproot_leaf_script();

        let deserialized: Result<Witness, _> = deserialize(serialized.as_slice());
        assert_eq!(deserialized.unwrap(), witness);

        if let Ok(element_bytes) = Vec::<u8>::arbitrary(&mut u) {
            witness.push(element_bytes.as_slice());
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});
