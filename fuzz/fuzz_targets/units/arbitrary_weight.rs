#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

use bitcoin::Weight;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let w = Weight::arbitrary(&mut u);

    if let Ok(weight) = w {
        weight.to_wu();
        weight.to_kwu_ceil();
        weight.to_kwu_floor();
        weight.to_vbytes_ceil();
        weight.to_vbytes_floor();

        // Operations that take u64 as the rhs
        for operation in [Weight::checked_mul, Weight::checked_div] {
            if let Ok(val) = u.arbitrary() {
                let _ = operation(weight, val);
            } else {
                return;
            }
        }

        // Operations that take Weight as the rhs
        for operation in [Weight::checked_add, Weight::checked_sub] {
            if let Ok(val) = u.arbitrary() {
                let _ = operation(weight, val);
            } else {
                return;
            }
        }
    }

    // Constructors that return a Weight
    for constructor in [Weight::from_wu] {
        if let Ok(val) = u.arbitrary() {
            constructor(val);
        } else {
            return;
        }
    }

    // Constructors that return an Option<Weight>
    for constructor in [Weight::from_vb, Weight::from_kwu] {
        if let Ok(val) = u.arbitrary() {
            constructor(val);
        } else {
            return;
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});
