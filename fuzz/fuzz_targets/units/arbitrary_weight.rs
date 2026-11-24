#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use arbitrary::{Arbitrary, Unstructured};
use bitcoin::{Amount, FeeRate, Weight};
use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

const WU_PER_VB: u128 = 4;
const WU_PER_KWU: u128 = 1_000;

/// Checks against the exact result computed in `u128`. Bounds are enforced.
fn check(got: Option<Weight>, exact: Option<u128>) {
    match exact {
        Some(exact) if exact <= u128::from(u64::MAX) => {
            assert_eq!(got.map(Weight::to_wu).map(u128::from), Some(exact))
        }
        _ => assert_eq!(got, None),
    }
}

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);
    // Never fails.
    let Ok(weight) = Weight::arbitrary(&mut u) else { return };
    let wu = weight.to_wu();
    let wu128 = u128::from(wu);

    // Validate conversions to coarser units.
    assert_eq!(u128::from(weight.to_vb_floor()), wu128 / WU_PER_VB);
    assert_eq!(u128::from(weight.to_vb_ceil()), wu128.div_ceil(WU_PER_VB));
    assert_eq!(u128::from(weight.to_kwu_floor()), wu128 / WU_PER_KWU);
    assert_eq!(u128::from(weight.to_kwu_ceil()), wu128.div_ceil(WU_PER_KWU));

    // Return `None` when the weight does not fit.
    check(Weight::from_vb(wu), Some(wu128 * WU_PER_VB));
    check(Weight::from_kwu(wu), Some(wu128 * WU_PER_KWU));

    // Return `None` when the exact result does not fit.
    check(weight.checked_mul(wu), Some(wu128 * wu128));
    check(weight.checked_div(wu), wu128.checked_div(wu128));
    check(weight.checked_add(weight), Some(wu128 + wu128));
    check(weight.checked_sub(weight), Some(0));

    // Fee for this weight is the fee rounded up to the next satoshi.
    let Ok(fee_rate) = FeeRate::from_sat_per_kwu(wu).into_result() else { return };
    let exact_fee = (wu128 * wu128).div_ceil(WU_PER_KWU);
    let fee = weight.mul_by_fee_rate(fee_rate);
    if exact_fee <= u128::from(Amount::MAX.to_sat()) {
        assert_eq!(u128::from(fee.unwrap().to_sat()), exact_fee);
        assert_eq!(fee_rate.to_fee(weight), fee.unwrap());
    } else {
        assert!(fee.is_error());
        assert_eq!(fee_rate.to_fee(weight), Amount::MAX);
    }
}

fuzz_target!(|data| {
    do_test(data);
});
