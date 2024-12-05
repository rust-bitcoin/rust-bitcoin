// SPDX-License-Identifier: CC0-1.0

//! Verification tests for the `amount` module.

use std::cmp;

use super::*;

// Note regarding the `unwind` parameter: this defines how many iterations
// of loops kani will unwind before handing off to the SMT solver. Basically
// it should be set as low as possible such that Kani still succeeds (doesn't
// return "undecidable").
//
// There is more info here: https://model-checking.github.io/kani/tutorial-loop-unwinding.html
//
// Unfortunately what it means to "loop" is pretty opaque ... in this case
// there appear to be loops in memcmp, which I guess comes from assert_eq!,
// though I didn't see any failures until I added the to_signed() test.
// Further confusing the issue, a value of 2 works fine on my system, but on
// CI it fails, so we need to set it higher.
#[kani::unwind(4)]
#[kani::proof]
fn u_amount_homomorphic() {
    let n1 = kani::any::<u64>();
    let n2 = kani::any::<u64>();
    kani::assume(n1.checked_add(n2).is_some()); // assume we don't overflow in the actual test
    assert_eq!(Amount::from_sat_unchecked(n1) + Amount::from_sat_unchecked(n2), Amount::from_sat_unchecked(n1 + n2));

    let mut amt = Amount::from_sat_unchecked(n1);
    amt += Amount::from_sat_unchecked(n2);
    assert_eq!(amt, Amount::from_sat_unchecked(n1 + n2));

    let max = cmp::max(n1, n2);
    let min = cmp::min(n1, n2);
    assert_eq!(Amount::from_sat_unchecked(max) - Amount::from_sat_unchecked(min), Amount::from_sat_unchecked(max - min));

    let mut amt = Amount::from_sat_unchecked(max);
    amt -= Amount::from_sat_unchecked(min);
    assert_eq!(amt, Amount::from_sat_unchecked(max - min));

    assert_eq!(
        Amount::from_sat_unchecked(n1).to_signed(),
        if n1 <= i64::MAX as u64 {
            Ok(SignedAmount::from_sat(n1.try_into().unwrap()))
        } else {
            Err(OutOfRangeError::too_big(true))
        },
    );
}

#[kani::unwind(4)]
#[kani::proof]
fn u_amount_homomorphic_checked() {
    let n1 = kani::any::<u64>();
    let n2 = kani::any::<u64>();
    assert_eq!(
        Amount::from_sat_unchecked(n1).checked_add(Amount::from_sat_unchecked(n2)),
        n1.checked_add(n2).map(Amount::from_sat_unchecked),
    );
    assert_eq!(
        Amount::from_sat_unchecked(n1).checked_sub(Amount::from_sat_unchecked(n2)),
        n1.checked_sub(n2).map(Amount::from_sat_unchecked),
    );
}

#[kani::unwind(4)]
#[kani::proof]
fn s_amount_homomorphic() {
    let n1 = kani::any::<i64>();
    let n2 = kani::any::<i64>();
    kani::assume(n1.checked_add(n2).is_some()); // assume we don't overflow in the actual test
    kani::assume(n1.checked_sub(n2).is_some()); // assume we don't overflow in the actual test
    assert_eq!(
        SignedAmount::from_sat(n1) + SignedAmount::from_sat(n2),
        SignedAmount::from_sat(n1 + n2)
    );
    assert_eq!(
        SignedAmount::from_sat(n1) - SignedAmount::from_sat(n2),
        SignedAmount::from_sat(n1 - n2)
    );

    let mut amt = SignedAmount::from_sat(n1);
    amt += SignedAmount::from_sat(n2);
    assert_eq!(amt, SignedAmount::from_sat(n1 + n2));
    let mut amt = SignedAmount::from_sat(n1);
    amt -= SignedAmount::from_sat(n2);
    assert_eq!(amt, SignedAmount::from_sat(n1 - n2));

    assert_eq!(
        SignedAmount::from_sat(n1).to_unsigned(),
        if n1 >= 0 {
            Ok(Amount::from_sat_unchecked(n1.try_into().unwrap()))
        } else {
            Err(OutOfRangeError { is_signed: false, is_greater_than_max: false })
        },
    );
}

#[kani::unwind(4)]
#[kani::proof]
fn s_amount_homomorphic_checked() {
    let n1 = kani::any::<i64>();
    let n2 = kani::any::<i64>();
    assert_eq!(
        SignedAmount::from_sat(n1).checked_add(SignedAmount::from_sat(n2)),
        n1.checked_add(n2).map(SignedAmount::from_sat),
    );
    assert_eq!(
        SignedAmount::from_sat(n1).checked_sub(SignedAmount::from_sat(n2)),
        n1.checked_sub(n2).map(SignedAmount::from_sat),
    );

    assert_eq!(
        SignedAmount::from_sat(n1).positive_sub(SignedAmount::from_sat(n2)),
        if n1 >= 0 && n2 >= 0 && n1 >= n2 { Some(SignedAmount::from_sat(n1 - n2)) } else { None },
    );
}
