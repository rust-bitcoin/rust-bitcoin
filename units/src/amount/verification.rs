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
    // Assume we don't overflow in the actual tests.
    kani::assume(n1.checked_add(n2).is_some()); // Adding u64s doesn't overflow.
    kani::assume(Amount::from_sat(n1).is_ok());
    kani::assume(Amount::from_sat(n2).is_ok());

    let a1 = Amount::from_sat_unchecked(n1);
    let a2 = Amount::from_sat_unchecked(n2);
    kani::assume(a1.checked_add(a2).is_some()); // Adding amounts doesn't overflow.

    assert_eq!(
        Amount::from_sat_unchecked(n1) + Amount::from_sat_unchecked(n2),
        Amount::from_sat_unchecked(n1 + n2)
    );

    let mut amt = Amount::from_sat_unchecked(n1);
    amt += Amount::from_sat_unchecked(n2);
    assert_eq!(amt, Amount::from_sat_unchecked(n1 + n2));

    let max = cmp::max(n1, n2);
    let min = cmp::min(n1, n2);
    assert_eq!(
        Amount::from_sat_unchecked(max) - Amount::from_sat_unchecked(min),
        Amount::from_sat_unchecked(max - min)
    );

    let mut amt = Amount::from_sat_unchecked(max);
    amt -= Amount::from_sat_unchecked(min);
    assert_eq!(amt, Amount::from_sat_unchecked(max - min));
}

#[kani::unwind(4)]
#[kani::proof]
fn s_amount_homomorphic() {
    let n1 = kani::any::<i64>();
    let n2 = kani::any::<i64>();

    // Assume we don't overflow in the actual tests.
    kani::assume(n1.checked_add(n2).is_some()); // Adding i64s doesn't overflow.
    kani::assume(n1.checked_sub(n2).is_some()); // Subbing i64s doesn't overflow.
    kani::assume(SignedAmount::from_sat(n1).is_ok());
    kani::assume(SignedAmount::from_sat(n2).is_ok());

    let a1 = SignedAmount::from_sat_unchecked(n1);
    let a2 = SignedAmount::from_sat_unchecked(n2);
    kani::assume(a1.checked_add(a2).is_some()); // Adding amounts doesn't overflow.
    kani::assume(a1.checked_sub(a2).is_some()); // Subbing amounts doesn't overflow.

    assert_eq!(
        SignedAmount::from_sat_unchecked(n1) + SignedAmount::from_sat_unchecked(n2),
        SignedAmount::from_sat_unchecked(n1 + n2)
    );
    assert_eq!(
        SignedAmount::from_sat_unchecked(n1) - SignedAmount::from_sat_unchecked(n2),
        SignedAmount::from_sat_unchecked(n1 - n2)
    );

    let mut amt = SignedAmount::from_sat_unchecked(n1);
    amt += SignedAmount::from_sat_unchecked(n2);
    assert_eq!(amt, SignedAmount::from_sat_unchecked(n1 + n2));
    let mut amt = SignedAmount::from_sat_unchecked(n1);
    amt -= SignedAmount::from_sat_unchecked(n2);
    assert_eq!(amt, SignedAmount::from_sat_unchecked(n1 - n2));
}
