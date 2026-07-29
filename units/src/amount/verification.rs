// SPDX-License-Identifier: CC0-1.0

//! Verification tests for the `amount` module.

use core::cmp;

use super::{Amount, SignedAmount};

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

    // Assume the values are within range.
    kani::assume(Amount::from_sat(n1).is_ok());
    kani::assume(Amount::from_sat(n2).is_ok());

    let sat = |sat| Amount::from_sat(sat).unwrap();

    // Assume sum is within range.
    kani::assume(sat(n1).checked_add(sat(n2)).is_some());

    assert_eq!(sat(n1) + sat(n2), sat(n1 + n2).into());

    let max = cmp::max(n1, n2);
    let min = cmp::min(n1, n2);
    assert_eq!(sat(max) - sat(min), sat(max - min).into());
}

#[kani::unwind(4)]
#[kani::proof]
fn s_amount_homomorphic() {
    let n1 = kani::any::<i64>();
    let n2 = kani::any::<i64>();

    // Assume the values are within range.
    kani::assume(SignedAmount::from_sat(n1).is_ok());
    kani::assume(SignedAmount::from_sat(n2).is_ok());

    let ssat = |ssat| SignedAmount::from_sat(ssat).unwrap();

    kani::assume(ssat(n1).checked_add(ssat(n2)).is_some()); // Adding amounts doesn't overflow.
    kani::assume(ssat(n1).checked_sub(ssat(n2)).is_some()); // Subbing amounts doesn't overflow.

    assert_eq!(ssat(n1) + ssat(n2), ssat(n1 + n2).into());
    assert_eq!(ssat(n1) - ssat(n2), ssat(n1 - n2).into());
}
