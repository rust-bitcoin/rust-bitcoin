// SPDX-License-Identifier: CC0-1.0

//! Verification tests for the `amount` module.

use std::cmp;

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

/// Verify that `checked_add` returns `None` exactly when sum > MAX_MONEY,
/// and `Some(sum)` otherwise.
#[kani::proof]
fn check_amount_checked_add_boundary() {
    let a_sat = kani::any::<u64>();
    let b_sat = kani::any::<u64>();

    kani::assume(Amount::from_sat(a_sat).is_ok());
    kani::assume(Amount::from_sat(b_sat).is_ok());

    let a = Amount::from_sat(a_sat).unwrap();
    let b = Amount::from_sat(b_sat).unwrap();

    let result = a.checked_add(b);
    // Both inputs are <= MAX_MONEY so u64 addition cannot overflow.
    let sum = a_sat + b_sat;
    if sum <= Amount::MAX.to_sat() {
        assert!(result.is_some());
        assert_eq!(result.unwrap().to_sat(), sum);
    } else {
        assert!(result.is_none());
    }
}

/// Verify that `checked_sub` returns `None` exactly when a < b, and
/// `Some(a - b)` otherwise.
#[kani::proof]
fn check_amount_checked_sub_boundary() {
    let a_sat = kani::any::<u64>();
    let b_sat = kani::any::<u64>();

    kani::assume(Amount::from_sat(a_sat).is_ok());
    kani::assume(Amount::from_sat(b_sat).is_ok());

    let a = Amount::from_sat(a_sat).unwrap();
    let b = Amount::from_sat(b_sat).unwrap();

    let result = a.checked_sub(b);
    if a_sat >= b_sat {
        assert!(result.is_some());
        assert_eq!(result.unwrap().to_sat(), a_sat - b_sat);
    } else {
        assert!(result.is_none());
    }
}

/// Verify `to_signed` then `to_unsigned` is a lossless roundtrip.
#[kani::proof]
fn check_amount_to_signed_roundtrip() {
    let sat = kani::any::<u64>();
    kani::assume(Amount::from_sat(sat).is_ok());

    let amount = Amount::from_sat(sat).unwrap();
    let signed = amount.to_signed();
    let back = signed.to_unsigned();

    assert!(back.is_ok());
    assert_eq!(back.unwrap(), amount);
}

/// Verify `signed_sub` never panics for any two valid amounts.
#[kani::proof]
fn check_amount_signed_sub_no_panic() {
    let a_sat = kani::any::<u64>();
    let b_sat = kani::any::<u64>();

    kani::assume(Amount::from_sat(a_sat).is_ok());
    kani::assume(Amount::from_sat(b_sat).is_ok());

    let a = Amount::from_sat(a_sat).unwrap();
    let b = Amount::from_sat(b_sat).unwrap();

    // signed_sub is documented to never overflow; verify it doesn't panic.
    let result = a.signed_sub(b);
    assert_eq!(result.to_sat(), a_sat as i64 - b_sat as i64);
}

/// Verify `SignedAmount::unsigned_abs` never panics and returns
/// the correct magnitude.
#[kani::proof]
fn check_signed_amount_unsigned_abs() {
    let sat = kani::any::<i64>();
    kani::assume(SignedAmount::from_sat(sat).is_ok());

    let amount = SignedAmount::from_sat(sat).unwrap();
    let abs_val = amount.unsigned_abs();

    assert_eq!(abs_val.to_sat(), sat.unsigned_abs());
}
