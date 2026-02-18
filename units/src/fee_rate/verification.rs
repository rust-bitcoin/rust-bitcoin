// SPDX-License-Identifier: CC0-1.0

//! Verification tests for the `fee_rate` module.

use super::*;

/// Verify that `from_sat_per_kwu` roundtrips through `to_sat_per_kwu_floor`
/// for all `u32` inputs: from_sat_per_kwu multiplies by 4_000,
/// to_sat_per_kwu_floor divides by 4_000 — lossless for u32 inputs.
#[kani::proof]
fn check_fee_rate_kwu_roundtrip() {
    let kwu_rate = kani::any::<u32>();
    let fee_rate = FeeRate::from_sat_per_kwu(kwu_rate);
    assert_eq!(fee_rate.to_sat_per_kwu_floor(), kwu_rate as u64);
}

/// Verify that `from_sat_per_kvb` roundtrips through `to_sat_per_kvb_floor`
/// for all `u32` inputs: from_sat_per_kvb multiplies by 1_000,
/// to_sat_per_kvb_floor divides by 1_000 — lossless for u32 inputs.
#[kani::proof]
fn check_fee_rate_kvb_roundtrip() {
    let kvb_rate = kani::any::<u32>();
    let fee_rate = FeeRate::from_sat_per_kvb(kvb_rate);
    assert_eq!(fee_rate.to_sat_per_kvb_floor(), kvb_rate as u64);
}

/// Verify that `checked_add` returns `None` exactly when u64 addition
/// overflows, and the correct value otherwise.
#[kani::proof]
fn check_fee_rate_checked_add() {
    let a = kani::any::<u64>();
    let b = kani::any::<u64>();

    let fa = FeeRate::from_sat_per_mvb(a);
    let fb = FeeRate::from_sat_per_mvb(b);
    let result = fa.checked_add(fb);

    match a.checked_add(b) {
        Some(sum) => {
            assert!(result.is_some());
            assert_eq!(result.unwrap().to_sat_per_mvb(), sum);
        }
        None => assert!(result.is_none()),
    }
}

/// Verify that `checked_sub` returns `None` exactly when a < b, and
/// `Some(a - b)` otherwise.
#[kani::proof]
fn check_fee_rate_checked_sub() {
    let a = kani::any::<u64>();
    let b = kani::any::<u64>();

    let fa = FeeRate::from_sat_per_mvb(a);
    let fb = FeeRate::from_sat_per_mvb(b);
    let result = fa.checked_sub(fb);

    if a >= b {
        assert!(result.is_some());
        assert_eq!(result.unwrap().to_sat_per_mvb(), a - b);
    } else {
        assert!(result.is_none());
    }
}
