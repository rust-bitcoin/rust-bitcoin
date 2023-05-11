// SPDX-License-Identifier: CC0-1.0

//! Implements `FeeRate` and assoctiated features.

use core::fmt;
use core::ops::{Div, Mul};

use super::Weight;
use crate::prelude::*;
use crate::Amount;

/// Represents fee rate.
///
/// This is an integer newtype representing fee rate in `sat/kwu`. It provides protection against mixing
/// up the types as well as basic formatting features.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct FeeRate(u64);

impl FeeRate {
    /// 0 sat/kwu.
    ///
    /// Equivalent to [`MIN`](Self::MIN), may better express intent in some contexts.
    pub const ZERO: FeeRate = FeeRate(0);

    /// Minimum possible value (0 sat/kwu).
    ///
    /// Equivalent to [`ZERO`](Self::ZERO), may better express intent in some contexts.
    pub const MIN: FeeRate = FeeRate::ZERO;

    /// Maximum possible value.
    pub const MAX: FeeRate = FeeRate(u64::MAX);

    /// Minimum fee rate required to broadcast a transaction.
    ///
    /// The value matches the default Bitcoin Core policy at the time of library release.
    pub const BROADCAST_MIN: FeeRate = FeeRate::from_sat_per_vb_unchecked(1);

    /// Fee rate used to compute dust amount.
    pub const DUST: FeeRate = FeeRate::from_sat_per_vb_unchecked(3);

    /// Constructs `FeeRate` from satoshis per 1000 weight units.
    pub const fn from_sat_per_kwu(sat_kwu: u64) -> Self { FeeRate(sat_kwu) }

    /// Constructs `FeeRate` from satoshis per virtual bytes.
    ///
    /// # Errors
    ///
    /// Returns `None` on arithmetic overflow.
    pub fn from_sat_per_vb(sat_vb: u64) -> Option<Self> {
        // 1 vb == 4 wu
        // 1 sat/vb == 1/4 sat/wu
        // sat_vb sat/vb * 1000 / 4 == sat/kwu
        Some(FeeRate(sat_vb.checked_mul(1000 / 4)?))
    }

    /// Constructs `FeeRate` from satoshis per virtual bytes without overflow check.
    pub const fn from_sat_per_vb_unchecked(sat_vb: u64) -> Self { FeeRate(sat_vb * (1000 / 4)) }

    /// Returns raw fee rate.
    ///
    /// Can be used instead of `into()` to avoid inference issues.
    pub const fn to_sat_per_kwu(self) -> u64 { self.0 }

    /// Converts to sat/vB rounding down.
    pub const fn to_sat_per_vb_floor(self) -> u64 { self.0 / (1000 / 4) }

    /// Converts to sat/vB rounding up.
    pub const fn to_sat_per_vb_ceil(self) -> u64 { (self.0 + (1000 / 4 - 1)) / (1000 / 4) }

    /// Checked multiplication.
    ///
    /// Computes `self * rhs` returning `None` if overflow occurred.
    pub fn checked_mul(self, rhs: u64) -> Option<Self> { self.0.checked_mul(rhs).map(Self) }

    /// Checked division.
    ///
    /// Computes `self / rhs` returning `None` if `rhs == 0`.
    pub fn checked_div(self, rhs: u64) -> Option<Self> { self.0.checked_div(rhs).map(Self) }
}

/// Alternative will display the unit.
impl fmt::Display for FeeRate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "{} sat/kwu", self.0)
        } else {
            fmt::Display::fmt(&self.0, f)
        }
    }
}

impl From<FeeRate> for u64 {
    fn from(value: FeeRate) -> Self { value.to_sat_per_kwu() }
}

/// Computes ceiling so that fee computation is conservative.
impl Mul<FeeRate> for Weight {
    type Output = Option<Amount>;

    fn mul(self, rhs: FeeRate) -> Self::Output {
        rhs.to_sat_per_kwu().checked_mul(self.to_wu()).map(|s| Amount::from_sat((s + 999) / 1_000))
    }
}

impl Div<Weight> for Amount {
    type Output = Option<FeeRate>;

    fn div(self, rhs: Weight) -> Self::Output {
        self.to_sat().checked_mul(1_000).map(|s| FeeRate(s / rhs.to_wu()))
    }
}

crate::parse::impl_parse_str_from_int_infallible!(FeeRate, u64, from_sat_per_kwu);

#[cfg(test)]
mod tests {
    use std::u64;

    use super::*;

    #[test]
    fn fee_rate_const_test() {
        assert_eq!(0, FeeRate::ZERO.to_sat_per_kwu());
        assert_eq!(u64::MIN, FeeRate::MIN.to_sat_per_kwu());
        assert_eq!(u64::MAX, FeeRate::MAX.to_sat_per_kwu());
        assert_eq!(250, FeeRate::BROADCAST_MIN.to_sat_per_kwu());
        assert_eq!(750, FeeRate::DUST.to_sat_per_kwu());
    }

    #[test]
    fn fee_rate_from_sat_per_vb_test() {
        let fee_rate = FeeRate::from_sat_per_vb(10).expect("expected feerate in sat/kwu");
        assert_eq!(FeeRate(2500), fee_rate);
    }

    #[test]
    fn fee_rate_from_sat_per_vb_overflow_test() {
        let fee_rate = FeeRate::from_sat_per_vb(u64::MAX);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn from_sat_per_vb_unchecked_test() {
        let fee_rate = FeeRate::from_sat_per_vb_unchecked(10);
        assert_eq!(FeeRate(2500), fee_rate);
    }

    #[test]
    #[should_panic]
    fn from_sat_per_vb_unchecked_panic_test() { FeeRate::from_sat_per_vb_unchecked(u64::MAX); }

    #[test]
    fn raw_feerate_test() {
        let fee_rate = FeeRate(333);
        assert_eq!(333, fee_rate.to_sat_per_kwu());
        assert_eq!(1, fee_rate.to_sat_per_vb_floor());
        assert_eq!(2, fee_rate.to_sat_per_vb_ceil());
    }

    #[test]
    fn checked_mul_test() {
        let fee_rate = FeeRate(10).checked_mul(10).expect("expected feerate in sat/kwu");
        assert_eq!(FeeRate(100), fee_rate);

        let fee_rate = FeeRate(10).checked_mul(u64::MAX);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn checked_div_test() {
        let fee_rate = FeeRate(10).checked_div(10).expect("expected feerate in sat/kwu");
        assert_eq!(FeeRate(1), fee_rate);

        let fee_rate = FeeRate(10).checked_div(0);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn weight_mul_feerate_trait_test() {
        let fee_rate = FeeRate(10);
        let weight = Weight::from_wu(1_000);

        let product: Option<Amount> = weight * fee_rate;
        assert_eq!(Amount::from_sat(10), product.unwrap());
    }

    #[test]
    fn weight_mul_feerate_trait_overflow_test() {
        let fee_rate = FeeRate(u64::MAX);
        let weight = Weight::from_wu(1_000);

        let product: Option<Amount> = weight * fee_rate;
        assert_eq!(None, product);
    }

    #[test]
    fn weight_div_amount_trait_test() {
        let weight = Weight::from_wu(1_000);
        let amount = Amount::from_sat(10);

        let quotient: FeeRate = (amount / weight).unwrap();
        assert_eq!(FeeRate(10), quotient);
    }

    #[test]
    fn weight_div_amount_trait_overflow_test() {
        let weight = Weight::from_wu(1_000);
        let amount = Amount::from_sat(u64::MAX);

        let quotient = amount / weight;
        assert_eq!(None, quotient);
    }
}
