// SPDX-License-Identifier: CC0-1.0

//! Implements `FeeRate` and associated features.

#[cfg(feature = "serde")]
pub mod serde;

use core::num::NonZeroU64;
use core::ops;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

/// Fee rate.
///
/// This is an integer newtype representing fee rate in `sat/kwu`. It provides protection
/// against mixing up the types as well as basic formatting features.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FeeRate(u64);

impl FeeRate {
    /// 0 sat/kwu.
    ///
    /// Equivalent to [`MIN`](Self::MIN), may better express intent in some contexts.
    pub const ZERO: FeeRate = FeeRate::from_sat_per_kwu(0);

    /// Minimum possible value (0 sat/kwu).
    ///
    /// Equivalent to [`ZERO`](Self::ZERO), may better express intent in some contexts.
    pub const MIN: FeeRate = FeeRate::ZERO;

    /// Maximum possible value.
    pub const MAX: FeeRate = FeeRate::from_sat_per_kwu(u64::MAX);

    /// Minimum fee rate required to broadcast a transaction.
    ///
    /// The value matches the default Bitcoin Core policy at the time of library release.
    pub const BROADCAST_MIN: FeeRate = FeeRate::from_sat_per_vb_u32(1);

    /// Fee rate used to compute dust amount.
    pub const DUST: FeeRate = FeeRate::from_sat_per_vb_u32(3);

    /// Constructs a new [`FeeRate`] from satoshis per 1000 weight units.
    pub const fn from_sat_per_kwu(sat_kwu: u64) -> Self { FeeRate(sat_kwu) }

    /// Constructs a new [`FeeRate`] from satoshis per virtual bytes.
    ///
    /// # Errors
    ///
    /// Returns [`None`] on arithmetic overflow.
    pub fn from_sat_per_vb(sat_vb: u64) -> Option<Self> {
        // 1 vb == 4 wu
        // 1 sat/vb == 1/4 sat/wu
        // sat/vb * 1000 / 4 == sat/kwu
        Some(FeeRate::from_sat_per_kwu(sat_vb.checked_mul(1000 / 4)?))
    }

    /// Constructs a new [`FeeRate`] from satoshis per virtual bytes.
    pub const fn from_sat_per_vb_u32(sat_vb: u32) -> Self {
        let sat_vb = sat_vb as u64; // No `Into` in const context.
        FeeRate::from_sat_per_kwu(sat_vb * (1000 / 4))
    }

    /// Constructs a new [`FeeRate`] from satoshis per kilo virtual bytes (1,000 vbytes).
    pub const fn from_sat_per_kvb(sat_kvb: u64) -> Self { FeeRate::from_sat_per_kwu(sat_kvb / 4) }

    /// Returns raw fee rate.
    pub const fn to_sat_per_kwu(self) -> u64 { self.0 }

    /// Converts to sat/vB rounding down.
    pub const fn to_sat_per_vb_floor(self) -> u64 { self.to_sat_per_kwu() / (1000 / 4) }

    /// Converts to sat/vB rounding up.
    pub const fn to_sat_per_vb_ceil(self) -> u64 {
        (self.to_sat_per_kwu() + (1000 / 4 - 1)) / (1000 / 4)
    }

    /// Checked multiplication.
    ///
    /// Computes `self * rhs` returning [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_mul(self, rhs: u64) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat_per_kwu().checked_mul(rhs) {
            Some(res) => Some(Self::from_sat_per_kwu(res)),
            None => None,
        }
    }

    /// Checked division.
    ///
    /// Computes `self / rhs` returning [`None`] if `rhs == 0`.
    #[must_use]
    pub const fn checked_div(self, rhs: u64) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat_per_kwu().checked_div(rhs) {
            Some(res) => Some(Self::from_sat_per_kwu(res)),
            None => None,
        }
    }

    /// Checked addition.
    ///
    /// Computes `self + rhs` returning [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_add(self, rhs: FeeRate) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat_per_kwu().checked_add(rhs.to_sat_per_kwu()) {
            Some(res) => Some(Self::from_sat_per_kwu(res)),
            None => None,
        }
    }

    /// Checked subtraction.
    ///
    /// Computes `self - rhs` returning [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_sub(self, rhs: FeeRate) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat_per_kwu().checked_sub(rhs.to_sat_per_kwu()) {
            Some(res) => Some(Self::from_sat_per_kwu(res)),
            None => None,
        }
    }
}

crate::internal_macros::impl_op_for_references! {
    impl ops::Add<FeeRate> for FeeRate {
        type Output = FeeRate;

        fn add(self, rhs: FeeRate) -> Self::Output { FeeRate::from_sat_per_kwu(self.to_sat_per_kwu() + rhs.to_sat_per_kwu()) }
    }

    impl ops::Sub<FeeRate> for FeeRate {
        type Output = FeeRate;

        fn sub(self, rhs: FeeRate) -> Self::Output { FeeRate::from_sat_per_kwu(self.to_sat_per_kwu() - rhs.to_sat_per_kwu()) }
    }

    impl ops::Div<NonZeroU64> for FeeRate {
        type Output = FeeRate;

        fn div(self, rhs: NonZeroU64) -> Self::Output{ Self::from_sat_per_kwu(self.to_sat_per_kwu() / rhs.get()) }
    }
}
crate::internal_macros::impl_add_assign!(FeeRate);
crate::internal_macros::impl_sub_assign!(FeeRate);

impl core::iter::Sum for FeeRate {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        FeeRate::from_sat_per_kwu(iter.map(FeeRate::to_sat_per_kwu).sum())
    }
}

impl<'a> core::iter::Sum<&'a FeeRate> for FeeRate {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a FeeRate>,
    {
        FeeRate::from_sat_per_kwu(iter.map(|f| FeeRate::to_sat_per_kwu(*f)).sum())
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FeeRate {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=4)?;
        match choice {
            0 => Ok(FeeRate::MIN),
            1 => Ok(FeeRate::BROADCAST_MIN),
            2 => Ok(FeeRate::DUST),
            3 => Ok(FeeRate::MAX),
            _ => Ok(FeeRate::from_sat_per_kwu(u64::arbitrary(u)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU64;

    use super::*;

    #[test]
    #[allow(clippy::op_ref)]
    fn feerate_div_nonzero() {
        let rate = FeeRate::from_sat_per_kwu(200);
        let divisor = NonZeroU64::new(2).unwrap();
        assert_eq!(rate / divisor, FeeRate::from_sat_per_kwu(100));
        assert_eq!(&rate / &divisor, FeeRate::from_sat_per_kwu(100));
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn addition() {
        let one = FeeRate::from_sat_per_kwu(1);
        let two = FeeRate::from_sat_per_kwu(2);
        let three = FeeRate::from_sat_per_kwu(3);

        assert!(one + two == three);
        assert!(&one + two == three);
        assert!(one + &two == three);
        assert!(&one + &two == three);
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn subtract() {
        let three = FeeRate::from_sat_per_kwu(3);
        let seven = FeeRate::from_sat_per_kwu(7);
        let ten = FeeRate::from_sat_per_kwu(10);

        assert_eq!(ten - seven, three);
        assert_eq!(&ten - seven, three);
        assert_eq!(ten - &seven, three);
        assert_eq!(&ten - &seven, three);
    }

    #[test]
    fn add_assign() {
        let mut f = FeeRate::from_sat_per_kwu(1);
        f += FeeRate::from_sat_per_kwu(2);
        assert_eq!(f, FeeRate::from_sat_per_kwu(3));

        let mut f = FeeRate::from_sat_per_kwu(1);
        f += &FeeRate::from_sat_per_kwu(2);
        assert_eq!(f, FeeRate::from_sat_per_kwu(3));
    }

    #[test]
    fn sub_assign() {
        let mut f = FeeRate::from_sat_per_kwu(3);
        f -= FeeRate::from_sat_per_kwu(2);
        assert_eq!(f, FeeRate::from_sat_per_kwu(1));

        let mut f = FeeRate::from_sat_per_kwu(3);
        f -= &FeeRate::from_sat_per_kwu(2);
        assert_eq!(f, FeeRate::from_sat_per_kwu(1));
    }

    #[test]
    fn checked_add() {
        let one = FeeRate::from_sat_per_kwu(1);
        let two = FeeRate::from_sat_per_kwu(2);
        let three = FeeRate::from_sat_per_kwu(3);

        assert_eq!(one.checked_add(two).unwrap(), three);

        let fee_rate = FeeRate::from_sat_per_kwu(u64::MAX).checked_add(one);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn checked_sub() {
        let one = FeeRate::from_sat_per_kwu(1);
        let two = FeeRate::from_sat_per_kwu(2);
        let three = FeeRate::from_sat_per_kwu(3);
        assert_eq!(three.checked_sub(two).unwrap(), one);

        let fee_rate = FeeRate::ZERO.checked_sub(one);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn fee_rate_const() {
        assert_eq!(FeeRate::ZERO.to_sat_per_kwu(), 0);
        assert_eq!(FeeRate::MIN.to_sat_per_kwu(), u64::MIN);
        assert_eq!(FeeRate::MAX.to_sat_per_kwu(), u64::MAX);
        assert_eq!(FeeRate::BROADCAST_MIN.to_sat_per_kwu(), 250);
        assert_eq!(FeeRate::DUST.to_sat_per_kwu(), 750);
    }

    #[test]
    fn fee_rate_from_sat_per_vb() {
        let fee_rate = FeeRate::from_sat_per_vb(10).expect("expected feerate in sat/kwu");
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(2500));
    }

    #[test]
    fn fee_rate_from_sat_per_kvb() {
        let fee_rate = FeeRate::from_sat_per_kvb(11);
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(2));
    }

    #[test]
    fn fee_rate_from_sat_per_vb_overflow() {
        let fee_rate = FeeRate::from_sat_per_vb(u64::MAX);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn from_sat_per_vb_u32() {
        let fee_rate = FeeRate::from_sat_per_vb_u32(10);
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(2500));
    }

    #[test]
    #[cfg(debug_assertions)]
    fn from_sat_per_vb_u32_cannot_panic() { FeeRate::from_sat_per_vb_u32(u32::MAX); }

    #[test]
    fn raw_feerate() {
        let fee_rate = FeeRate::from_sat_per_kwu(749);
        assert_eq!(fee_rate.to_sat_per_kwu(), 749);
        assert_eq!(fee_rate.to_sat_per_vb_floor(), 2);
        assert_eq!(fee_rate.to_sat_per_vb_ceil(), 3);
    }

    #[test]
    fn checked_mul() {
        let fee_rate =
            FeeRate::from_sat_per_kwu(10).checked_mul(10).expect("expected feerate in sat/kwu");
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(100));

        let fee_rate = FeeRate::from_sat_per_kwu(10).checked_mul(u64::MAX);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn checked_div() {
        let fee_rate =
            FeeRate::from_sat_per_kwu(10).checked_div(10).expect("expected feerate in sat/kwu");
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(1));

        let fee_rate = FeeRate::from_sat_per_kwu(10).checked_div(0);
        assert!(fee_rate.is_none());
    }
}
