// SPDX-License-Identifier: CC0-1.0

//! Implements `FeeRate` and associated features.

#[cfg(feature = "serde")]
pub mod serde;

use core::num::NonZeroU64;
use core::ops;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

mod encapsulate {
    /// Fee rate.
    ///
    /// This is an integer newtype representing fee rate. It provides protection
    /// against mixing up the types, conversion functions, and basic formatting.
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
    pub struct FeeRate(u64);

    impl FeeRate {
        /// Constructs a new [`FeeRate`] from satoshis per 1,000,000 virtual bytes.
        pub(crate) const fn from_sat_per_mvb(sat_mvb: u64) -> Self { Self(sat_mvb) }

        /// Converts to sat/MvB.
        pub(crate) const fn to_sat_per_mvb(self) -> u64 { self.0 }
    }
}
#[doc(inline)]
pub use encapsulate::FeeRate;

impl FeeRate {
    /// The zero fee rate.
    ///
    /// Equivalent to [`MIN`](Self::MIN), may better express intent in some contexts.
    pub const ZERO: FeeRate = FeeRate::from_sat_per_mvb(0);

    /// The minimum possible value.
    ///
    /// Equivalent to [`ZERO`](Self::ZERO), may better express intent in some contexts.
    pub const MIN: FeeRate = FeeRate::ZERO;

    /// The maximum possible value.
    pub const MAX: FeeRate = FeeRate::from_sat_per_mvb(u64::MAX);

    /// The minimum fee rate required to broadcast a transaction.
    ///
    /// The value matches the default Bitcoin Core policy at the time of library release.
    pub const BROADCAST_MIN: FeeRate = FeeRate::from_sat_per_vb_u32(1);

    /// The fee rate used to compute dust amount.
    pub const DUST: FeeRate = FeeRate::from_sat_per_vb_u32(3);

    /// Constructs a new [`FeeRate`] from satoshis per 1000 weight units,
    /// returning `None` if overflow occurred.
    pub const fn from_sat_per_kwu(sat_kwu: u64) -> Option<Self> {
        // No `map()` in const context.
        match sat_kwu.checked_mul(4_000) {
            Some(fee_rate) => Some(FeeRate::from_sat_per_mvb(fee_rate)),
            None => None,
        }
    }

    /// Constructs a new [`FeeRate`] from satoshis per virtual byte,
    /// returning `None` if overflow occurred.
    pub const fn from_sat_per_vb(sat_vb: u64) -> Option<Self> {
        // No `map()` in const context.
        match sat_vb.checked_mul(1_000_000) {
            Some(fee_rate) => Some(FeeRate::from_sat_per_mvb(fee_rate)),
            None => None,
        }
    }

    /// Constructs a new [`FeeRate`] from satoshis per virtual bytes.
    pub const fn from_sat_per_vb_u32(sat_vb: u32) -> Self {
        let sat_vb = sat_vb as u64; // No `Into` in const context.
        FeeRate::from_sat_per_mvb(sat_vb * 1_000_000)
    }

    /// Constructs a new [`FeeRate`] from satoshis per kilo virtual bytes (1,000 vbytes),
    /// returning `None` if overflow occurred.
    pub const fn from_sat_per_kvb(sat_kvb: u64) -> Option<Self> {
        // No `map()` in const context.
        match sat_kvb.checked_mul(1_000) {
            Some(fee_rate) => Some(FeeRate::from_sat_per_mvb(fee_rate)),
            None => None,
        }
    }

    /// Converts to sat/kwu rounding down.
    pub const fn to_sat_per_kwu_floor(self) -> u64 { self.to_sat_per_mvb() / 4_000 }

    /// Converts to sat/kwu rounding up.
    pub const fn to_sat_per_kwu_ceil(self) -> u64 { (self.to_sat_per_mvb() + 3_999) / 4_000 }

    /// Converts to sat/vB rounding down.
    pub const fn to_sat_per_vb_floor(self) -> u64 { self.to_sat_per_mvb() / 1_000_000 }

    /// Converts to sat/vB rounding up.
    pub const fn to_sat_per_vb_ceil(self) -> u64 { (self.to_sat_per_mvb() + 999_999) / 1_000_000 }

    /// Converts to sat/kvb rounding down.
    pub const fn to_sat_per_kvb_floor(self) -> u64 { self.to_sat_per_mvb() / 1_000 }

    /// Converts to sat/kvb rounding up.
    pub const fn to_sat_per_kvb_ceil(self) -> u64 { (self.to_sat_per_mvb() + 999) / 1_000 }

    /// Checked multiplication.
    ///
    /// Computes `self * rhs`, returning [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_mul(self, rhs: u64) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat_per_mvb().checked_mul(rhs) {
            Some(res) => Some(Self::from_sat_per_mvb(res)),
            None => None,
        }
    }

    /// Checked division.
    ///
    /// Computes `self / rhs` returning [`None`] if `rhs == 0`.
    #[must_use]
    pub const fn checked_div(self, rhs: u64) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat_per_mvb().checked_div(rhs) {
            Some(res) => Some(Self::from_sat_per_mvb(res)),
            None => None,
        }
    }

    /// Checked addition.
    ///
    /// Computes `self + rhs` returning [`None`] is case of overflow.
    #[must_use]
    pub const fn checked_add(self, rhs: FeeRate) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat_per_mvb().checked_add(rhs.to_sat_per_mvb()) {
            Some(res) => Some(Self::from_sat_per_mvb(res)),
            None => None,
        }
    }

    /// Checked subtraction.
    ///
    /// Computes `self - rhs`, returning [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_sub(self, rhs: FeeRate) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat_per_mvb().checked_sub(rhs.to_sat_per_mvb()) {
            Some(res) => Some(Self::from_sat_per_mvb(res)),
            None => None,
        }
    }
}

crate::internal_macros::impl_op_for_references! {
    impl ops::Add<FeeRate> for FeeRate {
        type Output = FeeRate;

        fn add(self, rhs: FeeRate) -> Self::Output { FeeRate::from_sat_per_mvb(self.to_sat_per_mvb() + rhs.to_sat_per_mvb()) }
    }

    impl ops::Sub<FeeRate> for FeeRate {
        type Output = FeeRate;

        fn sub(self, rhs: FeeRate) -> Self::Output { FeeRate::from_sat_per_mvb(self.to_sat_per_mvb() - rhs.to_sat_per_mvb()) }
    }

    impl ops::Div<NonZeroU64> for FeeRate {
        type Output = FeeRate;

        fn div(self, rhs: NonZeroU64) -> Self::Output{ Self::from_sat_per_mvb(self.to_sat_per_mvb() / rhs.get()) }
    }
}
crate::internal_macros::impl_add_assign!(FeeRate);
crate::internal_macros::impl_sub_assign!(FeeRate);

impl core::iter::Sum for FeeRate {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        FeeRate::from_sat_per_mvb(iter.map(FeeRate::to_sat_per_mvb).sum())
    }
}

impl<'a> core::iter::Sum<&'a FeeRate> for FeeRate {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a FeeRate>,
    {
        FeeRate::from_sat_per_mvb(iter.map(|f| FeeRate::to_sat_per_mvb(*f)).sum())
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
            _ => Ok(FeeRate::from_sat_per_mvb(u64::arbitrary(u)?)),
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
        let rate = FeeRate::from_sat_per_kwu(200).unwrap();
        let divisor = NonZeroU64::new(2).unwrap();
        assert_eq!(rate / divisor, FeeRate::from_sat_per_kwu(100).unwrap());
        assert_eq!(&rate / &divisor, FeeRate::from_sat_per_kwu(100).unwrap());
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn addition() {
        let one = FeeRate::from_sat_per_kwu(1).unwrap();
        let two = FeeRate::from_sat_per_kwu(2).unwrap();
        let three = FeeRate::from_sat_per_kwu(3).unwrap();

        assert!(one + two == three);
        assert!(&one + two == three);
        assert!(one + &two == three);
        assert!(&one + &two == three);
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn subtract() {
        let three = FeeRate::from_sat_per_kwu(3).unwrap();
        let seven = FeeRate::from_sat_per_kwu(7).unwrap();
        let ten = FeeRate::from_sat_per_kwu(10).unwrap();

        assert_eq!(ten - seven, three);
        assert_eq!(&ten - seven, three);
        assert_eq!(ten - &seven, three);
        assert_eq!(&ten - &seven, three);
    }

    #[test]
    fn add_assign() {
        let mut f = FeeRate::from_sat_per_kwu(1).unwrap();
        f += FeeRate::from_sat_per_kwu(2).unwrap();
        assert_eq!(f, FeeRate::from_sat_per_kwu(3).unwrap());

        let mut f = FeeRate::from_sat_per_kwu(1).unwrap();
        f += &FeeRate::from_sat_per_kwu(2).unwrap();
        assert_eq!(f, FeeRate::from_sat_per_kwu(3).unwrap());
    }

    #[test]
    fn sub_assign() {
        let mut f = FeeRate::from_sat_per_kwu(3).unwrap();
        f -= FeeRate::from_sat_per_kwu(2).unwrap();
        assert_eq!(f, FeeRate::from_sat_per_kwu(1).unwrap());

        let mut f = FeeRate::from_sat_per_kwu(3).unwrap();
        f -= &FeeRate::from_sat_per_kwu(2).unwrap();
        assert_eq!(f, FeeRate::from_sat_per_kwu(1).unwrap());
    }

    #[test]
    fn checked_add() {
        let one = FeeRate::from_sat_per_kwu(1).unwrap();
        let two = FeeRate::from_sat_per_kwu(2).unwrap();
        let three = FeeRate::from_sat_per_kwu(3).unwrap();

        assert_eq!(one.checked_add(two).unwrap(), three);

        assert!(FeeRate::from_sat_per_kvb(u64::MAX).is_none()); // sanity check.
        let fee_rate = FeeRate::from_sat_per_mvb(u64::MAX).checked_add(one);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn checked_sub() {
        let one = FeeRate::from_sat_per_kwu(1).unwrap();
        let two = FeeRate::from_sat_per_kwu(2).unwrap();
        let three = FeeRate::from_sat_per_kwu(3).unwrap();
        assert_eq!(three.checked_sub(two).unwrap(), one);

        let fee_rate = FeeRate::ZERO.checked_sub(one);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn fee_rate_const() {
        assert_eq!(FeeRate::ZERO.to_sat_per_kwu_floor(), 0);
        assert_eq!(FeeRate::MIN.to_sat_per_kwu_floor(), u64::MIN);
        assert_eq!(FeeRate::MAX.to_sat_per_kwu_floor(), u64::MAX / 4_000);
        assert_eq!(FeeRate::BROADCAST_MIN.to_sat_per_kwu_floor(), 250);
        assert_eq!(FeeRate::DUST.to_sat_per_kwu_floor(), 750);
    }

    #[test]
    fn fee_rate_from_sat_per_vb() {
        let fee_rate = FeeRate::from_sat_per_vb(10).expect("expected feerate in sat/kwu");
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(2500).unwrap());
    }

    #[test]
    fn fee_rate_from_sat_per_kvb() {
        let fee_rate = FeeRate::from_sat_per_kvb(11).unwrap();
        assert_eq!(fee_rate, FeeRate::from_sat_per_mvb(11_000));
    }

    #[test]
    fn fee_rate_from_sat_per_vb_overflow() {
        let fee_rate = FeeRate::from_sat_per_vb(u64::MAX);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn from_sat_per_vb_u32() {
        let fee_rate = FeeRate::from_sat_per_vb_u32(10);
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(2500).unwrap());
    }

    #[test]
    #[cfg(debug_assertions)]
    fn from_sat_per_vb_u32_cannot_panic() { FeeRate::from_sat_per_vb_u32(u32::MAX); }

    #[test]
    fn raw_feerate() {
        let fee_rate = FeeRate::from_sat_per_kwu(749).unwrap();
        assert_eq!(fee_rate.to_sat_per_kwu_floor(), 749);
        assert_eq!(fee_rate.to_sat_per_vb_floor(), 2);
        assert_eq!(fee_rate.to_sat_per_vb_ceil(), 3);
    }

    #[test]
    fn checked_mul() {
        let fee_rate = FeeRate::from_sat_per_kwu(10)
            .unwrap()
            .checked_mul(10)
            .expect("expected feerate in sat/kwu");
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(100).unwrap());

        let fee_rate = FeeRate::from_sat_per_kwu(10).unwrap().checked_mul(u64::MAX);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn checked_div() {
        let fee_rate = FeeRate::from_sat_per_kwu(10)
            .unwrap()
            .checked_div(10)
            .expect("expected feerate in sat/kwu");
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(1).unwrap());

        let fee_rate = FeeRate::from_sat_per_kwu(10).unwrap().checked_div(0);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn mvb() {
        let fee_rate = FeeRate::from_sat_per_mvb(1_234_567);
        let got = fee_rate.to_sat_per_mvb();
        assert_eq!(got, 1_234_567);
    }
}
