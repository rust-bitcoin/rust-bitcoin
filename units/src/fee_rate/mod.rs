// SPDX-License-Identifier: CC0-1.0

//! Implements `FeeRate` and associated features.

#[cfg(feature = "serde")]
pub mod serde;

use core::{fmt, ops};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

mod encapsulate {
    /// Fee rate.
    ///
    /// This is an integer newtype representing fee rate. It provides protection
    /// against mixing up the types as well as basic formatting features.
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
    pub struct FeeRate(u64);

    impl FeeRate {
        /// Constructs a new [`FeeRate`] from satoshis per 1000 virtual bytes.
        pub const fn from_sat_per_kvb(sat_kvb: u64) -> Self { FeeRate(sat_kvb) }

        /// Returns raw fee rate as satoshis per 1000 virtual bytes.
        pub const fn to_sat_per_kvb(self) -> u64 { self.0 }
    }
}
#[doc(inline)]
pub use encapsulate::FeeRate;

impl FeeRate {
    /// 0 sat/kwu.
    ///
    /// Equivalent to [`MIN`](Self::MIN), may better express intent in some contexts.
    pub const ZERO: FeeRate = FeeRate::from_sat_per_kvb(0);

    /// Minimum possible value (0 sat/kwu).
    ///
    /// Equivalent to [`ZERO`](Self::ZERO), may better express intent in some contexts.
    pub const MIN: FeeRate = FeeRate::ZERO;

    /// Maximum possible value.
    pub const MAX: FeeRate = FeeRate::from_sat_per_kvb(u64::MAX);

    /// Minimum fee rate required to broadcast a transaction.
    ///
    /// The value matches the default Bitcoin Core policy at the time of library release.
    pub const BROADCAST_MIN: FeeRate = FeeRate::from_sat_per_kvb(1000);

    /// Fee rate used to compute dust amount.
    pub const DUST: FeeRate = FeeRate::from_sat_per_kvb(3000);

    /// Constructs a new [`FeeRate`] from satoshis per 1000 weight units.
    pub const fn from_sat_per_kwu(sat_kwu: u64) -> Option<Self> {
        match sat_kwu.checked_mul(4) {
            Some(sat_kvb) => Some(FeeRate::from_sat_per_kvb(sat_kvb)),
            None => None,
        }
    }

    /// Constructs a new [`FeeRate`] from satoshis per virtual bytes.
    ///
    /// # Errors
    ///
    /// Returns [`None`] on arithmetic overflow.
    pub const fn from_sat_per_wu(sat_wu: u64) -> Option<Self> {
        match sat_wu.checked_mul(250) {
            Some(sat_kvb) => Some(FeeRate::from_sat_per_kvb(sat_kvb)),
            None => None,
        }
    }

    /// Constructs a new [`FeeRate`] from satoshis per virtual bytes.
    ///
    /// # Errors
    ///
    /// Returns [`None`] on arithmetic overflow.
    pub const fn from_sat_per_vb(sat_vb: u64) -> Option<Self> {
        match sat_vb.checked_mul(1000) {
            Some(sat_kvb) => Some(FeeRate::from_sat_per_kvb(sat_kvb)),
            None => None,
        }
    }

    /// Returns raw fee rate as satoshis per 1000 weight units.
    pub const fn to_sat_per_kwu(self) -> Option<u64> { self.to_sat_per_kvb().checked_div(4) }

    /// Converts to sat/vB rounding down.
    pub const fn to_sat_per_vb_floor(self) -> u64 { self.to_sat_per_kvb() / 1000 }

    /// Converts to sat/vB rounding up.
    pub const fn to_sat_per_vb_ceil(self) -> u64 { (self.to_sat_per_kvb() + 999) / 1000 }

    /// Checked multiplication.
    ///
    /// Computes `self * rhs` returning [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_mul(self, rhs: u64) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat_per_kvb().checked_mul(rhs) {
            Some(res) => Some(Self::from_sat_per_kvb(res)),
            None => None,
        }
    }

    /// Checked division.
    ///
    /// Computes `self / rhs` returning [`None`] if `rhs == 0`.
    #[must_use]
    pub const fn checked_div(self, rhs: u64) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat_per_kvb().checked_div(rhs) {
            Some(res) => Some(Self::from_sat_per_kvb(res)),
            None => None,
        }
    }

    /// Checked addition.
    ///
    /// Computes `self + rhs` returning [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_add(self, rhs: u64) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat_per_kvb().checked_add(rhs) {
            Some(res) => Some(Self::from_sat_per_kvb(res)),
            None => None,
        }
    }

    /// Checked subtraction.
    ///
    /// Computes `self - rhs` returning [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_sub(self, rhs: u64) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat_per_kvb().checked_sub(rhs) {
            Some(res) => Some(Self::from_sat_per_kvb(res)),
            None => None,
        }
    }
}

/// Alternative will display the unit.
impl fmt::Display for FeeRate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // FIXME: Why vb_ceil and not kvb?
        if f.alternate() {
            // We use .00 to indicate that 1 sat/vbyte is not the minimum.
            // https://github.com/rust-bitcoin/rust-bitcoin/pull/2064#issuecomment-1736297479
            write!(f, "{}.00 sat/kvb", self.to_sat_per_kvb())
        } else {
            fmt::Display::fmt(&self.to_sat_per_kvb(), f)
        }
    }
}

impl From<FeeRate> for u64 {
    fn from(value: FeeRate) -> Self { value.to_sat_per_kvb() }
}

crate::internal_macros::impl_op_for_references! {
    impl ops::Add<FeeRate> for FeeRate {
        type Output = FeeRate;

        fn add(self, rhs: FeeRate) -> Self::Output { FeeRate::from_sat_per_kvb(self.to_sat_per_kvb() + rhs.to_sat_per_kvb()) }
    }

    impl ops::Sub<FeeRate> for FeeRate {
        type Output = FeeRate;

        fn sub(self, rhs: FeeRate) -> Self::Output { FeeRate::from_sat_per_kvb(self.to_sat_per_kvb() - rhs.to_sat_per_kvb()) }
    }
}
crate::internal_macros::impl_add_assign!(FeeRate);
crate::internal_macros::impl_sub_assign!(FeeRate);

impl core::iter::Sum for FeeRate {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        FeeRate::from_sat_per_kvb(iter.map(FeeRate::to_sat_per_kvb).sum())
    }
}

impl<'a> core::iter::Sum<&'a FeeRate> for FeeRate {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a FeeRate>,
    {
        FeeRate::from_sat_per_kvb(iter.map(|f| FeeRate::to_sat_per_kvb(*f)).sum())
    }
}

crate::impl_parse_str_from_int_infallible!(FeeRate, u64, from_sat_per_kvb);

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FeeRate {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=4)?;
        match choice {
            0 => Ok(FeeRate::MIN),
            1 => Ok(FeeRate::BROADCAST_MIN),
            2 => Ok(FeeRate::DUST),
            3 => Ok(FeeRate::MAX),
            _ => Ok(FeeRate::from_sat_per_kvb(u64::arbitrary(u)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity_check() {
        let fee_rate: u64 = u64::from(FeeRate::from_sat_per_kvb(100));
        assert_eq!(fee_rate, 100_u64);
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn addition() {
        let one = FeeRate::from_sat_per_kvb(1);
        let two = FeeRate::from_sat_per_kvb(2);
        let three = FeeRate::from_sat_per_kvb(3);

        assert!(one + two == three);
        assert!(&one + two == three);
        assert!(one + &two == three);
        assert!(&one + &two == three);
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn subtract() {
        let three = FeeRate::from_sat_per_kvb(3);
        let seven = FeeRate::from_sat_per_kvb(7);
        let ten = FeeRate::from_sat_per_kvb(10);

        assert_eq!(ten - seven, three);
        assert_eq!(&ten - seven, three);
        assert_eq!(ten - &seven, three);
        assert_eq!(&ten - &seven, three);
    }

    #[test]
    fn add_assign() {
        let mut f = FeeRate::from_sat_per_kvb(1);
        f += FeeRate::from_sat_per_kvb(2);
        assert_eq!(f, FeeRate::from_sat_per_kvb(3));

        let mut f = FeeRate::from_sat_per_kvb(1);
        f += &FeeRate::from_sat_per_kvb(2);
        assert_eq!(f, FeeRate::from_sat_per_kvb(3));
    }

    #[test]
    fn sub_assign() {
        let mut f = FeeRate::from_sat_per_kvb(3);
        f -= FeeRate::from_sat_per_kvb(2);
        assert_eq!(f, FeeRate::from_sat_per_kvb(1));

        let mut f = FeeRate::from_sat_per_kvb(3);
        f -= &FeeRate::from_sat_per_kvb(2);
        assert_eq!(f, FeeRate::from_sat_per_kvb(1));
    }

    #[test]
    fn checked_add() {
        let f = FeeRate::from_sat_per_kvb(1).checked_add(2).unwrap();
        assert_eq!(f, FeeRate::from_sat_per_kvb(3));

        let f = FeeRate::from_sat_per_kvb(u64::MAX).checked_add(1);
        assert!(f.is_none());
    }

    #[test]
    fn checked_sub() {
        let f = FeeRate::from_sat_per_kvb(2).checked_sub(1).unwrap();
        assert_eq!(f, FeeRate::from_sat_per_kvb(1));

        let f = FeeRate::ZERO.checked_sub(1);
        assert!(f.is_none());
    }

    #[test]
    fn fee_rate_const() {
        assert_eq!(FeeRate::ZERO.to_sat_per_kvb(), 0);
        assert_eq!(FeeRate::MIN.to_sat_per_kvb(), u64::MIN);
        assert_eq!(FeeRate::MAX.to_sat_per_kvb(), u64::MAX);
        assert_eq!(FeeRate::BROADCAST_MIN.to_sat_per_kvb(), 1000);
        assert_eq!(FeeRate::DUST.to_sat_per_kvb(), 3000);
    }

    #[test]
    fn fee_rate_from_sat_per_vb() {
        let fee_rate = FeeRate::from_sat_per_vb(10).expect("expected feerate in sat/kwu");
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(2500).unwrap());
    }

    #[test]
    fn fee_rate_from_sat_per_vb_overflow() {
        let fee_rate = FeeRate::from_sat_per_vb(u64::MAX);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn from_sat_per_vb_unchecked() {
        let fee_rate = FeeRate::from_sat_per_kvb(10_000);
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(2500).unwrap());
    }

    #[test]
    fn raw_feerate() {
        let fee_rate = FeeRate::from_sat_per_kwu(749).unwrap();
        assert_eq!(fee_rate.to_sat_per_kwu().unwrap(), 749);
        assert_eq!(fee_rate.to_sat_per_vb_floor(), 2);
        assert_eq!(fee_rate.to_sat_per_vb_ceil(), 3);
    }

    #[test]
    fn checked_mul() {
        let fee_rate =
            FeeRate::from_sat_per_kvb(10).checked_mul(10).expect("expected feerate in sat/kwu");
        assert_eq!(fee_rate, FeeRate::from_sat_per_kvb(100));

        let fee_rate = FeeRate::from_sat_per_kvb(10).checked_mul(u64::MAX);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn checked_div() {
        let fee_rate =
            FeeRate::from_sat_per_kvb(10).checked_div(10).expect("expected feerate in sat/kwu");
        assert_eq!(fee_rate, FeeRate::from_sat_per_kvb(1));

        let fee_rate = FeeRate::from_sat_per_kvb(10).checked_div(0);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn sat_per_kwu_looses_precision() {
        let fee_rate = FeeRate::from_sat_per_kwu(3).unwrap();
        assert_eq!(fee_rate.to_sat_per_kwu().unwrap(), 3);
    }
}
