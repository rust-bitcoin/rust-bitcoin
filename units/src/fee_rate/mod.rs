// SPDX-License-Identifier: CC0-1.0

//! Implements `FeeRate` and associated features.

#[cfg(feature = "serde")]
pub mod serde;

use core::num::NonZeroU64;
use core::ops;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use NumOpResult as R;

use crate::result::{MathOp, NumOpError as E, NumOpResult};
use crate::{Amount, Weight};

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
use internals::const_casts;

impl FeeRate {
    /// The zero fee rate.
    ///
    /// Equivalent to [`MIN`](Self::MIN), may better express intent in some contexts.
    pub const ZERO: Self = Self::from_sat_per_mvb(0);

    /// The minimum possible value.
    ///
    /// Equivalent to [`ZERO`](Self::ZERO), may better express intent in some contexts.
    pub const MIN: Self = Self::ZERO;

    /// The maximum possible value.
    pub const MAX: Self = Self::from_sat_per_mvb(u64::MAX);

    /// The minimum fee rate required to broadcast a transaction.
    ///
    /// The value matches the default Bitcoin Core policy at the time of library release.
    pub const BROADCAST_MIN: Self = Self::from_sat_per_vb(1);

    /// The fee rate used to compute dust amount.
    pub const DUST: Self = Self::from_sat_per_vb(3);

    /// Constructs a new [`FeeRate`] from satoshis per 1000 weight units.
    pub const fn from_sat_per_kwu(sat_kwu: u32) -> Self {
        let fee_rate = (const_casts::u32_to_u64(sat_kwu)) * 4_000;
        Self::from_sat_per_mvb(fee_rate)
    }

    /// Constructs a new [`FeeRate`] from amount per 1000 weight units.
    pub const fn from_per_kwu(rate: Amount) -> NumOpResult<Self> {
        // No `map()` in const context.
        match rate.checked_mul(4_000) {
            Some(per_mvb) => R::Valid(Self::from_sat_per_mvb(per_mvb.to_sat())),
            None => R::Error(E::while_doing(MathOp::Mul)),
        }
    }

    /// Constructs a new [`FeeRate`] from satoshis per virtual byte.
    pub const fn from_sat_per_vb(sat_vb: u32) -> Self {
        let fee_rate = (const_casts::u32_to_u64(sat_vb)) * 1_000_000;
        Self::from_sat_per_mvb(fee_rate)
    }

    /// Constructs a new [`FeeRate`] from amount per virtual byte.
    pub const fn from_per_vb(rate: Amount) -> NumOpResult<Self> {
        // No `map()` in const context.
        match rate.checked_mul(1_000_000) {
            Some(per_mvb) => R::Valid(Self::from_sat_per_mvb(per_mvb.to_sat())),
            None => R::Error(E::while_doing(MathOp::Mul)),
        }
    }

    /// Constructs a new [`FeeRate`] from satoshis per kilo virtual bytes (1,000 vbytes).
    pub const fn from_sat_per_kvb(sat_kvb: u32) -> Self {
        let fee_rate = (const_casts::u32_to_u64(sat_kvb)) * 1_000;
        Self::from_sat_per_mvb(fee_rate)
    }

    /// Constructs a new [`FeeRate`] from satoshis per kilo virtual bytes (1,000 vbytes).
    pub const fn from_per_kvb(rate: Amount) -> NumOpResult<Self> {
        // No `map()` in const context.
        match rate.checked_mul(1_000) {
            Some(per_mvb) => R::Valid(Self::from_sat_per_mvb(per_mvb.to_sat())),
            None => R::Error(E::while_doing(MathOp::Mul)),
        }
    }

    /// Converts to sat/kwu rounding down.
    pub const fn to_sat_per_kwu_floor(self) -> u64 { self.to_sat_per_mvb() / 4_000 }

    /// Converts to sat/kwu rounding up.
    pub const fn to_sat_per_kwu_ceil(self) -> u64 { self.to_sat_per_mvb().div_ceil(4_000) }

    /// Converts to sat/vB rounding down.
    pub const fn to_sat_per_vb_floor(self) -> u64 { self.to_sat_per_mvb() / 1_000_000 }

    /// Converts to sat/vB rounding up.
    pub const fn to_sat_per_vb_ceil(self) -> u64 { self.to_sat_per_mvb().div_ceil(1_000_000) }

    /// Converts to sat/kvb rounding down.
    pub const fn to_sat_per_kvb_floor(self) -> u64 { self.to_sat_per_mvb() / 1_000 }

    /// Converts to sat/kvb rounding up.
    pub const fn to_sat_per_kvb_ceil(self) -> u64 { self.to_sat_per_mvb().div_ceil(1_000) }

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
    /// Computes `self + rhs` returning [`None`] in case of overflow.
    #[must_use]
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
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
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat_per_mvb().checked_sub(rhs.to_sat_per_mvb()) {
            Some(res) => Some(Self::from_sat_per_mvb(res)),
            None => None,
        }
    }

    /// Calculates the fee by multiplying this fee rate by weight.
    ///
    /// Computes the absolute fee amount for a given [`Weight`] at this fee rate. When the resulting
    /// fee is a non-integer amount, the amount is rounded up, ensuring that the transaction fee is
    /// enough instead of falling short if rounded down.
    ///
    /// If the calculation would overflow we saturate to [`Amount::MAX`]. Since such a fee can never
    /// be paid this is meaningful as an error case while still removing the possibility of silently
    /// wrapping.
    pub const fn to_fee(self, weight: Weight) -> Amount {
        // No `unwrap_or()` in const context.
        match self.mul_by_weight(weight) {
            NumOpResult::Valid(fee) => fee,
            NumOpResult::Error(_) => Amount::MAX,
        }
    }

    /// Calculates the fee by multiplying this fee rate by weight, in weight units, returning [`None`]
    /// if an overflow occurred.
    ///
    /// This is equivalent to `Self::mul_by_weight(weight).ok()`.
    #[must_use]
    #[deprecated(since = "1.0.0-rc.0", note = "use `to_fee()` instead")]
    pub fn fee_wu(self, weight: Weight) -> Option<Amount> { self.mul_by_weight(weight).ok() }

    /// Calculates the fee by multiplying this fee rate by weight, in virtual bytes, returning [`None`]
    /// if `vb` cannot be represented as [`Weight`].
    ///
    /// This is equivalent to converting `vb` to [`Weight`] using [`Weight::from_vb`] and then calling
    /// [`Self::to_fee`].
    #[must_use]
    #[deprecated(since = "1.0.0-rc.0", note = "use Weight::from_vb and then `to_fee()` instead")]
    pub fn fee_vb(self, vb: u64) -> Option<Amount> { Weight::from_vb(vb).map(|w| self.to_fee(w)) }

    /// Checked weight multiplication.
    ///
    /// Computes the absolute fee amount for a given [`Weight`] at this fee rate. When the resulting
    /// fee is a non-integer amount, the amount is rounded up, ensuring that the transaction fee is
    /// enough instead of falling short if rounded down.
    pub const fn mul_by_weight(self, weight: Weight) -> NumOpResult<Amount> {
        let wu = weight.to_wu();
        if let Some(fee_kwu) = self.to_sat_per_kwu_floor().checked_mul(wu) {
            let fee = fee_kwu.div_ceil(1_000);
            if let Ok(fee_amount) = Amount::from_sat(fee) {
                return NumOpResult::Valid(fee_amount);
            }
        }
        NumOpResult::Error(E::while_doing(MathOp::Mul))
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
        Self::from_sat_per_mvb(iter.map(Self::to_sat_per_mvb).sum())
    }
}

impl<'a> core::iter::Sum<&'a Self> for FeeRate {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        Self::from_sat_per_mvb(iter.map(|f| Self::to_sat_per_mvb(*f)).sum())
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FeeRate {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=4)?;
        match choice {
            0 => Ok(Self::MIN),
            1 => Ok(Self::BROADCAST_MIN),
            2 => Ok(Self::DUST),
            3 => Ok(Self::MAX),
            _ => Ok(Self::from_sat_per_mvb(u64::arbitrary(u)?)),
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

        let mut f = NumOpResult::Valid(FeeRate::from_sat_per_kwu(1));
        f += FeeRate::from_sat_per_kwu(2);
        assert_eq!(f, NumOpResult::Valid(FeeRate::from_sat_per_kwu(3)));

        let mut f = NumOpResult::Valid(FeeRate::from_sat_per_kwu(1));
        f += NumOpResult::Valid(FeeRate::from_sat_per_kwu(2));
        assert_eq!(f, NumOpResult::Valid(FeeRate::from_sat_per_kwu(3)));
    }

    #[test]
    fn sub_assign() {
        let mut f = FeeRate::from_sat_per_kwu(3);
        f -= FeeRate::from_sat_per_kwu(2);
        assert_eq!(f, FeeRate::from_sat_per_kwu(1));

        let mut f = FeeRate::from_sat_per_kwu(3);
        f -= &FeeRate::from_sat_per_kwu(2);
        assert_eq!(f, FeeRate::from_sat_per_kwu(1));

        let mut f = NumOpResult::Valid(FeeRate::from_sat_per_kwu(3));
        f -= FeeRate::from_sat_per_kwu(2);
        assert_eq!(f, NumOpResult::Valid(FeeRate::from_sat_per_kwu(1)));

        let mut f = NumOpResult::Valid(FeeRate::from_sat_per_kwu(3));
        f -= NumOpResult::Valid(FeeRate::from_sat_per_kwu(2));
        assert_eq!(f, NumOpResult::Valid(FeeRate::from_sat_per_kwu(1)));
    }

    #[test]
    fn checked_add() {
        let one = FeeRate::from_sat_per_kwu(1);
        let two = FeeRate::from_sat_per_kwu(2);
        let three = FeeRate::from_sat_per_kwu(3);

        assert_eq!(one.checked_add(two).unwrap(), three);

        // Sanity check - no overflow adding one to per kvb max.
        let _ = FeeRate::from_sat_per_kvb(u32::MAX).checked_add(one).unwrap();
        let fee_rate = FeeRate::from_sat_per_mvb(u64::MAX).checked_add(one);
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
        assert_eq!(FeeRate::ZERO.to_sat_per_kwu_floor(), 0);
        assert_eq!(FeeRate::MIN.to_sat_per_kwu_floor(), u64::MIN);
        assert_eq!(FeeRate::MAX.to_sat_per_kwu_floor(), u64::MAX / 4_000);
        assert_eq!(FeeRate::BROADCAST_MIN.to_sat_per_kwu_floor(), 250);
        assert_eq!(FeeRate::DUST.to_sat_per_kwu_floor(), 750);
    }

    #[test]
    fn fee_rate_from_sat_per_vb() {
        let fee_rate = FeeRate::from_sat_per_vb(10);
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(2500));
    }

    #[test]
    fn fee_rate_from_sat_per_kvb() {
        let fee_rate = FeeRate::from_sat_per_kvb(11);
        assert_eq!(fee_rate, FeeRate::from_sat_per_mvb(11_000));
    }

    #[test]
    fn fee_rate_to_sat_per_x() {
        let fee_rate = FeeRate::from_sat_per_mvb(2_000_400);

        // sat/kwu: 2_000_400 / 4_000 = 500.1
        assert_eq!(fee_rate.to_sat_per_kwu_floor(), 500);
        assert_eq!(fee_rate.to_sat_per_kwu_ceil(), 501);

        // sat/vB: 2_000_400 / 1_000_000 = 2.0004
        assert_eq!(fee_rate.to_sat_per_vb_floor(), 2);
        assert_eq!(fee_rate.to_sat_per_vb_ceil(), 3);

        // sat/kvb: 2_000_400 / 1_000 = 2_000.4
        assert_eq!(fee_rate.to_sat_per_kvb_floor(), 2_000);
        assert_eq!(fee_rate.to_sat_per_kvb_ceil(), 2_001);

        let max = FeeRate::MAX;
        assert_eq!(max.to_sat_per_kwu_ceil(), u64::MAX / 4_000 + 1);
        assert_eq!(max.to_sat_per_vb_ceil(), u64::MAX / 1_000_000 + 1);
        assert_eq!(max.to_sat_per_kvb_ceil(), u64::MAX / 1_000 + 1);
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

    #[test]
    fn mvb() {
        let fee_rate = FeeRate::from_sat_per_mvb(1_234_567);
        let got = fee_rate.to_sat_per_mvb();
        assert_eq!(got, 1_234_567);
    }
}

#[cfg(kani)]
mod verification;
