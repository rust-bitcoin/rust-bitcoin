// SPDX-License-Identifier: CC0-1.0

//! Implements `FeeRate` and associated features.

#[cfg(feature = "serde")]
pub mod serde;

use core::{fmt, ops};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

use crate::decimal::Rounding;

mod encapsulate {
    /// Fee rate.
    ///
    /// This is an integer newtype representing fee rate in `sat/kwu`. It provides protection
    /// against mixing up the types as well as basic formatting features.
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
    pub struct FeeRate(u64);

    impl FeeRate {
        /// Constructs a new [`FeeRate`] from satoshis per 1000 weight units.
        pub const fn from_sat_per_kwu(sat_kwu: u64) -> Self { FeeRate(sat_kwu) }

        /// Returns raw fee rate.
        ///
        /// Can be used instead of `into()` to avoid inference issues.
        pub const fn to_sat_per_kwu(self) -> u64 { self.0 }
    }
}
#[doc(inline)]
pub use encapsulate::FeeRate;

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
    pub const BROADCAST_MIN: FeeRate = FeeRate::from_sat_per_vb_unchecked(1);

    /// Fee rate used to compute dust amount.
    pub const DUST: FeeRate = FeeRate::from_sat_per_vb_unchecked(3);

    /// Constructs a new [`FeeRate`] from satoshis per virtual bytes.
    ///
    /// # Errors
    ///
    /// Returns [`None`] on arithmetic overflow.
    pub fn from_sat_per_vb(sat_vb: u64) -> Option<Self> {
        // 1 vb == 4 wu
        // 1 sat/vb == 1/4 sat/wu
        // sat_vb sat/vb * 1000 / 4 == sat/kwu
        Some(FeeRate::from_sat_per_kwu(sat_vb.checked_mul(1000 / 4)?))
    }

    /// Constructs a new [`FeeRate`] from satoshis per virtual bytes without overflow check.
    pub const fn from_sat_per_vb_unchecked(sat_vb: u64) -> Self {
        FeeRate::from_sat_per_kwu(sat_vb * (1000 / 4))
    }

    /// Constructs a new [`FeeRate`] from satoshis per kilo virtual bytes (1,000 vbytes).
    pub const fn from_sat_per_kvb(sat_kvb: u64) -> Self { FeeRate::from_sat_per_kwu(sat_kvb / 4) }

    /// Converts to sat/vB rounding down.
    pub const fn to_sat_per_vb_floor(self) -> u64 { self.to_sat_per_kwu() / (1000 / 4) }

    /// Converts to sat/vB rounding up.
    pub const fn to_sat_per_vb_ceil(self) -> u64 {
        (self.to_sat_per_kwu() + (1000 / 4 - 1)) / (1000 / 4)
    }

    /// Displays the fee rate using sat/kwu unit.
    ///
    /// This unit is precise, so it doesn't need rounding options.
    ///
    /// The unit is displayed by default, call [`without_unit`](Display::without_unit) on the
    /// returned value to hide it.
    pub fn display_sat_per_kwu(self) -> Display {
        Display {
            fee_rate: self,
            format: Format::SatPerKwu,
            display_unit: true,
        }
    }

    /// Displays the fee rate using sat/kwu unit, rounding if needed.
    ///
    /// By default this has precision of 3 decimal places (but the trailing zeros are not
    /// displayed). In that case the value is precise and no rounding is applied.
    ///
    /// However, using smaller formatter precision will require rounding of the numer. This method
    /// uses the natural rounding based on whether the most-significant decimal place that is
    /// hidden is less than 5 or not.
    ///
    /// The unit is displayed by default, call [`without_unit`](Display::without_unit) on the
    /// returned value to hide it.
    pub fn display_sat_per_vb_round(self) -> Display {
        Display {
            fee_rate: self,
            format: Format::SatPerVB { rounding: Rounding::Round },
            display_unit: true,
        }
    }

    /// Displays the fee rate using sat/kwu unit, rounding down if needed.
    ///
    /// By default this has precision of 3 decimal places (but the trailing zeros are not
    /// displayed). In that case the value is precise and no rounding is applied.
    ///
    /// However, using smaller formatter precision will require rounding of the numer. This method
    /// computes the floor - always rounding down, even if the most-significant decimal place that
    /// is hidden is greater than or equal to 5.
    ///
    /// The unit is displayed by default, call [`without_unit`](Display::without_unit) on the
    /// returned value to hide it.
    pub fn display_sat_per_vb_floor(self) -> Display {
        Display {
            fee_rate: self,
            format: Format::SatPerVB { rounding: Rounding::Floor },
            display_unit: true,
        }
    }

    /// Displays the fee rate using sat/kwu unit, rounding up if needed.
    ///
    /// By default this has precision of 3 decimal places (but the trailing zeros are not
    /// displayed). In that case the value is precise and no rounding is applied.
    ///
    /// However, using smaller formatter precision will require rounding of the numer. This method
    /// computes the ceiling - always rounding up, even if the most-significant decimal place that
    /// is hidden is less than 5.
    ///
    /// The unit is displayed by default, call [`without_unit`](Display::without_unit) on the
    /// returned value to hide it.
    pub fn display_sat_per_vb_ceil(self) -> Display {
        Display {
            fee_rate: self,
            format: Format::SatPerVB { rounding: Rounding::Ceil },
            display_unit: true,
        }
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
    pub const fn checked_add(self, rhs: u64) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat_per_kwu().checked_add(rhs) {
            Some(res) => Some(Self::from_sat_per_kwu(res)),
            None => None,
        }
    }

    /// Checked subtraction.
    ///
    /// Computes `self - rhs` returning [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_sub(self, rhs: u64) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat_per_kwu().checked_sub(rhs) {
            Some(res) => Some(Self::from_sat_per_kwu(res)),
            None => None,
        }
    }
}

/// Alternative will display the unit.
impl fmt::Display for FeeRate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "{}.00 sat/vbyte", self.to_sat_per_vb_ceil())
        } else {
            fmt::Display::fmt(&self.to_sat_per_kwu(), f)
        }
    }
}

impl From<FeeRate> for u64 {
    fn from(value: FeeRate) -> Self { value.to_sat_per_kwu() }
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

crate::impl_parse_str_from_int_infallible!(FeeRate, u64, from_sat_per_kwu);

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

/// A helper/builder that displays fee rate with specified settings.
///
/// This provides richer interface than [`fmt::Formatter`]:
///
/// * Ability to select unit
/// * Show or hide unit
/// * How rounding works if smaller precision is requested
///
/// However, this can still be combined with [`fmt::Formatter`] options to precisely control zeros,
/// padding, alignment... The formatting works like floats from `core` but applies rounding
/// according to its setting.
#[derive(Debug, Clone)]
pub struct Display {
    fee_rate: FeeRate,
    format: Format,
    display_unit: bool,
}

impl Display {
    /// Do not display the unit.
    ///
    /// The unit is displayed by default to avoid confusion but if you need to hide it in
    /// non-confusing situations you can call this function before formatting.
    #[must_use = "the Display is not modified but a new one is returned"]
    pub fn without_unit(mut self) -> Self {
        self.display_unit = false;
        self
    }
}

impl fmt::Display for Display {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use crate::decimal::Decimal;

        let decimal = match self.format {
            Format::SatPerKwu => {
                Decimal {
                    negative: false,
                    num_before_decimal_point: self.fee_rate.to_sat_per_kwu(),
                    exp: 0,
                    num_after_decimal_point: 0,
                    nb_decimals: 0,
                    unit: self.display_unit.then_some("sat/kwu"),
                    rounding: Rounding::Floor,
                }
            },
            Format::SatPerVB { rounding } => {
                // sat/vB = sat/kwu / 250
                // if one has a number x known to have 3 decimal places multiplying by 1000 gives
                // an integer
                // if one has a number x and wants to display x / 1000, x % 1000 needs to be
                // displayed after decimal point, with leading zeros
                // so we have (fee_rate / 250 * 1000) % 1000
                // which is fee_rate * 4 % 1000
                // `as` will not truncate because of % 1000
                let thousandths = (u128::from(self.fee_rate.to_sat_per_kwu()) * 4 % 1000) as u64;
                Decimal {
                    negative: false,
                    num_before_decimal_point: self.fee_rate.to_sat_per_vb_floor(),
                    exp: 0,
                    num_after_decimal_point: thousandths,
                    nb_decimals: 3,
                    unit: self.display_unit.then_some("sat/kwu"),
                    rounding,
                }
            },
        };

        fmt::Display::fmt(&decimal, f)
    }
}

#[derive(Debug, Clone)]
enum Format {
    SatPerKwu,
    SatPerVB { rounding: Rounding },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity_check() {
        let fee_rate: u64 = u64::from(FeeRate::from_sat_per_kwu(100));
        assert_eq!(fee_rate, 100_u64);
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
        let f = FeeRate::from_sat_per_kwu(1).checked_add(2).unwrap();
        assert_eq!(FeeRate::from_sat_per_kwu(3), f);

        let f = FeeRate::from_sat_per_kwu(u64::MAX).checked_add(1);
        assert!(f.is_none());
    }

    #[test]
    fn checked_sub() {
        let f = FeeRate::from_sat_per_kwu(2).checked_sub(1).unwrap();
        assert_eq!(FeeRate::from_sat_per_kwu(1), f);

        let f = FeeRate::ZERO.checked_sub(1);
        assert!(f.is_none());
    }

    #[test]
    fn fee_rate_const() {
        assert_eq!(0, FeeRate::ZERO.to_sat_per_kwu());
        assert_eq!(u64::MIN, FeeRate::MIN.to_sat_per_kwu());
        assert_eq!(u64::MAX, FeeRate::MAX.to_sat_per_kwu());
        assert_eq!(250, FeeRate::BROADCAST_MIN.to_sat_per_kwu());
        assert_eq!(750, FeeRate::DUST.to_sat_per_kwu());
    }

    #[test]
    fn fee_rate_from_sat_per_vb() {
        let fee_rate = FeeRate::from_sat_per_vb(10).expect("expected feerate in sat/kwu");
        assert_eq!(FeeRate::from_sat_per_kwu(2500), fee_rate);
    }

    #[test]
    fn fee_rate_from_sat_per_kvb() {
        let fee_rate = FeeRate::from_sat_per_kvb(11);
        assert_eq!(FeeRate::from_sat_per_kwu(2), fee_rate);
    }

    #[test]
    fn fee_rate_from_sat_per_vb_overflow() {
        let fee_rate = FeeRate::from_sat_per_vb(u64::MAX);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn from_sat_per_vb_unchecked() {
        let fee_rate = FeeRate::from_sat_per_vb_unchecked(10);
        assert_eq!(FeeRate::from_sat_per_kwu(2500), fee_rate);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "attempt to multiply with overflow"]
    fn from_sat_per_vb_unchecked_panic() { FeeRate::from_sat_per_vb_unchecked(u64::MAX); }

    #[test]
    fn raw_feerate() {
        let fee_rate = FeeRate::from_sat_per_kwu(749);
        assert_eq!(749, fee_rate.to_sat_per_kwu());
        assert_eq!(2, fee_rate.to_sat_per_vb_floor());
        assert_eq!(3, fee_rate.to_sat_per_vb_ceil());
    }

    #[test]
    fn checked_mul() {
        let fee_rate =
            FeeRate::from_sat_per_kwu(10).checked_mul(10).expect("expected feerate in sat/kwu");
        assert_eq!(FeeRate::from_sat_per_kwu(100), fee_rate);

        let fee_rate = FeeRate::from_sat_per_kwu(10).checked_mul(u64::MAX);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn checked_div() {
        let fee_rate =
            FeeRate::from_sat_per_kwu(10).checked_div(10).expect("expected feerate in sat/kwu");
        assert_eq!(FeeRate::from_sat_per_kwu(1), fee_rate);

        let fee_rate = FeeRate::from_sat_per_kwu(10).checked_div(0);
        assert!(fee_rate.is_none());
    }
}
