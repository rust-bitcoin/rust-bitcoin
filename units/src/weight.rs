// SPDX-License-Identifier: CC0-1.0

//! Implements `Weight` and associated features.

use core::num::NonZeroU64;
use core::{fmt, ops};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{parse_int, Amount, FeeRate, NumOpResult};

/// The factor that non-witness serialization data is multiplied by during weight calculation.
pub const WITNESS_SCALE_FACTOR: usize = 4;

mod encapsulate {
    /// The weight of a transaction or block.
    ///
    /// This is an integer newtype representing weight in weight units. It provides protection
    /// against mixing up the types, conversion functions, and basic formatting.
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
    pub struct Weight(u64);

    impl Weight {
        /// Constructs a new [`Weight`] from weight units.
        pub const fn from_wu(wu: u64) -> Self { Self(wu) }

        /// Returns raw weight units.
        ///
        /// Can be used instead of `into()` to avoid inference issues.
        pub const fn to_wu(self) -> u64 { self.0 }
    }
}
#[doc(inline)]
pub use encapsulate::Weight;

impl Weight {
    /// Zero weight units (wu).
    ///
    /// Equivalent to [`MIN`](Self::MIN), may better express intent in some contexts.
    pub const ZERO: Self = Self::from_wu(0);

    /// Minimum possible value (0 wu).
    ///
    /// Equivalent to [`ZERO`](Self::ZERO), may better express intent in some contexts.
    pub const MIN: Self = Self::from_wu(u64::MIN);

    /// Maximum possible value.
    pub const MAX: Self = Self::from_wu(u64::MAX);

    /// The factor that non-witness serialization data is multiplied by during weight calculation.
    pub const WITNESS_SCALE_FACTOR: u64 = WITNESS_SCALE_FACTOR as u64; // this value is 4

    /// The maximum allowed weight for a block, see BIP-0141 (network rule).
    pub const MAX_BLOCK: Self = Self::from_wu(4_000_000);

    /// The minimum transaction weight for a valid serialized transaction.
    pub const MIN_TRANSACTION: Self = Self::from_wu(Self::WITNESS_SCALE_FACTOR * 60);

    /// Constructs a new [`Weight`] from kilo weight units returning [`None`] if an overflow occurred.
    pub const fn from_kwu(wu: u64) -> Option<Self> {
        // No `map()` in const context.
        match wu.checked_mul(1000) {
            Some(wu) => Some(Self::from_wu(wu)),
            None => None,
        }
    }

    /// Constructs a new [`Weight`] from virtual bytes, returning [`None`] if an overflow occurred.
    pub const fn from_vb(vb: u64) -> Option<Self> {
        // No `map()` in const context.
        match vb.checked_mul(Self::WITNESS_SCALE_FACTOR) {
            Some(wu) => Some(Self::from_wu(wu)),
            None => None,
        }
    }

    /// Constructs a new [`Weight`] from virtual bytes panicking if an overflow occurred.
    ///
    /// # Panics
    ///
    /// If the conversion from virtual bytes overflows.
    #[deprecated(since = "1.0.0-rc.0", note = "use `from_vb_unchecked` instead")]
    pub const fn from_vb_unwrap(vb: u64) -> Self {
        match vb.checked_mul(Self::WITNESS_SCALE_FACTOR) {
            Some(weight) => Self::from_wu(weight),
            None => panic!("checked_mul overflowed"),
        }
    }

    /// Constructs a new [`Weight`] from virtual bytes without an overflow check.
    pub const fn from_vb_unchecked(vb: u64) -> Self {
        Self::from_wu(vb * Self::WITNESS_SCALE_FACTOR)
    }

    /// Constructs a new [`Weight`] from witness size.
    #[deprecated(since = "1.0.0-rc.1", note = "use `from_wu` instead")]
    pub const fn from_witness_data_size(witness_size: u64) -> Self { Self::from_wu(witness_size) }

    /// Constructs a new [`Weight`] from non-witness size.
    ///
    /// # Panics
    ///
    /// If the conversion from virtual bytes overflows.
    #[deprecated(since = "1.0.0-rc.1", note = "use `from_vb` or `from_vb_unchecked` instead")]
    pub const fn from_non_witness_data_size(non_witness_size: u64) -> Self {
        Self::from_wu(non_witness_size * Self::WITNESS_SCALE_FACTOR)
    }

    /// Converts to kilo weight units rounding down.
    pub const fn to_kwu_floor(self) -> u64 { self.to_wu() / 1000 }

    /// Converts to kilo weight units rounding up.
    pub const fn to_kwu_ceil(self) -> u64 { self.to_wu().div_ceil(1_000) }

    /// Converts to vB rounding down.
    pub const fn to_vbytes_floor(self) -> u64 { self.to_wu() / Self::WITNESS_SCALE_FACTOR }

    /// Converts to vB rounding up.
    pub const fn to_vbytes_ceil(self) -> u64 { self.to_wu().div_ceil(Self::WITNESS_SCALE_FACTOR) }

    /// Checked addition.
    ///
    /// Computes `self + rhs` returning [`None`] if an overflow occurred.
    #[must_use]
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        // No `map()` in const context.
        match self.to_wu().checked_add(rhs.to_wu()) {
            Some(wu) => Some(Self::from_wu(wu)),
            None => None,
        }
    }

    /// Checked subtraction.
    ///
    /// Computes `self - rhs` returning [`None`] if an overflow occurred.
    #[must_use]
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        // No `map()` in const context.
        match self.to_wu().checked_sub(rhs.to_wu()) {
            Some(wu) => Some(Self::from_wu(wu)),
            None => None,
        }
    }

    /// Checked multiplication.
    ///
    /// Computes `self * rhs` returning [`None`] if an overflow occurred.
    #[must_use]
    pub const fn checked_mul(self, rhs: u64) -> Option<Self> {
        // No `map()` in const context.
        match self.to_wu().checked_mul(rhs) {
            Some(wu) => Some(Self::from_wu(wu)),
            None => None,
        }
    }

    /// Checked division.
    ///
    /// Computes `self / rhs` returning [`None`] if `rhs == 0`.
    #[must_use]
    pub const fn checked_div(self, rhs: u64) -> Option<Self> {
        // No `map()` in const context.
        match self.to_wu().checked_div(rhs) {
            Some(wu) => Some(Self::from_wu(wu)),
            None => None,
        }
    }

    /// Checked fee rate multiplication.
    ///
    /// Computes the absolute fee amount for a given [`FeeRate`] at this weight. When the resulting
    /// fee is a non-integer amount, the amount is rounded up, ensuring that the transaction fee is
    /// enough instead of falling short if rounded down.
    pub const fn mul_by_fee_rate(self, fee_rate: FeeRate) -> NumOpResult<Amount> {
        fee_rate.mul_by_weight(self)
    }
}

/// Alternative will display the unit.
impl fmt::Display for Weight {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "{} wu", self.to_wu())
        } else {
            fmt::Display::fmt(&self.to_wu(), f)
        }
    }
}

impl From<Weight> for u64 {
    fn from(value: Weight) -> Self { value.to_wu() }
}

crate::internal_macros::impl_op_for_references! {
    impl ops::Add<Weight> for Weight {
        type Output = Weight;

        fn add(self, rhs: Weight) -> Self::Output { Weight::from_wu(self.to_wu() + rhs.to_wu()) }
    }
    impl ops::Sub<Weight> for Weight {
        type Output = Weight;

        fn sub(self, rhs: Weight) -> Self::Output { Weight::from_wu(self.to_wu() - rhs.to_wu()) }
    }

    impl ops::Mul<u64> for Weight {
        type Output = Weight;

        fn mul(self, rhs: u64) -> Self::Output { Weight::from_wu(self.to_wu() * rhs) }
    }
    impl ops::Mul<Weight> for u64 {
        type Output = Weight;

        fn mul(self, rhs: Weight) -> Self::Output { Weight::from_wu(self * rhs.to_wu()) }
    }
    impl ops::Div<u64> for Weight {
        type Output = Weight;

        fn div(self, rhs: u64) -> Self::Output { Weight::from_wu(self.to_wu() / rhs) }
    }
    impl ops::Div<Weight> for Weight {
        type Output = u64;

        fn div(self, rhs: Weight) -> Self::Output { self.to_wu() / rhs.to_wu() }
    }
    impl ops::Rem<u64> for Weight {
        type Output = Weight;

        fn rem(self, rhs: u64) -> Self::Output { Weight::from_wu(self.to_wu() % rhs) }
    }
    impl ops::Rem<Weight> for Weight {
        type Output = u64;

        fn rem(self, rhs: Weight) -> Self::Output { self.to_wu() % rhs.to_wu() }
    }
    impl ops::Div<NonZeroU64> for Weight {
        type Output = Weight;

        fn div(self, rhs: NonZeroU64) -> Self::Output{ Self::from_wu(self.to_wu() / rhs.get()) }
    }
}
crate::internal_macros::impl_add_assign!(Weight);
crate::internal_macros::impl_sub_assign!(Weight);

impl ops::MulAssign<u64> for Weight {
    fn mul_assign(&mut self, rhs: u64) { *self = Self::from_wu(self.to_wu() * rhs); }
}

impl ops::DivAssign<u64> for Weight {
    fn div_assign(&mut self, rhs: u64) { *self = Self::from_wu(self.to_wu() / rhs); }
}

impl ops::RemAssign<u64> for Weight {
    fn rem_assign(&mut self, rhs: u64) { *self = Self::from_wu(self.to_wu() % rhs); }
}

impl core::iter::Sum for Weight {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        Self::from_wu(iter.map(Self::to_wu).sum())
    }
}

impl<'a> core::iter::Sum<&'a Self> for Weight {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        iter.copied().sum()
    }
}

parse_int::impl_parse_str_from_int_infallible!(Weight, u64, from_wu);

#[cfg(feature = "serde")]
impl Serialize for Weight {
    #[inline]
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        u64::serialize(&self.to_wu(), s)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Weight {
    #[inline]
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::from_wu(u64::deserialize(d)?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Weight {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let w = u64::arbitrary(u)?;
        Ok(Self::from_wu(w))
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU64;

    use super::*;

    const ONE: Weight = Weight::from_wu(1);
    const TWO: Weight = Weight::from_wu(2);
    const FOUR: Weight = Weight::from_wu(4);

    #[test]
    fn sanity_check() {
        assert_eq!(Weight::MIN_TRANSACTION, Weight::from_wu(240));
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn weight_div_nonzero() {
        let w = Weight::from_wu(100);
        let divisor = NonZeroU64::new(4).unwrap();
        assert_eq!(w / divisor, Weight::from_wu(25));
        // for borrowed variants
        assert_eq!(&w / &divisor, Weight::from_wu(25));
        assert_eq!(w / &divisor, Weight::from_wu(25));
    }

    #[test]
    fn from_kwu() {
        let got = Weight::from_kwu(1).unwrap();
        let want = Weight::from_wu(1_000);
        assert_eq!(got, want);
    }

    #[test]
    fn from_kwu_overflows() { assert!(Weight::from_kwu(u64::MAX).is_none()) }

    #[test]
    fn from_vb() {
        let got = Weight::from_vb(1).unwrap();
        let want = Weight::from_wu(4);
        assert_eq!(got, want);
    }

    #[test]
    fn from_vb_overflows() {
        assert!(Weight::from_vb(u64::MAX).is_none());
    }

    #[test]
    fn from_vb_unchecked() {
        let got = Weight::from_vb_unchecked(1);
        let want = Weight::from_wu(4);
        assert_eq!(got, want);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "attempt to multiply with overflow"]
    fn from_vb_unchecked_panic() { Weight::from_vb_unchecked(u64::MAX); }

    #[test]
    #[allow(deprecated)] // tests the deprecated function
    #[allow(deprecated_in_future)]
    fn from_witness_data_size() {
        let witness_data_size = 1;
        let got = Weight::from_witness_data_size(witness_data_size);
        let want = Weight::from_wu(witness_data_size);
        assert_eq!(got, want);
    }

    #[test]
    #[allow(deprecated)] // tests the deprecated function
    #[allow(deprecated_in_future)]
    fn from_non_witness_data_size() {
        let non_witness_data_size = 1;
        let got = Weight::from_non_witness_data_size(non_witness_data_size);
        let want = Weight::from_wu(non_witness_data_size * 4);
        assert_eq!(got, want);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn try_from_string() {
        let weight_value: alloc::string::String = "10".into();
        let got = Weight::try_from(weight_value).unwrap();
        let want = Weight::from_wu(10);
        assert_eq!(got, want);

        // Only base-10 integers should parse
        let weight_value: alloc::string::String = "0xab".into();
        assert!(Weight::try_from(weight_value).is_err());
        let weight_value: alloc::string::String = "10.123".into();
        assert!(Weight::try_from(weight_value).is_err());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn try_from_box() {
        let weight_value: alloc::boxed::Box<str> = "10".into();
        let got = Weight::try_from(weight_value).unwrap();
        let want = Weight::from_wu(10);
        assert_eq!(got, want);

        // Only base-10 integers should parse
        let weight_value: alloc::boxed::Box<str> = "0xab".into();
        assert!(Weight::try_from(weight_value).is_err());
        let weight_value: alloc::boxed::Box<str> = "10.123".into();
        assert!(Weight::try_from(weight_value).is_err());
    }

    #[test]
    fn to_kwu_floor() {
        assert_eq!(Weight::from_wu(5_000).to_kwu_floor(), 5);
        assert_eq!(Weight::from_wu(5_999).to_kwu_floor(), 5);
    }

    #[test]
    fn to_kwu_ceil() {
        assert_eq!(Weight::from_wu(1_000).to_kwu_ceil(), 1);
        assert_eq!(Weight::from_wu(1_001).to_kwu_ceil(), 2);
        assert_eq!(Weight::MAX.to_kwu_ceil(), u64::MAX / 1_000 + 1);
    }

    #[test]
    fn to_vb_floor() {
        assert_eq!(Weight::from_wu(8).to_vbytes_floor(), 2);
        assert_eq!(Weight::from_wu(9).to_vbytes_floor(), 2);
    }

    #[test]
    fn to_vb_ceil() {
        assert_eq!(Weight::from_wu(4).to_vbytes_ceil(), 1);
        assert_eq!(Weight::from_wu(5).to_vbytes_ceil(), 2);
        assert_eq!(Weight::MAX.to_vbytes_ceil(), u64::MAX / Weight::WITNESS_SCALE_FACTOR + 1);
    }

    #[test]
    fn checked_add() {
        assert_eq!(ONE.checked_add(ONE).unwrap(), TWO);
    }

    #[test]
    fn checked_add_overflows() { assert!(Weight::MAX.checked_add(ONE).is_none()) }

    #[test]
    fn checked_sub() {
        assert_eq!(TWO.checked_sub(ONE).unwrap(), ONE);
    }

    #[test]
    fn checked_sub_overflows() { assert!(Weight::ZERO.checked_sub(ONE).is_none()) }

    #[test]
    fn checked_mul() {
        assert_eq!(TWO.checked_mul(1).unwrap(), TWO);
        assert_eq!(TWO.checked_mul(2).unwrap(), FOUR);
    }

    #[test]
    fn checked_mul_overflows() { assert!(Weight::MAX.checked_mul(2).is_none()) }

    #[test]
    fn checked_div() {
        assert_eq!(FOUR.checked_div(2).unwrap(), TWO);
        assert_eq!(TWO.checked_div(1).unwrap(), TWO);
    }

    #[test]
    fn checked_div_overflows() { assert!(TWO.checked_div(0).is_none()) }

    #[test]
    #[allow(clippy::op_ref)]
    fn addition() {
        let one = Weight::from_wu(1);
        let two = Weight::from_wu(2);
        let three = Weight::from_wu(3);

        assert!(one + two == three);
        assert!(&one + two == three);
        assert!(one + &two == three);
        assert!(&one + &two == three);
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn subtract() {
        let ten = Weight::from_wu(10);
        let seven = Weight::from_wu(7);
        let three = Weight::from_wu(3);

        assert_eq!(ten - seven, three);
        assert_eq!(&ten - seven, three);
        assert_eq!(ten - &seven, three);
        assert_eq!(&ten - &seven, three);
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn multiply() {
        let two = Weight::from_wu(2);
        let six = Weight::from_wu(6);

        assert_eq!(3_u64 * two, six);
        assert_eq!(two * 3_u64, six);
    }

    #[test]
    fn divide() {
        let eight = Weight::from_wu(8);
        let four = Weight::from_wu(4);

        assert_eq!(eight / four, 2_u64);
        assert_eq!(eight / 4_u64, Weight::from_wu(2));
    }

    #[test]
    fn add_assign() {
        let mut f = Weight::from_wu(1);
        f += Weight::from_wu(2);
        assert_eq!(f, Weight::from_wu(3));

        let mut f = Weight::from_wu(1);
        f += &Weight::from_wu(2);
        assert_eq!(f, Weight::from_wu(3));
    }

    #[test]
    fn sub_assign() {
        let mut f = Weight::from_wu(3);
        f -= Weight::from_wu(2);
        assert_eq!(f, Weight::from_wu(1));

        let mut f = Weight::from_wu(3);
        f -= &Weight::from_wu(2);
        assert_eq!(f, Weight::from_wu(1));
    }

    #[test]
    fn mul_assign() {
        let mut w = Weight::from_wu(3);
        w *= 2_u64;
        assert_eq!(w, Weight::from_wu(6));
    }

    #[test]
    fn div_assign() {
        let mut w = Weight::from_wu(8);
        w /= Weight::from_wu(4).into();
        assert_eq!(w, Weight::from_wu(2));
    }

    #[test]
    fn remainder() {
        let weight10 = Weight::from_wu(10);
        let weight3 = Weight::from_wu(3);

        let remainder = weight10 % weight3;
        assert_eq!(remainder, 1);

        let remainder = weight10 % 3;
        assert_eq!(remainder, Weight::from_wu(1));
    }

    #[test]
    fn remainder_assign() {
        let mut weight = Weight::from_wu(10);
        weight %= 3;
        assert_eq!(weight, Weight::from_wu(1));
    }

    #[test]
    fn iter_sum() {
        let values = [
            Weight::from_wu(10),
            Weight::from_wu(50),
            Weight::from_wu(30),
            Weight::from_wu(5),
            Weight::from_wu(5),
        ];
        let got: Weight = values.into_iter().sum();
        let want = Weight::from_wu(100);
        assert_eq!(got, want);
    }

    #[test]
    fn iter_sum_ref() {
        let values = [
            Weight::from_wu(10),
            Weight::from_wu(50),
            Weight::from_wu(30),
            Weight::from_wu(5),
            Weight::from_wu(5),
        ];
        let got: Weight = values.iter().sum();
        let want = Weight::from_wu(100);
        assert_eq!(got, want);
    }

    #[test]
    fn iter_sum_empty() {
        let values: [Weight; 0] = [];
        let got: Weight = values.into_iter().sum();
        let want = Weight::from_wu(0);
        assert_eq!(got, want);
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    /// Verify that `from_vb` / `to_vbytes_floor` is a lossless roundtrip when
    /// the multiplication by 4 does not overflow.
    #[kani::proof]
    fn check_weight_from_vb_roundtrip() {
        let vb = kani::any::<u64>();
        kani::assume(Weight::from_vb(vb).is_some());

        let weight = Weight::from_vb(vb).unwrap();
        assert_eq!(weight.to_vbytes_floor(), vb);
    }

    /// Verify that `from_kwu` / `to_kwu_floor` is a lossless roundtrip when
    /// the multiplication by 1000 does not overflow.
    #[kani::proof]
    fn check_weight_from_kwu_roundtrip() {
        let kwu = kani::any::<u64>();
        kani::assume(Weight::from_kwu(kwu).is_some());

        let weight = Weight::from_kwu(kwu).unwrap();
        assert_eq!(weight.to_kwu_floor(), kwu);
    }

    /// Verify that `checked_add` returns `None` exactly when u64 addition
    /// overflows, and the correct value otherwise.
    #[kani::proof]
    fn check_weight_checked_add() {
        let a = kani::any::<u64>();
        let b = kani::any::<u64>();

        let wa = Weight::from_wu(a);
        let wb = Weight::from_wu(b);
        let result = wa.checked_add(wb);

        match a.checked_add(b) {
            Some(sum) => {
                assert!(result.is_some());
                assert_eq!(result.unwrap().to_wu(), sum);
            }
            None => assert!(result.is_none()),
        }
    }

    /// Verify that `checked_sub` returns `None` exactly when a < b, and
    /// `Some(a - b)` otherwise.
    #[kani::proof]
    fn check_weight_checked_sub() {
        let a = kani::any::<u64>();
        let b = kani::any::<u64>();

        let wa = Weight::from_wu(a);
        let wb = Weight::from_wu(b);
        let result = wa.checked_sub(wb);

        if a >= b {
            assert!(result.is_some());
            assert_eq!(result.unwrap().to_wu(), a - b);
        } else {
            assert!(result.is_none());
        }
    }

    /// Verify that `from_vb` returns `None` exactly when `vb * 4` overflows u64.
    #[kani::proof]
    fn check_weight_from_vb_overflow() {
        let vb = kani::any::<u64>();
        let result = Weight::from_vb(vb);

        match vb.checked_mul(4) {
            Some(wu) => {
                assert!(result.is_some());
                assert_eq!(result.unwrap().to_wu(), wu);
            }
            None => assert!(result.is_none()),
        }
    }

    /// Verify that `from_kwu` returns `None` exactly when `kwu * 1000` overflows u64.
    #[kani::proof]
    fn check_weight_from_kwu_overflow() {
        let kwu = kani::any::<u64>();
        let result = Weight::from_kwu(kwu);

        match kwu.checked_mul(1000) {
            Some(wu) => {
                assert!(result.is_some());
                assert_eq!(result.unwrap().to_wu(), wu);
            }
            None => assert!(result.is_none()),
        }
    }
}
