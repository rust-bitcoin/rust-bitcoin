// SPDX-License-Identifier: CC0-1.0

//! Implements `Weight` and associated features.

use core::{fmt, ops};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The factor that non-witness serialization data is multiplied by during weight calculation.
pub const WITNESS_SCALE_FACTOR: usize = 4;

/// Represents block weight - the weight of a transaction or block.
///
/// This is an integer newtype representing [`Weight`] in `wu`. It provides protection against mixing
/// up the types as well as basic formatting features.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Weight(u64);

impl Weight {
    /// 0 wu.
    ///
    /// Equivalent to [`MIN`](Self::MIN), may better express intent in some contexts.
    pub const ZERO: Weight = Weight(0);

    /// Minimum possible value (0 wu).
    ///
    /// Equivalent to [`ZERO`](Self::ZERO), may better express intent in some contexts.
    pub const MIN: Weight = Weight(u64::MIN);

    /// Maximum possible value.
    pub const MAX: Weight = Weight(u64::MAX);

    /// The factor that non-witness serialization data is multiplied by during weight calculation.
    pub const WITNESS_SCALE_FACTOR: u64 = WITNESS_SCALE_FACTOR as u64;

    /// The maximum allowed weight for a block, see BIP 141 (network rule).
    pub const MAX_BLOCK: Weight = Weight(4_000_000);

    /// The minimum transaction weight for a valid serialized transaction.
    pub const MIN_TRANSACTION: Weight = Weight(Self::WITNESS_SCALE_FACTOR * 60);

    /// Constructs a new [`Weight`] from weight units.
    pub const fn from_wu(wu: u64) -> Self { Weight(wu) }

    /// Constructs a new [`Weight`] from kilo weight units returning [`None`] if an overflow occurred.
    pub fn from_kwu(wu: u64) -> Option<Self> { wu.checked_mul(1000).map(Weight) }

    /// Constructs a new [`Weight`] from virtual bytes, returning [`None`] if an overflow occurred.
    pub const fn from_vb(vb: u64) -> Option<Self> {
        // No `map()` in const context.
        match vb.checked_mul(Self::WITNESS_SCALE_FACTOR) {
            Some(wu) => Some(Weight::from_wu(wu)),
            None => None,
        }
    }

    /// Constructs a new [`Weight`] from virtual bytes panicking if an overflow occurred.
    ///
    /// # Panics
    ///
    /// If the conversion from virtual bytes overflows.
    #[deprecated(since = "TBD", note = "use `from_vb_unchecked` instead")]
    pub const fn from_vb_unwrap(vb: u64) -> Weight {
        match vb.checked_mul(Self::WITNESS_SCALE_FACTOR) {
            Some(weight) => Weight(weight),
            None => panic!("checked_mul overflowed"),
        }
    }

    /// Constructs a new [`Weight`] from virtual bytes without an overflow check.
    pub const fn from_vb_unchecked(vb: u64) -> Self { Weight::from_wu(vb * 4) }

    /// Constructs a new [`Weight`] from witness size.
    pub const fn from_witness_data_size(witness_size: u64) -> Self { Weight(witness_size) }

    /// Constructs a new [`Weight`] from non-witness size.
    pub const fn from_non_witness_data_size(non_witness_size: u64) -> Self {
        Weight(non_witness_size * Self::WITNESS_SCALE_FACTOR)
    }

    /// Returns raw weight units.
    ///
    /// Can be used instead of `into()` to avoid inference issues.
    pub const fn to_wu(self) -> u64 { self.0 }

    /// Converts to kilo weight units rounding down.
    pub const fn to_kwu_floor(self) -> u64 { self.0 / 1000 }

    /// Converts to kilo weight units rounding up.
    pub const fn to_kwu_ceil(self) -> u64 { (self.0 + 999) / 1000 }

    /// Converts to vB rounding down.
    pub const fn to_vbytes_floor(self) -> u64 { self.0 / Self::WITNESS_SCALE_FACTOR }

    /// Converts to vB rounding up.
    pub const fn to_vbytes_ceil(self) -> u64 {
        (self.0 + Self::WITNESS_SCALE_FACTOR - 1) / Self::WITNESS_SCALE_FACTOR
    }

    /// Checked addition.
    ///
    /// Computes `self + rhs` returning [`None`] if an overflow occurred.
    #[must_use]
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        // No `map()` in const context.
        match self.0.checked_add(rhs.0) {
            Some(wu) => Some(Weight::from_wu(wu)),
            None => None,
        }
    }

    /// Checked subtraction.
    ///
    /// Computes `self - rhs` returning [`None`] if an overflow occurred.
    #[must_use]
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        // No `map()` in const context.
        match self.0.checked_sub(rhs.0) {
            Some(wu) => Some(Weight::from_wu(wu)),
            None => None,
        }
    }

    /// Checked multiplication.
    ///
    /// Computes `self * rhs` returning [`None`] if an overflow occurred.
    #[must_use]
    pub const fn checked_mul(self, rhs: u64) -> Option<Self> {
        // No `map()` in const context.
        match self.0.checked_mul(rhs) {
            Some(wu) => Some(Weight::from_wu(wu)),
            None => None,
        }
    }

    /// Checked division.
    ///
    /// Computes `self / rhs` returning [`None`] if `rhs == 0`.
    #[must_use]
    pub const fn checked_div(self, rhs: u64) -> Option<Self> {
        // No `map()` in const context.
        match self.0.checked_div(rhs) {
            Some(wu) => Some(Weight::from_wu(wu)),
            None => None,
        }
    }
}

/// Alternative will display the unit.
impl fmt::Display for Weight {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "{} wu", self.0)
        } else {
            fmt::Display::fmt(&self.0, f)
        }
    }
}

impl From<Weight> for u64 {
    fn from(value: Weight) -> Self { value.to_wu() }
}

impl ops::Add for Weight {
    type Output = Weight;

    fn add(self, rhs: Weight) -> Self::Output { Weight(self.0 + rhs.0) }
}

impl ops::AddAssign for Weight {
    fn add_assign(&mut self, rhs: Self) { self.0 += rhs.0 }
}

impl ops::Sub for Weight {
    type Output = Weight;

    fn sub(self, rhs: Weight) -> Self::Output { Weight(self.0 - rhs.0) }
}

impl ops::SubAssign for Weight {
    fn sub_assign(&mut self, rhs: Self) { self.0 -= rhs.0 }
}

impl ops::Mul<u64> for Weight {
    type Output = Weight;

    fn mul(self, rhs: u64) -> Self::Output { Weight(self.0 * rhs) }
}

impl ops::Mul<Weight> for u64 {
    type Output = Weight;

    fn mul(self, rhs: Weight) -> Self::Output { Weight(self * rhs.0) }
}

impl ops::MulAssign<u64> for Weight {
    fn mul_assign(&mut self, rhs: u64) { self.0 *= rhs }
}

impl ops::Div<u64> for Weight {
    type Output = Weight;

    fn div(self, rhs: u64) -> Self::Output { Weight(self.0 / rhs) }
}

impl ops::Div<Weight> for Weight {
    type Output = u64;

    fn div(self, rhs: Weight) -> Self::Output { self.to_wu() / rhs.to_wu() }
}

impl ops::DivAssign<u64> for Weight {
    fn div_assign(&mut self, rhs: u64) { self.0 /= rhs }
}

impl core::iter::Sum for Weight {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        Weight(iter.map(Weight::to_wu).sum())
    }
}

impl<'a> core::iter::Sum<&'a Weight> for Weight {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Weight>,
    {
        iter.cloned().sum()
    }
}

crate::impl_parse_str_from_int_infallible!(Weight, u64, from_wu);

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Weight {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let w = u64::arbitrary(u)?;
        Ok(Weight(w))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: Weight = Weight(1);
    const TWO: Weight = Weight(2);
    const FOUR: Weight = Weight(4);

    #[test]
    fn from_kwu() {
        let got = Weight::from_kwu(1).unwrap();
        let want = Weight(1_000);
        assert_eq!(got, want);
    }

    #[test]
    fn from_kwu_overflows() { assert!(Weight::from_kwu(u64::MAX).is_none()) }

    #[test]
    fn from_vb() {
        let got = Weight::from_vb(1).unwrap();
        let want = Weight(4);
        assert_eq!(got, want);
    }

    #[test]
    fn from_vb_overflows() {
        assert!(Weight::from_vb(u64::MAX).is_none());
    }

    #[test]
    fn from_vb_unchecked() {
        let got = Weight::from_vb_unchecked(1);
        let want = Weight(4);
        assert_eq!(got, want);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn from_vb_unchecked_panic() { Weight::from_vb_unchecked(u64::MAX); }

    #[test]
    fn from_witness_data_size() {
        let witness_data_size = 1;
        let got = Weight::from_witness_data_size(witness_data_size);
        let want = Weight(witness_data_size);
        assert_eq!(got, want);
    }

    #[test]
    fn from_non_witness_data_size() {
        let non_witness_data_size = 1;
        let got = Weight::from_non_witness_data_size(non_witness_data_size);
        let want = Weight(non_witness_data_size * 4);
        assert_eq!(got, want);
    }

    #[test]
    fn to_kwu_floor() {
        assert_eq!(Weight(1_000).to_kwu_floor(), 1);
        assert_eq!(Weight(1_999).to_kwu_floor(), 1);
    }

    #[test]
    fn to_kwu_ceil() {
        assert_eq!(Weight(1_000).to_kwu_ceil(), 1);
        assert_eq!(Weight(1_001).to_kwu_ceil(), 2);
    }

    #[test]
    fn to_vb_floor() {
        assert_eq!(Weight(4).to_vbytes_floor(), 1);
        assert_eq!(Weight(5).to_vbytes_floor(), 1);
    }

    #[test]
    fn to_vb_ceil() {
        assert_eq!(Weight(4).to_vbytes_ceil(), 1);
        assert_eq!(Weight(5).to_vbytes_ceil(), 2);
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
}
