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

    /// Checked weight multiplication.
    ///
    /// Computes the absolute fee amount for a given [`Weight`] at this fee rate.
    ///
    /// `None` is returned if an overflow occurred.
    pub fn checked_mul_by_weight(self, rhs: Weight) -> Option<Amount> {
        let sats = self.0.checked_mul(rhs.to_wu())?.checked_add(999)? / 1000;
        Some(Amount::from_sat(sats))
    }

    /// Calculates fee by multiplying this fee rate by weight, in weight units, returning `None`
    /// if overflow occurred.
    ///
    /// This is equivalent to `Self::checked_mul_by_weight()`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin::{absolute, transaction, FeeRate, Transaction};
    /// # // Dummy transaction.
    /// # let tx = Transaction { version: transaction::Version::ONE, lock_time: absolute::LockTime::ZERO, input: vec![], output: vec![] };
    ///
    /// let rate = FeeRate::from_sat_per_vb(1).expect("1 sat/vbyte is valid");
    /// let fee = rate.fee_wu(tx.weight()).unwrap();
    /// assert_eq!(fee.to_sat(), tx.vsize() as u64);
    /// ```
    pub fn fee_wu(self, weight: Weight) -> Option<Amount> { self.checked_mul_by_weight(weight) }

    /// Calculates fee by multiplying this fee rate by weight, in virtual bytes, returning `None`
    /// if overflow occurred.
    ///
    /// This is equivalent to converting `vb` to `weight` using `Weight::from_vb` and then calling
    /// `Self::fee_wu(weight)`.
    pub fn fee_vb(self, vb: u64) -> Option<Amount> {
        Weight::from_vb(vb).and_then(|w| self.fee_wu(w))
    }
}

/// Alternative will display the unit.
impl fmt::Display for FeeRate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "{}.00 sat/vbyte", self.to_sat_per_vb_ceil())
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
    type Output = Amount;

    fn mul(self, rhs: FeeRate) -> Self::Output {
        Amount::from_sat((rhs.to_sat_per_kwu() * self.to_wu() + 999) / 1000)
    }
}

impl Mul<Weight> for FeeRate {
    type Output = Amount;

    fn mul(self, rhs: Weight) -> Self::Output { rhs * self }
}

impl Div<Weight> for Amount {
    type Output = FeeRate;

    fn div(self, rhs: Weight) -> Self::Output { FeeRate(self.to_sat() * 1000 / rhs.to_wu()) }
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
    fn checked_weight_mul_test() {
        let weight = Weight::from_vb(10).unwrap();
        let fee: Amount = FeeRate::from_sat_per_vb(10)
            .unwrap()
            .checked_mul_by_weight(weight)
            .expect("expected Amount");
        assert_eq!(Amount::from_sat(100), fee);

        let fee = FeeRate(10).checked_mul_by_weight(Weight::MAX);
        assert!(fee.is_none());

        let weight = Weight::from_vb(3).unwrap();
        let fee_rate = FeeRate::from_sat_per_vb(3).unwrap();
        let fee = fee_rate.checked_mul_by_weight(weight).unwrap();
        assert_eq!(Amount::from_sat(9), fee);
    }

    #[test]
    fn checked_div_test() {
        let fee_rate = FeeRate(10).checked_div(10).expect("expected feerate in sat/kwu");
        assert_eq!(FeeRate(1), fee_rate);

        let fee_rate = FeeRate(10).checked_div(0);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn fee_convenience_functions_agree() {
        use hex::test_hex_unwrap as hex;

        use crate::blockdata::transaction::Transaction;
        use crate::consensus::Decodable;

        const SOME_TX: &str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";

        let raw_tx = hex!(SOME_TX);
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();

        let rate = FeeRate::from_sat_per_vb(1).expect("1 sat/byte is valid");

        assert_eq!(rate.fee_vb(tx.vsize() as u64), rate.fee_wu(tx.weight()));
    }
}
