// SPDX-License-Identifier: CC0-1.0

//! Implements `FeeRate` and assoctiated features.

use core::fmt;
use core::ops::{Div, Mul};

use super::Weight;
use crate::Amount;

/// Represents fee rate.
///
/// This is an integer newtype representing fee rate in `sat/kwu`. It provides protection against mixing
/// up the types as well as basic formatting features.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FeeRate {
    per_kwu: Amount,
}

impl FeeRate {
    /// 0 sat/kwu.
    ///
    /// Equivalent to [`MIN`](Self::MIN), may better express intent in some contexts.
    pub const ZERO: FeeRate = FeeRate { per_kwu: Amount::ZERO };

    /// Minimum possible value (0 sat/kwu).
    ///
    /// Equivalent to [`ZERO`](Self::ZERO), may better express intent in some contexts.
    pub const MIN: FeeRate = FeeRate::ZERO;

    /// Maximum possible value.
    pub const MAX: FeeRate = FeeRate { per_kwu: Amount::MAX };

    /// Minimum fee rate required to broadcast a transaction.
    ///
    /// The value matches the default Bitcoin Core policy at the time of library release.
    pub const BROADCAST_MIN: FeeRate = FeeRate::from_per_vb_unchecked(Amount::from_sat(1));

    /// Fee rate used to compute dust amount.
    pub const DUST: FeeRate = FeeRate::from_per_vb_unchecked(Amount::from_sat(3));

    /// Constructs `FeeRate` from an amount per 1000 weight units.
    pub const fn from_per_kwu(per_kwu: Amount) -> Self { FeeRate { per_kwu } }

    /// Constructs `FeeRate` from an amount per virtual bytes.
    ///
    /// # Errors
    ///
    /// Returns `None` on arithmetic overflow.
    pub const fn from_per_vb(per_vb: Amount) -> Option<Self> {
        // 1 vb == 4 wu
        // 1 sat/vb == 1/4 sat/wu
        // sat_vb sat/vb * 1000 / 4 == sat/kwu

        // NB remove indirection after impl const support for ops
        if let Some(per_kwu) = per_vb.checked_mul(1000 / 4) {
            Some(FeeRate { per_kwu })
        } else {
            None
        }
    }

    /// Constructs `FeeRate` from an amount per virtual bytes without overflow check.
    pub const fn from_per_vb_unchecked(per_vb: Amount) -> Self {
        FeeRate { per_kwu: Amount::from_sat(per_vb.to_sat() * (1000 / 4)) }
    }

    /// Returns the fee rate per kilo weight unit.
    pub const fn to_per_kwu(self) -> Amount { self.per_kwu }

    /// Converts to amount per virtual byte rounding down.
    pub const fn to_per_vb_floor(self) -> Amount {
        // NB remove indirection after impl const support for ops
        Amount::from_sat(self.per_kwu.to_sat() / (1000 / 4))
    }

    /// Converts to amount per virtual byte rounding up.
    pub const fn to_per_vb_ceil(self) -> Amount {
        // NB remove indirection after impl const support for ops
        Amount::from_sat((self.per_kwu.to_sat() + 1000 / 4 - 1) / (1000 / 4))
    }

    /// Convert to amount per kilo virtual byte.
    ///
    /// Returns [None] on overflow.
    pub const fn to_per_kvb(self) -> Option<Amount> {
        // NB remove indirection after impl const support for ops
        if let Some(per_kvb) = self.per_kwu.to_sat().checked_mul(4) {
            Some(Amount::from_sat(per_kvb))
        } else {
            None
        }
    }

    /// Constructs `FeeRate` from satoshis per 1000 weight units.
    pub const fn from_sat_per_kwu(sat_kwu: u64) -> Self {
        Self::from_per_kwu(Amount::from_sat(sat_kwu))
    }

    /// Constructs `FeeRate` from satoshis per virtual bytes.
    ///
    /// # Errors
    ///
    /// Returns `None` on arithmetic overflow.
    pub fn from_sat_per_vb(sat_vb: u64) -> Option<Self> {
        Self::from_per_vb(Amount::from_sat(sat_vb))
    }

    /// Constructs `FeeRate` from satoshis per virtual bytes without overflow check.
    pub const fn from_sat_per_vb_unchecked(sat_vb: u64) -> Self {
        Self::from_per_vb_unchecked(Amount::from_sat(sat_vb))
    }

    /// Returns raw fee rate.
    pub const fn to_sat_per_kwu(self) -> u64 { self.to_per_kwu().to_sat() }

    /// Converts to sat/vB rounding down.
    pub const fn to_sat_per_vb_floor(self) -> u64 { self.to_per_vb_floor().to_sat() }

    /// Converts to sat/vB rounding up.
    pub const fn to_sat_per_vb_ceil(self) -> u64 { self.to_per_vb_ceil().to_sat() }

    /// Checked multiplication.
    ///
    /// Computes `self * rhs` returning `None` if overflow occurred.
    pub const fn checked_mul(self, rhs: u64) -> Option<Self> {
        // NB remove indirection after impl const support for ops
        match self.per_kwu.checked_mul(rhs) {
            Some(v) => Some(Self::from_per_kwu(v)),
            None => None,
        }
    }

    /// Checked division.
    ///
    /// Computes `self / rhs` returning `None` if `rhs == 0`.
    pub fn checked_div(self, rhs: u64) -> Option<Self> {
        // NB remove indirection after impl const support for ops
        self.per_kwu.checked_div(rhs).map(Self::from_per_kwu)
    }

    /// Checked weight multiplication.
    ///
    /// Computes `self * rhs` where rhs is of type Weight. `None` is returned if an overflow
    /// occurred.
    pub fn checked_mul_by_weight(self, rhs: Weight) -> Option<Amount> {
        let too_large_by_1000x = self.per_kwu.checked_mul(rhs.to_wu())?;
        Some(too_large_by_1000x / 1000)
    }

    /// Calculates fee by multiplying this fee rate by weight, in weight units, returning `None`
    /// if overflow occurred.
    ///
    /// This is equivalent to `Self::checked_mul_by_weight()`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use bitcoin::{absolute, transaction, FeeRate, Transaction};
    /// # // Dummy transaction.
    /// # let tx = Transaction { version: transaction::Version::ONE, lock_time: absolute::LockTime::ZERO, input: vec![], output: vec![] };
    ///
    /// let rate = FeeRate::from_sat_per_vb(1).expect("1 sat/vbyte is valid");
    /// let fee = rate.fee_wu(tx.weight());
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
            write!(f, "{} sat/kwu (~{} sat/vb)",
                self.per_kwu.to_sat(), self.to_per_vb_ceil().to_sat(),
            )
        } else {
            fmt::Display::fmt(&self.per_kwu, f)
        }
    }
}

/// Computes ceiling so that fee computation is conservative.
impl Mul<FeeRate> for Weight {
    type Output = Amount;

    fn mul(self, rhs: FeeRate) -> Self::Output {
        (rhs.to_per_kwu() * self.to_wu() + Amount::from_sat(999)) / 1000
    }
}

impl Mul<Weight> for FeeRate {
    type Output = Amount;

    fn mul(self, rhs: Weight) -> Self::Output { rhs * self }
}

impl Div<Weight> for Amount {
    type Output = FeeRate;

    fn div(self, rhs: Weight) -> Self::Output {
        FeeRate { per_kwu: self * 1000 / rhs.to_wu() }
    }
}

#[cfg(feature = "serde")]
pub mod serde {
    #![allow(missing_docs)]
    //! A module for serde-serializing fee rates in various units.

    use serde::de::{Deserialize, Deserializer, Error};
    use serde::ser::Serializer;

    use super::{Amount, FeeRate};
    use crate::amount::Denomination;

    pub mod btc_per_kvb {
        //! Serialize fee rates as bitcoin per kilo-virtual bytes.
        use super::*;

        pub fn serialize<S: Serializer>(r: &FeeRate, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_f64((r.to_per_vb_ceil() * 1000).to_btc())
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<FeeRate, D::Error> {
            let btc_per_kvb = f64::deserialize(d)?;
            let per_kwu = Amount::from_btc(btc_per_kvb / 4.0).map_err(D::Error::custom)?;
            Ok(FeeRate::from_per_kwu(per_kwu))
        }

        pub mod opt {
            use super::*;

            pub fn serialize<S: Serializer>(r: &Option<FeeRate>, s: S) -> Result<S::Ok, S::Error> {
                match r {
                    Some(r) => s.serialize_f64((r.to_per_vb_ceil() * 1000).to_btc()),
                    None => s.serialize_none(),
                }
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<FeeRate>, D::Error> {
                let btc_per_kvb = f64::deserialize(d)?;
                let per_kwu = Amount::from_btc(btc_per_kvb / 4.0).map_err(D::Error::custom)?;
                Ok(Some(FeeRate::from_per_kwu(per_kwu)))
            }
        }
    }

    pub mod sat_per_vb {
        use super::*;

        pub fn serialize<S: Serializer>(r: &FeeRate, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_f64(r.to_per_vb_ceil().to_float_in(Denomination::Satoshi))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<FeeRate, D::Error> {
            let sat_per_vb = Amount::from_float_in(f64::deserialize(d)?, Denomination::Satoshi)
                .map_err(D::Error::custom)?;
            FeeRate::from_per_vb(sat_per_vb).ok_or(D::Error::custom("fee rate overflow"))
        }

        pub mod opt {
            use super::*;

            pub fn serialize<S: Serializer>(r: &Option<FeeRate>, s: S) -> Result<S::Ok, S::Error> {
                match r {
                    Some(r) => s.serialize_f64(r.to_per_vb_ceil().to_float_in(Denomination::Satoshi)),
                    None => s.serialize_none(),
                }
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<FeeRate>, D::Error> {
                let sat_per_vb = Amount::from_float_in(f64::deserialize(d)?, Denomination::Satoshi)
                    .map_err(D::Error::custom)?;
                Ok(Some(FeeRate::from_per_vb(sat_per_vb)
                    .ok_or(D::Error::custom("fee rate overflow"))?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::u64;

    use super::*;

    #[test]
    fn fee_rate_const_test() {
        let sat = Amount::from_sat;

        assert_eq!(Amount::ZERO, FeeRate::ZERO.to_per_kwu());
        assert_eq!(Amount::MIN, FeeRate::MIN.to_per_kwu());
        assert_eq!(Amount::MAX, FeeRate::MAX.to_per_kwu());
        assert_eq!(sat(250), FeeRate::BROADCAST_MIN.to_per_kwu());
        assert_eq!(sat(750), FeeRate::DUST.to_per_kwu());
    }

    #[test]
    fn fee_rate_from_sat_per_vb_test() {
        let sat = Amount::from_sat;

        let fee_rate = FeeRate::from_per_vb(sat(10)).expect("expected feerate in sat/kwu");
        assert_eq!(FeeRate::from_per_kwu(sat(2500)), fee_rate);
    }

    #[test]
    fn fee_rate_from_sat_per_vb_overflow_test() {
        let fee_rate = FeeRate::from_per_vb(Amount::MAX);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn from_sat_per_vb_unchecked_test() {
        let sat = Amount::from_sat;

        let fee_rate = FeeRate::from_per_vb_unchecked(sat(10));
        assert_eq!(FeeRate::from_per_kwu(sat(2500)), fee_rate);
    }

    #[test]
    #[should_panic]
    fn from_sat_per_vb_unchecked_panic_test() {
        FeeRate::from_per_vb_unchecked(Amount::MAX);
    }

    #[test]
    fn raw_feerate_test() {
        let sat = Amount::from_sat;

        let fee_rate = FeeRate::from_per_kwu(sat(333));
        assert_eq!(sat(333), fee_rate.to_per_kwu());
        assert_eq!(sat(1), fee_rate.to_per_vb_floor());
        assert_eq!(sat(2), fee_rate.to_per_vb_ceil());
        assert_eq!(sat(4 * 333), fee_rate.to_per_kvb().unwrap());
    }

    #[test]
    fn checked_mul_test() {
        let sat = Amount::from_sat;

        let fee_rate = FeeRate::from_per_kwu(sat(10)).checked_mul(10)
            .expect("expected feerate in sat/kwu");
        assert_eq!(FeeRate::from_per_kwu(sat(100)), fee_rate);

        let fee_rate = FeeRate::from_per_kwu(sat(10)).checked_mul(u64::MAX);
        assert!(fee_rate.is_none());
    }

    #[test]
    fn checked_weight_mul_test() {
        let weight = Weight::from_wu(10);
        let fee = FeeRate::from_per_kwu(Amount::from_sat(10_000))
            .checked_mul_by_weight(weight).expect("expected Amount");
        assert_eq!(Amount::from_sat(100), fee);

        let fee = FeeRate::from_per_kwu(Amount::from_sat(10_000))
            .checked_mul_by_weight(Weight::MAX);
        assert!(fee.is_none());
    }

    #[test]
    fn checked_div_test() {
        let sat = Amount::from_sat;

        let fee_rate = FeeRate::from_per_kwu(sat(10)).checked_div(10)
            .expect("expected feerate in sat/kwu");
        assert_eq!(FeeRate::from_per_kwu(sat(1)), fee_rate);

        let fee_rate = FeeRate::from_per_kwu(sat(10)).checked_div(0);
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

        let rate = FeeRate::from_per_vb(Amount::ONE_SAT).expect("1 sat/byte is valid");

        assert_eq!(rate.fee_vb(tx.vsize() as u64), rate.fee_wu(tx.weight()));
    }
}
