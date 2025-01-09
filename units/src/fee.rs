// SPDX-License-Identifier: CC0-1.0

//! Calculate transaction fee ([`Amount`]) from a [`FeeRate`] and [`Weight`].
//!
//! The total fee for a transaction can be calculated by multiplying the transaction weight by the
//! fee rate used to send the transaction.
//!
//! Either the weight or fee rate can be calculated if one knows the total fee and either of the
//! other values. Note however that such calculations truncate (as for integer division).
//!
//! We provide `fee.checked_div_by_weight_ceil(weight)` to calculate a minimum threshold fee rate
//! required to pay at least `fee` for transaction with `weight`.

use core::ops;

use crate::{Amount, FeeRate, Weight};

impl Amount {
    /// Checked weight ceiling division.
    ///
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made. This method rounds up ensuring the transaction fee-rate is
    /// sufficient. See also [`Self::checked_div_by_weight_floor`].
    ///
    /// Returns [`None`] if overflow occurred.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::{Amount, FeeRate, Weight};
    /// let amount = Amount::from_sat(10);
    /// let weight = Weight::from_wu(300);
    /// let fee_rate = amount.checked_div_by_weight_ceil(weight).expect("Division by weight failed");
    /// assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(34));
    /// ```
    #[cfg(feature = "alloc")]
    #[must_use]
    pub const fn checked_div_by_weight_ceil(self, weight: Weight) -> Option<FeeRate> {
        let wu = weight.to_wu();
        // No `?` operator in const context.
        if let Some(sats) = self.to_sat().checked_mul(1_000) {
            if let Some(wu_minus_one) = wu.checked_sub(1) {
                if let Some(sats_plus_wu_minus_one) = sats.checked_add(wu_minus_one) {
                    if let Some(fee_rate) = sats_plus_wu_minus_one.checked_div(wu) {
                        return Some(FeeRate::from_sat_per_kwu(fee_rate));
                    }
                }
            }
        }
        None
    }

    /// Checked weight floor division.
    ///
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made. See also [`Self::checked_div_by_weight_ceil`].
    ///
    /// Returns [`None`] if overflow occurred.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub const fn checked_div_by_weight_floor(self, weight: Weight) -> Option<FeeRate> {
        // No `?` operator in const context.
        match self.to_sat().checked_mul(1_000) {
            Some(res) => match res.checked_div(weight.to_wu()) {
                Some(fee_rate) => Some(FeeRate::from_sat_per_kwu(fee_rate)),
                None => None,
            },
            None => None,
        }
    }
}

impl FeeRate {
    /// Calculates the fee by multiplying this fee rate by weight, in weight units, returning [`None`]
    /// if an overflow occurred.
    ///
    /// This is equivalent to `Self::checked_mul_by_weight()`.
    #[must_use]
    pub fn fee_wu(self, weight: Weight) -> Option<Amount> { self.checked_mul_by_weight(weight) }

    /// Calculates the fee by multiplying this fee rate by weight, in virtual bytes, returning [`None`]
    /// if an overflow occurred.
    ///
    /// This is equivalent to converting `vb` to [`Weight`] using [`Weight::from_vb`] and then calling
    /// `Self::fee_wu(weight)`.
    #[must_use]
    pub fn fee_vb(self, vb: u64) -> Option<Amount> {
        Weight::from_vb(vb).and_then(|w| self.fee_wu(w))
    }

    /// Checked weight multiplication.
    ///
    /// Computes the absolute fee amount for a given [`Weight`] at this fee rate.
    /// When the resulting fee is a non-integer amount, the amount is rounded up,
    /// ensuring that the transaction fee is enough instead of falling short if
    /// rounded down.
    ///
    /// [`None`] is returned if an overflow occurred.
    #[must_use]
    pub const fn checked_mul_by_weight(self, weight: Weight) -> Option<Amount> {
        // No `?` operator in const context.
        match self.to_sat_per_kwu().checked_mul(weight.to_wu()) {
            Some(mul_res) => match mul_res.checked_add(999) {
                Some(add_res) => Some(Amount::from_sat(add_res / 1000)),
                None => None,
            },
            None => None,
        }
    }
}

/// Computes the ceiling so that the fee computation is conservative.
impl ops::Mul<FeeRate> for Weight {
    type Output = Amount;

    fn mul(self, rhs: FeeRate) -> Self::Output {
        Amount::from_sat((rhs.to_sat_per_kwu() * self.to_wu() + 999) / 1000)
    }
}

impl ops::Mul<Weight> for FeeRate {
    type Output = Amount;

    fn mul(self, rhs: Weight) -> Self::Output { rhs * self }
}

impl ops::Div<Weight> for Amount {
    type Output = FeeRate;

    /// Truncating integer division.
    ///
    /// This is likely the wrong thing for a user dividing an amount by a weight. Consider using
    /// `checked_div_by_weight` instead.
    fn div(self, rhs: Weight) -> Self::Output {
        FeeRate::from_sat_per_kwu(self.to_sat() * 1000 / rhs.to_wu())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_rate_div_by_weight() {
        let fee_rate = Amount::from_sat(329) / Weight::from_wu(381);
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(863));
    }

    #[test]
    fn fee_wu() {
        let fee_overflow = FeeRate::from_sat_per_kwu(10).fee_wu(Weight::MAX);
        assert!(fee_overflow.is_none());

        let fee_rate = FeeRate::from_sat_per_vb(2).unwrap();
        let weight = Weight::from_vb(3).unwrap();
        assert_eq!(fee_rate.fee_wu(weight).unwrap(), Amount::from_sat(6));
    }

    #[test]
    fn fee_vb() {
        let fee_overflow = FeeRate::from_sat_per_kwu(10).fee_vb(Weight::MAX.to_wu());
        assert!(fee_overflow.is_none());

        let fee_rate = FeeRate::from_sat_per_vb(2).unwrap();
        assert_eq!(fee_rate.fee_vb(3).unwrap(), Amount::from_sat(6));
    }

    #[test]
    fn checked_weight_mul() {
        let weight = Weight::from_vb(10).unwrap();
        let fee: Amount = FeeRate::from_sat_per_vb(10)
            .unwrap()
            .checked_mul_by_weight(weight)
            .expect("expected Amount");
        assert_eq!(Amount::from_sat(100), fee);

        let fee = FeeRate::from_sat_per_kwu(10).checked_mul_by_weight(Weight::MAX);
        assert!(fee.is_none());

        let weight = Weight::from_vb(3).unwrap();
        let fee_rate = FeeRate::from_sat_per_vb(3).unwrap();
        let fee = fee_rate.checked_mul_by_weight(weight).unwrap();
        assert_eq!(Amount::from_sat(9), fee);

        let weight = Weight::from_wu(381);
        let fee_rate = FeeRate::from_sat_per_kwu(864);
        let fee = fee_rate.checked_mul_by_weight(weight).unwrap();
        // 381 * 0.864 yields 329.18.
        // The result is then rounded up to 330.
        assert_eq!(fee, Amount::from_sat(330));
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn multiply() {
        let two = FeeRate::from_sat_per_vb(2).unwrap();
        let three = Weight::from_vb(3).unwrap();
        let six = Amount::from_sat(6);

        assert_eq!(two * three, six);
    }
}
