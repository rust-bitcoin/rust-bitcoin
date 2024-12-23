// SPDX-License-Identifier: CC0-1.0

//! Implements traits to support the following calculations:
//!
//! - `fee_rate * weight = fee`
//! - `weight = fee / fee_rate`
//! - `fee_rate = fee / weight`
//!
//! In words, the total fee for a transaction is calculated by
//! multiplying the transaction weight by the fee rate.

use core::ops;

use super::{Amount, FeeRate, Weight};

impl FeeRate {
    /// Checked multiplication by weight.
    ///
    /// Computes the absolute fee for a given [`Weight`] at this fee rate. When the resulting fee is
    /// a non-integer amount, the amount is rounded up, ensuring that the transaction fee is enough
    /// instead of falling short if rounded down.
    ///
    /// # Returns
    ///
    /// Returns [`None`] if overflow occurs or if the resulting fee is larger than
    /// [`Amount::MAX_MONEY`].
    #[must_use]
    pub const fn checked_mul_by_weight(self, weight: Weight) -> Option<Amount> {
        // No `?` operator in const context.
        match self.to_sat_per_kwu().checked_mul(weight.to_wu()) {
            Some(mul_res) => match mul_res.checked_add(999) {
                Some(add_res) => match Amount::from_sat(add_res / 1000) {
                    Ok(fee) => Some(fee),
                    Err(_) => None,
                },
                None => None,
            },
            None => None,
        }
    }
}

impl Amount {
    /// Checked weight ceiling division.
    ///
    /// Computes the fee rate for a transaction with `weight` assuming this amount represents a
    /// transaction fee.
    ///
    /// Rounds up ensuring the transaction fee rate is sufficient. See also
    /// [`Self::checked_div_by_weight_floor`].
    ///
    /// # Returns
    ///
    /// Returns [`None`] if `weight` is zero or the division results in overflow.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::{Amount, FeeRate, Weight};
    /// let amount = Amount::from_sat_unchecked(10);
    /// let weight = Weight::from_wu(300);
    /// let fee_rate = amount.checked_div_by_weight_ceil(weight).expect("Division by weight failed");
    /// assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(34));
    /// ```
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
    /// Computes the fee rate for a transaction with `weight` assuming this amount represents a
    /// transaction fee.
    ///
    /// Does integer division i.e., rounds down. See also [`Self::checked_div_by_weight_ceil`].
    ///
    /// # Returns
    ///
    /// Returns [`None`] if `weight` is zero or the division results in overflow.
    #[must_use]
    pub const fn checked_div_by_weight_floor(self, weight: Weight) -> Option<FeeRate> {
        let fee = match self.to_sat().checked_mul(1_000) {
            Some(fee) => fee,
            None => panic!("unreachable, MAX_MONEY times 1,000 cannot overflow"),
        };
        // No `?` operator in const context.
        match fee.checked_div(weight.to_wu()) {
            Some(fee_rate) => Some(FeeRate::from_sat_per_kwu(fee_rate)),
            None => None,
        }
    }

    /// Checked fee rate floor division.
    ///
    /// Computes the maximum weight for a transaction with `fee_rate` assuming this amount
    /// represents a transaction fee.
    ///
    /// Does integer division i.e., rounds down. This ensures the weight returned is a maximum
    /// threshold ensuring a transaction requires less fees than this amount.
    ///
    /// # Returns
    ///
    /// Returns [`None`] if `fee_rate` is zero or the division results in overflow.
    #[must_use]
    pub const fn checked_div_by_fee_rate_floor(self, fee_rate: FeeRate) -> Option<Weight> {
        let fee = match self.to_sat().checked_mul(1_000) {
            Some(fee) => fee,
            None => panic!("unreachable, MAX_MONEY times 1,000 cannot overflow"),
        };
        match fee.checked_div(fee_rate.to_sat_per_kwu()) {
            Some(weight) => Some(Weight::from_wu(weight)),
            None => None,
        }
    }
}

/// Computes the ceiling so that the fee computation is conservative.
impl ops::Mul<FeeRate> for Weight {
    type Output = Option<Amount>;

    fn mul(self, rhs: FeeRate) -> Self::Output { rhs.checked_mul_by_weight(self) }
}

impl ops::Mul<Weight> for FeeRate {
    type Output = Option<Amount>;

    fn mul(self, rhs: Weight) -> Self::Output { self.checked_mul_by_weight(rhs) }
}

impl ops::Div<Weight> for Amount {
    type Output = FeeRate;

    /// Truncating integer division.
    ///
    /// This is likely the wrong thing for a user dividing an amount by a weight. Consider using
    /// [`Amount::checked_div_by_weight_ceil`] instead.
    ///
    /// # Panics
    ///
    /// This operation will panic if `weight` is zero or the division results in overflow.
    fn div(self, rhs: Weight) -> Self::Output { self.checked_div_by_weight_floor(rhs).unwrap() }
}

impl ops::Div<FeeRate> for Amount {
    type Output = Weight;

    /// Truncating integer division.
    ///
    /// # Panics
    ///
    /// This operation will panic if `fee_rate` is zero or the division results in overflow.
    fn div(self, rhs: FeeRate) -> Self::Output { self.checked_div_by_fee_rate_floor(rhs).unwrap() }
}
