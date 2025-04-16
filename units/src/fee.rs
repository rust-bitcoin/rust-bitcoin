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

use NumOpResult as R;

use crate::{Amount, FeeRate, MathOp, NumOpResult, OptionExt, Weight};

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
    /// # use bitcoin_units::{amount, Amount, FeeRate, Weight};
    /// let amount = Amount::from_sat(10)?;
    /// let weight = Weight::from_wu(300);
    /// let fee_rate = amount.checked_div_by_weight_ceil(weight);
    /// assert_eq!(fee_rate, Some(FeeRate::from_sat_per_kwu(34)));
    /// # Ok::<_, amount::OutOfRangeError>(())
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
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made. See also [`Self::checked_div_by_weight_ceil`].
    ///
    /// Returns [`None`] if overflow occurred.
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

    /// Checked fee rate floor division.
    ///
    /// Computes the maximum weight that would result in a fee less than or equal to this amount
    /// at the given `fee_rate`. Uses floor division to ensure the resulting weight doesn't cause
    /// the fee to exceed the amount.
    ///
    /// Returns [`None`] if overflow occurred or if `fee_rate` is zero.
    #[must_use]
    pub const fn checked_div_by_fee_rate_floor(self, fee_rate: FeeRate) -> Option<Weight> {
        match self.to_sat().checked_mul(1000) {
            Some(amount_msats) => match amount_msats.checked_div(fee_rate.to_sat_per_kwu()) {
                Some(wu) => Some(Weight::from_wu(wu)),
                None => None,
            },
            None => None,
        }
    }

    /// Checked fee rate ceiling division.
    ///
    /// Computes the minimum weight that would result in a fee greater than or equal to this amount
    /// at the given `fee_rate`. Uses ceiling division to ensure the resulting weight is sufficient.
    ///
    /// Returns [`None`] if overflow occurred or if `fee_rate` is zero.
    #[must_use]
    pub const fn checked_div_by_fee_rate_ceil(self, fee_rate: FeeRate) -> Option<Weight> {
        let rate = fee_rate.to_sat_per_kwu();
        match self.to_sat().checked_mul(1000) {
            Some(amount_msats) => match rate.checked_sub(1) {
                Some(rate_minus_one) => match amount_msats.checked_add(rate_minus_one) {
                    Some(rounded_msats) => match rounded_msats.checked_div(rate) {
                        Some(wu) => Some(Weight::from_wu(wu)),
                        None => None,
                    },
                    None => None,
                },
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
    pub fn to_fee(self, weight: Weight) -> Option<Amount> { self.checked_mul_by_weight(weight) }

    /// Calculates the fee by multiplying this fee rate by weight, in weight units, returning [`None`]
    /// if an overflow occurred.
    ///
    /// This is equivalent to `Self::checked_mul_by_weight()`.
    #[must_use]
    #[deprecated(since = "TBD", note = "use `to_fee()` instead")]
    pub fn fee_wu(self, weight: Weight) -> Option<Amount> { self.checked_mul_by_weight(weight) }

    /// Calculates the fee by multiplying this fee rate by weight, in virtual bytes, returning [`None`]
    /// if an overflow occurred.
    ///
    /// This is equivalent to converting `vb` to [`Weight`] using [`Weight::from_vb`] and then calling
    /// `Self::fee_wu(weight)`.
    #[must_use]
    #[deprecated(since = "TBD", note = "use Weight::from_vb and then `to_fee()` instead")]
    pub fn fee_vb(self, vb: u64) -> Option<Amount> {
        Weight::from_vb(vb).and_then(|w| self.to_fee(w))
    }

    /// Checked weight multiplication.
    ///
    /// Computes the absolute fee amount for a given [`Weight`] at this fee rate. When the resulting
    /// fee is a non-integer amount, the amount is rounded up, ensuring that the transaction fee is
    /// enough instead of falling short if rounded down.
    ///
    /// Returns [`None`] if overflow occurred.
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

crate::internal_macros::impl_op_for_references! {
    impl ops::Mul<FeeRate> for Weight {
        type Output = NumOpResult<Amount>;
        fn mul(self, rhs: FeeRate) -> Self::Output {
            rhs.checked_mul_by_weight(self).valid_or_error(MathOp::Mul)
        }
    }
    impl ops::Mul<FeeRate> for NumOpResult<Weight> {
        type Output = NumOpResult<Amount>;
        fn mul(self, rhs: FeeRate) -> Self::Output {
            match self {
                R::Valid(lhs) => lhs * rhs,
                R::Error(e) => NumOpResult::Error(e),
            }
        }
    }
    impl ops::Mul<NumOpResult<FeeRate>> for Weight {
        type Output = NumOpResult<Amount>;
        fn mul(self, rhs: NumOpResult<FeeRate>) -> Self::Output {
            match rhs {
                R::Valid(fee_rate) => self * fee_rate,
                R::Error(e) => NumOpResult::Error(e),
            }
        }
    }
    impl ops::Mul<NumOpResult<FeeRate>> for NumOpResult<Weight> {
        type Output = NumOpResult<Amount>;
        fn mul(self, rhs: NumOpResult<FeeRate>) -> Self::Output {
            match self {
                R::Valid(lhs) => { match rhs {
                    R::Valid(fee_rate) => lhs * fee_rate,
                    R::Error(e) => NumOpResult::Error(e),
                }}
                R::Error(e) => NumOpResult::Error(e),
            }
        }
    }

    impl ops::Mul<Weight> for FeeRate {
        type Output = NumOpResult<Amount>;
        fn mul(self, rhs: Weight) -> Self::Output {
            self.checked_mul_by_weight(rhs).valid_or_error(MathOp::Mul)
        }
    }
    impl ops::Mul<Weight> for NumOpResult<FeeRate> {
        type Output = NumOpResult<Amount>;
        fn mul(self, rhs: Weight) -> Self::Output {
            match self {
                R::Valid(lhs) => lhs * rhs,
                R::Error(e) => NumOpResult::Error(e),
            }
        }
    }
    impl ops::Mul<NumOpResult<Weight>> for FeeRate {
        type Output = NumOpResult<Amount>;
        fn mul(self, rhs: NumOpResult<Weight>) -> Self::Output {
            match rhs {
                R::Valid(weight) => self * weight,
                R::Error(e) => NumOpResult::Error(e),
            }
        }
    }
    impl ops::Mul<NumOpResult<Weight>> for NumOpResult<FeeRate> {
        type Output = NumOpResult<Amount>;
        fn mul(self, rhs: NumOpResult<Weight>) -> Self::Output {
            match self {
                R::Valid(lhs) => { match rhs {
                    R::Valid(weight) => lhs * weight,
                    R::Error(e) => NumOpResult::Error(e),
                }}
                R::Error(e) => NumOpResult::Error(e),
            }
        }
    }

    impl ops::Div<Weight> for Amount {
        type Output = NumOpResult<FeeRate>;

        fn div(self, rhs: Weight) -> Self::Output {
            self.checked_div_by_weight_floor(rhs).valid_or_error(MathOp::Div)
        }
    }
    impl ops::Div<Weight> for NumOpResult<Amount> {
        type Output = NumOpResult<FeeRate>;

        fn div(self, rhs: Weight) -> Self::Output {
            match self {
                R::Valid(lhs) => lhs / rhs,
                R::Error(e) => NumOpResult::Error(e),
            }
        }
    }
    impl ops::Div<NumOpResult<Weight>> for Amount {
        type Output = NumOpResult<FeeRate>;

        fn div(self, rhs: NumOpResult<Weight>) -> Self::Output {
            match rhs {
                R::Valid(weight) => self / weight,
                R::Error(e) => NumOpResult::Error(e),
            }
        }
    }
    impl ops::Div<NumOpResult<Weight>> for NumOpResult<Amount> {
        type Output = NumOpResult<FeeRate>;

        fn div(self, rhs: NumOpResult<Weight>) -> Self::Output {
            match self {
                R::Valid(lhs) => { match rhs {
                    R::Valid(weight) => lhs / weight,
                    R::Error(e) => NumOpResult::Error(e),
                }}
                R::Error(e) => NumOpResult::Error(e),
            }
        }
    }

    impl ops::Div<FeeRate> for Amount {
        type Output = NumOpResult<Weight>;

        fn div(self, rhs: FeeRate) -> Self::Output {
            self.checked_div_by_fee_rate_floor(rhs).valid_or_error(MathOp::Div)
        }
    }
    impl ops::Div<FeeRate> for NumOpResult<Amount> {
        type Output = NumOpResult<Weight>;

        fn div(self, rhs: FeeRate) -> Self::Output {
            match self {
                R::Valid(lhs) => lhs / rhs,
                R::Error(e) => NumOpResult::Error(e),
            }
        }
    }
    impl ops::Div<NumOpResult<FeeRate>> for Amount {
        type Output = NumOpResult<Weight>;

        fn div(self, rhs: NumOpResult<FeeRate>) -> Self::Output {
            match rhs {
                R::Valid(fee_rate) => self / fee_rate,
                R::Error(e) => NumOpResult::Error(e),
            }
        }
    }
    impl ops::Div<NumOpResult<FeeRate>> for NumOpResult<Amount> {
        type Output = NumOpResult<Weight>;

        fn div(self, rhs: NumOpResult<FeeRate>) -> Self::Output {
            match self {
                R::Valid(lhs) => { match rhs {
                    R::Valid(fee_rate) => lhs / fee_rate,
                    R::Error(e) => NumOpResult::Error(e),
                }}
                R::Error(e) => NumOpResult::Error(e),
            }
        }
    }
}

impl Weight {
    /// Checked fee rate multiplication.
    ///
    /// Computes the absolute fee amount for a given [`FeeRate`] at this weight. When the resulting
    /// fee is a non-integer amount, the amount is rounded up, ensuring that the transaction fee is
    /// enough instead of falling short if rounded down.
    ///
    /// Returns [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_mul_by_fee_rate(self, fee_rate: FeeRate) -> Option<Amount> {
        fee_rate.checked_mul_by_weight(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_rate_div_by_weight() {
        let fee_rate = (Amount::from_sat_u32(329) / Weight::from_wu(381)).unwrap();
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(863));
    }

    #[test]
    fn fee_wu() {
        let fee_overflow = FeeRate::from_sat_per_kwu(10).to_fee(Weight::MAX);
        assert!(fee_overflow.is_none());

        let fee_rate = FeeRate::from_sat_per_vb(2).unwrap();
        let weight = Weight::from_vb(3).unwrap();
        assert_eq!(fee_rate.to_fee(weight).unwrap(), Amount::from_sat_u32(6));
    }

    #[test]
    fn checked_weight_mul() {
        let weight = Weight::from_vb(10).unwrap();
        let fee: Amount = FeeRate::from_sat_per_vb(10)
            .unwrap()
            .checked_mul_by_weight(weight)
            .expect("expected Amount");
        assert_eq!(Amount::from_sat_u32(100), fee);

        let fee = FeeRate::from_sat_per_kwu(10).checked_mul_by_weight(Weight::MAX);
        assert!(fee.is_none());

        let weight = Weight::from_vb(3).unwrap();
        let fee_rate = FeeRate::from_sat_per_vb(3).unwrap();
        let fee = fee_rate.checked_mul_by_weight(weight).unwrap();
        assert_eq!(Amount::from_sat_u32(9), fee);

        let weight = Weight::from_wu(381);
        let fee_rate = FeeRate::from_sat_per_kwu(864);
        let fee = weight.checked_mul_by_fee_rate(fee_rate).unwrap();
        // 381 * 0.864 yields 329.18.
        // The result is then rounded up to 330.
        assert_eq!(fee, Amount::from_sat_u32(330));
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn multiply() {
        let two = FeeRate::from_sat_per_vb(2).unwrap();
        let three = Weight::from_vb(3).unwrap();
        let six = Amount::from_sat_u32(6);

        assert_eq!(two * three, six.into());

        // Test reference operators
        assert_eq!(&two * three, six.into());
        assert_eq!(two * &three, six.into());
        assert_eq!(&two * &three, six.into());
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn amount_div_by_fee_rate() {
        // Test exact division
        let amount = Amount::from_sat_u32(1000);
        let fee_rate = FeeRate::from_sat_per_kwu(2);
        let weight = (amount / fee_rate).unwrap();
        assert_eq!(weight, Weight::from_wu(500_000));

        // Test reference division
        let weight_ref = (&amount / fee_rate).unwrap();
        assert_eq!(weight_ref, Weight::from_wu(500_000));
        let weight_ref2 = (amount / &fee_rate).unwrap();
        assert_eq!(weight_ref2, Weight::from_wu(500_000));
        let weight_ref3 = (&amount / &fee_rate).unwrap();
        assert_eq!(weight_ref3, Weight::from_wu(500_000));

        // Test truncation behavior
        let amount = Amount::from_sat_u32(1000);
        let fee_rate = FeeRate::from_sat_per_kwu(3);
        let weight = (amount / fee_rate).unwrap();
        // 1000 * 1000 = 1,000,000 msats
        // 1,000,000 / 3 = 333,333.33... wu
        // Should truncate down to 333,333 wu
        assert_eq!(weight, Weight::from_wu(333_333));

        // Verify that ceiling division gives different result
        let ceil_weight = amount.checked_div_by_fee_rate_ceil(fee_rate).unwrap();
        assert_eq!(ceil_weight, Weight::from_wu(333_334));

        // Test that division by zero returns None
        let zero_rate = FeeRate::from_sat_per_kwu(0);
        assert!(amount.checked_div_by_fee_rate_floor(zero_rate).is_none());
        assert!(amount.checked_div_by_fee_rate_ceil(zero_rate).is_none());
    }
}
