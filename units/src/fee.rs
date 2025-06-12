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

use crate::{Amount, FeeRate, MathOp, NumOpError as E, NumOpResult, OptionExt, Weight};

impl FeeRate {
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
        match self.checked_mul_by_weight(weight) {
            Some(fee) => fee,
            None => Amount::MAX,
        }
    }

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
    pub fn fee_vb(self, vb: u64) -> Option<Amount> { Weight::from_vb(vb).map(|w| self.to_fee(w)) }

    /// Checked weight multiplication.
    ///
    /// Computes the absolute fee amount for a given [`Weight`] at this fee rate. When the resulting
    /// fee is a non-integer amount, the amount is rounded up, ensuring that the transaction fee is
    /// enough instead of falling short if rounded down.
    ///
    /// Returns [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_mul_by_weight(self, weight: Weight) -> Option<Amount> {
        let wu = weight.to_wu();
        if let Some(fee_kwu) = self.to_sat_per_kwu_floor().checked_mul(wu) {
            // Bump by 999 to do ceil division using kwu.
            if let Some(bump) = fee_kwu.checked_add(999) {
                let fee = bump / 1_000;
                if let Ok(fee_amount) = Amount::from_sat(fee) {
                    return Some(fee_amount);
                }
            }
        }
        None
    }
}

crate::internal_macros::impl_op_for_references! {
    impl ops::Mul<FeeRate> for Weight {
        type Output = NumOpResult<Amount>;
        fn mul(self, rhs: FeeRate) -> Self::Output {
            match rhs.checked_mul_by_weight(self) {
                Some(amount) => R::Valid(amount),
                None => R::Error(E::while_doing(MathOp::Mul)),
            }
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
            match self.checked_mul_by_weight(rhs) {
                Some(amount) => R::Valid(amount),
                None => R::Error(E::while_doing(MathOp::Mul)),
            }
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
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(863).unwrap());
    }

    #[test]
    fn fee_wu() {
        let fee_rate = FeeRate::from_sat_per_vb(2).unwrap();
        let weight = Weight::from_vb(3).unwrap();
        assert_eq!(fee_rate.to_fee(weight), Amount::from_sat_u32(6));
    }

    #[test]
    fn checked_weight_mul() {
        let weight = Weight::from_vb(10).unwrap();
        let fee: Amount = FeeRate::from_sat_per_vb(10)
            .unwrap()
            .checked_mul_by_weight(weight)
            .expect("expected Amount");
        assert_eq!(Amount::from_sat_u32(100), fee);

        let fee = FeeRate::from_sat_per_kwu(10).unwrap().checked_mul_by_weight(Weight::MAX);
        assert!(fee.is_none());

        let weight = Weight::from_vb(3).unwrap();
        let fee_rate = FeeRate::from_sat_per_vb(3).unwrap();
        let fee = fee_rate.checked_mul_by_weight(weight).unwrap();
        assert_eq!(Amount::from_sat_u32(9), fee);

        let weight = Weight::from_wu(381);
        let fee_rate = FeeRate::from_sat_per_kwu(864).unwrap();
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
        let fee_rate = FeeRate::from_sat_per_kwu(2).unwrap();
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
        let fee_rate = FeeRate::from_sat_per_kwu(3).unwrap();
        let weight = (amount / fee_rate).unwrap();
        // 1000 * 1000 = 1,000,000 msats
        // 1,000,000 / 3 = 333,333.33... wu
        // Should truncate down to 333,333 wu
        assert_eq!(weight, Weight::from_wu(333_333));

        // Verify that ceiling division gives different result
        let ceil_weight = amount.checked_div_by_fee_rate_ceil(fee_rate).unwrap();
        assert_eq!(ceil_weight, Weight::from_wu(333_334));

        // Test that division by zero returns None
        let zero_rate = FeeRate::from_sat_per_kwu(0).unwrap();
        assert!(amount.checked_div_by_fee_rate_floor(zero_rate).is_none());
        assert!(amount.checked_div_by_fee_rate_ceil(zero_rate).is_none());
    }
}
