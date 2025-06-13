// SPDX-License-Identifier: CC0-1.0

//! Calculate transaction fee ([`Amount`]) from a [`FeeRate`] and [`Weight`].
//!
//! The total fee for a transaction can be calculated by multiplying the transaction weight by the
//! fee rate used to send the transaction.
//!
//! Either the weight or fee rate can be calculated if one knows the total fee and either of the
//! other values. Note however that such calculations truncate (as for integer division).
//!
//! We provide `fee.div_by_weight_ceil(weight)` to calculate a minimum threshold fee rate
//! required to pay at least `fee` for transaction with `weight`.
//!
//! We support various `core::ops` traits all of which return [`NumOpResult<T>`].
//!
//! For specific methods see:
//!
//! * [`Amount::div_by_weight_floor`]
//! * [`Amount::div_by_weight_ceil`]
//! * [`Amount::div_by_fee_rate_floor`]
//! * [`Amount::div_by_fee_rate_ceil`]
//! * [`Weight::mul_by_fee_rate`]
//! * [`FeeRate::mul_by_weight`]
//! * [`FeeRate::to_fee`]

use core::ops;

use NumOpResult as R;

use crate::{Amount, FeeRate, NumOpResult, Weight};

crate::internal_macros::impl_op_for_references! {
    impl ops::Mul<FeeRate> for Weight {
        type Output = NumOpResult<Amount>;
        fn mul(self, rhs: FeeRate) -> Self::Output { rhs.mul_by_weight(self) }
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
        fn mul(self, rhs: Weight) -> Self::Output { self.mul_by_weight(rhs) }
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
            self.div_by_weight_floor(rhs)
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
            self.div_by_fee_rate_floor(rhs)
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
    fn weight_mul() {
        let weight = Weight::from_vb(10).unwrap();
        let fee: Amount =
            FeeRate::from_sat_per_vb(10).unwrap().mul_by_weight(weight).expect("expected Amount");
        assert_eq!(Amount::from_sat_u32(100), fee);

        let fee = FeeRate::from_sat_per_kwu(10).unwrap().mul_by_weight(Weight::MAX);
        assert!(fee.is_error());

        let weight = Weight::from_vb(3).unwrap();
        let fee_rate = FeeRate::from_sat_per_vb(3).unwrap();
        let fee = fee_rate.mul_by_weight(weight).unwrap();
        assert_eq!(Amount::from_sat_u32(9), fee);

        let weight = Weight::from_wu(381);
        let fee_rate = FeeRate::from_sat_per_kwu(864).unwrap();
        let fee = weight.mul_by_fee_rate(fee_rate).unwrap();
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
        let ceil_weight = amount.div_by_fee_rate_ceil(fee_rate).unwrap();
        assert_eq!(ceil_weight, Weight::from_wu(333_334));

        // Test that division by zero returns None
        let zero_rate = FeeRate::from_sat_per_kwu(0).unwrap();
        assert!(amount.div_by_fee_rate_floor(zero_rate).is_error());
        assert!(amount.div_by_fee_rate_ceil(zero_rate).is_error());
    }
}
