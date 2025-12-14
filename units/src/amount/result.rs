// SPDX-License-Identifier: CC0-1.0

//! Provides a monodic type returned by mathematical operations (`core::ops`).

use core::num::{NonZeroI64, NonZeroU64};
use core::ops;

use NumOpResult as R;

use super::{Amount, SignedAmount};
use crate::internal_macros::{
    impl_add_assign_for_results, impl_div_assign, impl_mul_assign, impl_sub_assign_for_results,
};
use crate::result::{MathOp, NumOpError, NumOpResult, OptionExt};

impl From<Amount> for NumOpResult<Amount> {
    fn from(a: Amount) -> Self { Self::Valid(a) }
}
impl From<&Amount> for NumOpResult<Amount> {
    fn from(a: &Amount) -> Self { Self::Valid(*a) }
}

impl From<SignedAmount> for NumOpResult<SignedAmount> {
    fn from(a: SignedAmount) -> Self { Self::Valid(a) }
}
impl From<&SignedAmount> for NumOpResult<SignedAmount> {
    fn from(a: &SignedAmount) -> Self { Self::Valid(*a) }
}

crate::internal_macros::impl_op_for_references! {
    impl ops::Add<Amount> for Amount {
        type Output = NumOpResult<Amount>;

        fn add(self, rhs: Amount) -> Self::Output { self.checked_add(rhs).valid_or_error(MathOp::Add) }
    }
    impl ops::Add<NumOpResult<Amount>> for Amount {
        type Output = NumOpResult<Amount>;

        fn add(self, rhs: NumOpResult<Amount>) -> Self::Output { rhs.and_then(|a| a + self) }
    }

    impl ops::Sub<Amount> for Amount {
        type Output = NumOpResult<Amount>;

        fn sub(self, rhs: Amount) -> Self::Output { self.checked_sub(rhs).valid_or_error(MathOp::Sub) }
    }
    impl ops::Sub<NumOpResult<Amount>> for Amount {
        type Output = NumOpResult<Amount>;

        fn sub(self, rhs: NumOpResult<Amount>) -> Self::Output {
            match rhs {
                R::Valid(amount) => self - amount,
                R::Error(_) => rhs,
            }
        }
    }

    impl ops::Mul<u64> for Amount {
        type Output = NumOpResult<Amount>;

        fn mul(self, rhs: u64) -> Self::Output { self.checked_mul(rhs).valid_or_error(MathOp::Mul) }
    }
    impl ops::Mul<u64> for NumOpResult<Amount> {
        type Output = NumOpResult<Amount>;

        fn mul(self, rhs: u64) -> Self::Output { self.and_then(|lhs| lhs * rhs) }
    }
    impl ops::Mul<Amount> for u64 {
        type Output = NumOpResult<Amount>;

        fn mul(self, rhs: Amount) -> Self::Output { rhs.checked_mul(self).valid_or_error(MathOp::Mul) }
    }
    impl ops::Mul<NumOpResult<Amount>> for u64 {
        type Output = NumOpResult<Amount>;

        fn mul(self, rhs: NumOpResult<Amount>) -> Self::Output { rhs.and_then(|rhs| self * rhs) }
    }

    impl ops::Div<u64> for Amount {
        type Output = NumOpResult<Amount>;

        fn div(self, rhs: u64) -> Self::Output { self.checked_div(rhs).valid_or_error(MathOp::Div) }
    }
    impl ops::Div<u64> for NumOpResult<Amount> {
        type Output = NumOpResult<Amount>;

        fn div(self, rhs: u64) -> Self::Output { self.and_then(|lhs| lhs / rhs) }
    }
    impl ops::Div<Amount> for Amount {
        type Output = NumOpResult<u64>;

        fn div(self, rhs: Amount) -> Self::Output {
            self.to_sat().checked_div(rhs.to_sat()).valid_or_error(MathOp::Div)
        }
    }
    impl ops::Div<NonZeroU64> for Amount {
        type Output = Amount;

        fn div(self, rhs: NonZeroU64) -> Self::Output { Self::from_sat(self.to_sat() / rhs.get()).expect("construction after division cannot fail") }
    }
    impl ops::Rem<u64> for Amount {
        type Output = NumOpResult<Amount>;

        fn rem(self, modulus: u64) -> Self::Output { self.checked_rem(modulus).valid_or_error(MathOp::Rem) }
    }
    impl ops::Rem<u64> for NumOpResult<Amount> {
        type Output = NumOpResult<Amount>;

        fn rem(self, modulus: u64) -> Self::Output { self.and_then(|lhs| lhs % modulus) }
    }

    impl ops::Add<SignedAmount> for SignedAmount {
        type Output = NumOpResult<SignedAmount>;

        fn add(self, rhs: SignedAmount) -> Self::Output { self.checked_add(rhs).valid_or_error(MathOp::Add) }
    }
    impl ops::Add<NumOpResult<SignedAmount>> for SignedAmount {
        type Output = NumOpResult<SignedAmount>;

        fn add(self, rhs: NumOpResult<SignedAmount>) -> Self::Output { rhs.and_then(|a| a + self) }
    }

    impl ops::Sub<SignedAmount> for SignedAmount {
        type Output = NumOpResult<SignedAmount>;

        fn sub(self, rhs: SignedAmount) -> Self::Output { self.checked_sub(rhs).valid_or_error(MathOp::Sub) }
    }
    impl ops::Sub<NumOpResult<SignedAmount>> for SignedAmount {
        type Output = NumOpResult<SignedAmount>;

        fn sub(self, rhs: NumOpResult<SignedAmount>) -> Self::Output {
            match rhs {
                R::Valid(amount) => self - amount,
                R::Error(_) => rhs,
            }
        }
    }

    impl ops::Mul<i64> for SignedAmount {
        type Output = NumOpResult<SignedAmount>;

        fn mul(self, rhs: i64) -> Self::Output { self.checked_mul(rhs).valid_or_error(MathOp::Mul) }
    }
    impl ops::Mul<i64> for NumOpResult<SignedAmount> {
        type Output = NumOpResult<SignedAmount>;

        fn mul(self, rhs: i64) -> Self::Output { self.and_then(|lhs| lhs * rhs) }
    }
    impl ops::Mul<SignedAmount> for i64 {
        type Output = NumOpResult<SignedAmount>;

        fn mul(self, rhs: SignedAmount) -> Self::Output { rhs.checked_mul(self).valid_or_error(MathOp::Mul) }
    }
    impl ops::Mul<NumOpResult<SignedAmount>> for i64 {
        type Output = NumOpResult<SignedAmount>;

        fn mul(self, rhs: NumOpResult<SignedAmount>) -> Self::Output { rhs.and_then(|rhs| self * rhs) }
    }

    impl ops::Div<i64> for SignedAmount {
        type Output = NumOpResult<SignedAmount>;

        fn div(self, rhs: i64) -> Self::Output { self.checked_div(rhs).valid_or_error(MathOp::Div) }
    }
    impl ops::Div<i64> for NumOpResult<SignedAmount> {
        type Output = NumOpResult<SignedAmount>;

        fn div(self, rhs: i64) -> Self::Output { self.and_then(|lhs| lhs / rhs) }
    }
    impl ops::Div<SignedAmount> for SignedAmount {
        type Output = NumOpResult<i64>;

        fn div(self, rhs: SignedAmount) -> Self::Output {
            self.to_sat().checked_div(rhs.to_sat()).valid_or_error(MathOp::Div)
        }
    }
    impl ops::Div<NonZeroI64> for SignedAmount {
        type Output = SignedAmount;

        fn div(self, rhs: NonZeroI64) -> Self::Output { Self::from_sat(self.to_sat() / rhs.get()).expect("construction after division cannot fail") }
    }
    impl ops::Rem<i64> for SignedAmount {
        type Output = NumOpResult<SignedAmount>;

        fn rem(self, modulus: i64) -> Self::Output { self.checked_rem(modulus).valid_or_error(MathOp::Rem) }
    }
    impl ops::Rem<i64> for NumOpResult<SignedAmount> {
        type Output = NumOpResult<SignedAmount>;

        fn rem(self, modulus: i64) -> Self::Output { self.and_then(|lhs| lhs % modulus) }
    }
}

impl_mul_assign!(NumOpResult<Amount>, u64);
impl_mul_assign!(NumOpResult<SignedAmount>, i64);
impl_div_assign!(NumOpResult<Amount>, u64);
impl_div_assign!(NumOpResult<SignedAmount>, i64);

impl_add_assign_for_results!(Amount);
impl_add_assign_for_results!(SignedAmount);
impl_sub_assign_for_results!(Amount);
impl_sub_assign_for_results!(SignedAmount);

impl ops::Neg for SignedAmount {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::from_sat(self.to_sat().neg()).expect("all +ve and -ve values are valid")
    }
}

impl core::iter::Sum<Self> for NumOpResult<Amount> {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        iter.fold(Self::Valid(Amount::ZERO), |acc, amount| match (acc, amount) {
            (Self::Valid(lhs), Self::Valid(rhs)) => lhs + rhs,
            (_, _) => Self::Error(NumOpError::while_doing(MathOp::Add)),
        })
    }
}
impl<'a> core::iter::Sum<&'a Self> for NumOpResult<Amount> {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        iter.fold(Self::Valid(Amount::ZERO), |acc, amount| match (acc, amount) {
            (Self::Valid(lhs), Self::Valid(rhs)) => lhs + rhs,
            (_, _) => Self::Error(NumOpError::while_doing(MathOp::Add)),
        })
    }
}

impl core::iter::Sum<Self> for NumOpResult<SignedAmount> {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        iter.fold(Self::Valid(SignedAmount::ZERO), |acc, amount| match (acc, amount) {
            (Self::Valid(lhs), Self::Valid(rhs)) => lhs + rhs,
            (_, _) => Self::Error(NumOpError::while_doing(MathOp::Add)),
        })
    }
}
impl<'a> core::iter::Sum<&'a Self> for NumOpResult<SignedAmount> {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        iter.fold(Self::Valid(SignedAmount::ZERO), |acc, amount| match (acc, amount) {
            (Self::Valid(lhs), Self::Valid(rhs)) => lhs + rhs,
            (_, _) => Self::Error(NumOpError::while_doing(MathOp::Add)),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sum_amount_results() {
        let amounts = [
            NumOpResult::Valid(Amount::from_sat_u32(100)),
            NumOpResult::Valid(Amount::from_sat_u32(200)),
            NumOpResult::Valid(Amount::from_sat_u32(300)),
        ];

        let sum: NumOpResult<Amount> = amounts.into_iter().sum();
        assert_eq!(sum, NumOpResult::Valid(Amount::from_sat_u32(600)));
    }

    #[test]
    fn test_sum_amount_results_with_references() {
        let amounts = [
            NumOpResult::Valid(Amount::from_sat_u32(100)),
            NumOpResult::Valid(Amount::from_sat_u32(200)),
            NumOpResult::Valid(Amount::from_sat_u32(300)),
        ];

        let sum: NumOpResult<Amount> = amounts.iter().sum();
        assert_eq!(sum, NumOpResult::Valid(Amount::from_sat_u32(600)));
    }

    #[test]
    fn test_sum_amount_with_error_propagation() {
        let amounts = [
            NumOpResult::Valid(Amount::from_sat_u32(100)),
            NumOpResult::Error(NumOpError::while_doing(MathOp::Add)),
            NumOpResult::Valid(Amount::from_sat_u32(200)),
        ];

        let sum: NumOpResult<Amount> = amounts.into_iter().sum();
        assert!(matches!(sum, NumOpResult::Error(_)));
    }

    #[test]
    fn test_sum_signed_amount_results() {
        let amounts = [
            NumOpResult::Valid(SignedAmount::from_sat_i32(100)),
            NumOpResult::Valid(SignedAmount::from_sat_i32(-50)),
            NumOpResult::Valid(SignedAmount::from_sat_i32(200)),
        ];

        let sum: NumOpResult<SignedAmount> = amounts.into_iter().sum();
        assert_eq!(sum, NumOpResult::Valid(SignedAmount::from_sat_i32(250)));
    }

    #[test]
    fn test_sum_signed_amount_results_with_references() {
        let amounts = [
            NumOpResult::Valid(SignedAmount::from_sat_i32(100)),
            NumOpResult::Valid(SignedAmount::from_sat_i32(-50)),
            NumOpResult::Valid(SignedAmount::from_sat_i32(200)),
        ];

        let sum: NumOpResult<SignedAmount> = amounts.iter().sum();
        assert_eq!(sum, NumOpResult::Valid(SignedAmount::from_sat_i32(250)));
    }

    #[test]
    fn test_sum_signed_amount_with_error_propagation() {
        let amounts = [
            NumOpResult::Valid(SignedAmount::from_sat_i32(100)),
            NumOpResult::Error(NumOpError::while_doing(MathOp::Add)),
            NumOpResult::Valid(SignedAmount::from_sat_i32(200)),
        ];

        let sum: NumOpResult<SignedAmount> = amounts.into_iter().sum();
        assert!(matches!(sum, NumOpResult::Error(_)));
    }

    #[test]
    fn test_op_assign_amount() {
        let sat = Amount::from_sat_u32(50);

        let mut res = sat + sat;
        res += Amount::from_sat_u32(50);
        assert_eq!(res, NumOpResult::Valid(Amount::from_sat_u32(150)));

        let add_err = NumOpResult::Error(NumOpError::while_doing(MathOp::Add));
        res += add_err; // Add an error result
        assert_eq!(res, add_err);

        let mut res = sat + sat;
        res -= Amount::from_sat_u32(20);
        assert_eq!(res, NumOpResult::Valid(Amount::from_sat_u32(80)));

        let sub_err = NumOpResult::Error(NumOpError::while_doing(MathOp::Sub));
        res -= sub_err; // Subtract an error result
        assert_eq!(res, sub_err);
    }

    #[test]
    fn test_op_assign_signed_amount() {
        let ssat = SignedAmount::from_sat_i32(50);

        let mut res = ssat + ssat;
        res += SignedAmount::from_sat_i32(-30);
        assert_eq!(res, NumOpResult::Valid(SignedAmount::from_sat_i32(70)));

        let add_err = NumOpResult::Error(NumOpError::while_doing(MathOp::Add));
        res += add_err; // Add an error result
        assert_eq!(res, add_err);

        let mut res = ssat + ssat;
        res -= SignedAmount::from_sat_i32(25);
        assert_eq!(res, NumOpResult::Valid(SignedAmount::from_sat_i32(75)));

        let sub_err = NumOpResult::Error(NumOpError::while_doing(MathOp::Sub));
        res -= sub_err; // Subtract an error result
        assert_eq!(res, sub_err);
    }

    #[test]
    fn test_op_assign_amount_error() {
        let mut res: NumOpResult<Amount> = NumOpResult::Error(NumOpError::while_doing(MathOp::Add));

        // Adding a valid amount to an error should make an Add error
        res += Amount::from_sat_u32(10);
        assert_eq!(res, NumOpResult::Error(NumOpError::while_doing(MathOp::Add)));

        // Adding an error to an error change to an Add error
        res += NumOpResult::Error(NumOpError::while_doing(MathOp::Sub));
        assert_eq!(res, NumOpResult::Error(NumOpError::while_doing(MathOp::Add)));

        // Subtracting a valid amount from an error should make a Sub error
        res -= Amount::from_sat_u32(10);
        assert_eq!(res, NumOpResult::Error(NumOpError::while_doing(MathOp::Sub)));

        // Subtracting an error from an error change to a Sub error
        res -= NumOpResult::Error(NumOpError::while_doing(MathOp::Add));
        assert_eq!(res, NumOpResult::Error(NumOpError::while_doing(MathOp::Sub)));
    }
}
