// SPDX-License-Identifier: CC0-1.0

//! Provides a monodic type returned by mathematical operations (`core::ops`).

use core::num::{NonZeroI64, NonZeroU64};
use core::ops;

use NumOpResult as R;

use super::{Amount, SignedAmount};
use crate::internal_macros::{impl_div_assign, impl_mul_assign};
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

    impl<T> ops::Add<NumOpResult<T>> for NumOpResult<T>
    where
        (T: Copy + ops::Add<Output = NumOpResult<T>>)
    {
        type Output = NumOpResult<T>;

        fn add(self, rhs: Self) -> Self::Output {
            match (self, rhs) {
                (R::Valid(lhs), R::Valid(rhs)) => lhs + rhs,
                (_, _) => R::Error(NumOpError::while_doing(MathOp::Add)),
            }
        }
    }

    impl<T> ops::Add<T> for NumOpResult<T>
    where
        (T: Copy + ops::Add<NumOpResult<T>, Output = NumOpResult<T>>)
    {
        type Output = NumOpResult<T>;

        fn add(self, rhs: T) -> Self::Output { rhs + self }
    }

    impl<T> ops::Sub<NumOpResult<T>> for NumOpResult<T>
    where
        (T: Copy + ops::Sub<Output = NumOpResult<T>>)
    {
        type Output = NumOpResult<T>;

        fn sub(self, rhs: Self) -> Self::Output {
            match (self, rhs) {
                (R::Valid(lhs), R::Valid(rhs)) => lhs - rhs,
                (_, _) => R::Error(NumOpError::while_doing(MathOp::Sub)),
            }
        }
    }

    impl<T> ops::Sub<T> for NumOpResult<T>
    where
        (T: Copy + ops::Sub<Output = NumOpResult<T>>)
    {
        type Output = NumOpResult<T>;

        fn sub(self, rhs: T) -> Self::Output {
            match self {
                R::Valid(amount) => amount - rhs,
                R::Error(_) => self,
            }
        }
    }
}

impl_mul_assign!(NumOpResult<Amount>, u64);
impl_mul_assign!(NumOpResult<SignedAmount>, i64);
impl_div_assign!(NumOpResult<Amount>, u64);
impl_div_assign!(NumOpResult<SignedAmount>, i64);

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
}
