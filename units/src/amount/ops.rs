// SPDX-License-Identifier: CC0-1.0

//! Implements mathematical operators from [`core::ops`] and basic conversions.

use core::num::{NonZeroI64, NonZeroU64};
use core::ops;

use NumOpResult as R;

use super::{Amount, SignedAmount};
use crate::internal_macros::{
    impl_add_assign_for_results, impl_div_assign, impl_mul_assign, impl_rem_assign,
    impl_sub_assign_for_results,
};
use crate::result::{MathErrorKind, MathOp, NumOpResult, OptionExt};

impl From<Amount> for NumOpResult<Amount> {
    #[inline]
    fn from(a: Amount) -> Self { Self::Valid(a) }
}
impl From<&Amount> for NumOpResult<Amount> {
    #[inline]
    fn from(a: &Amount) -> Self { Self::Valid(*a) }
}

impl From<SignedAmount> for NumOpResult<SignedAmount> {
    #[inline]
    fn from(a: SignedAmount) -> Self { Self::Valid(a) }
}
impl From<&SignedAmount> for NumOpResult<SignedAmount> {
    #[inline]
    fn from(a: &SignedAmount) -> Self { Self::Valid(*a) }
}

crate::internal_macros::impl_op_for_references! {
    impl ops::Add<Amount> for Amount {
        type Output = NumOpResult<Amount>;

        fn add(self, rhs: Amount) -> Self::Output { self.checked_add(rhs).valid_or_error(MathErrorKind::Overflow { op: MathOp::Add, is_negative: false }) }
    }
    impl ops::Add<NumOpResult<Amount>> for Amount {
        type Output = NumOpResult<Amount>;

        fn add(self, rhs: NumOpResult<Amount>) -> Self::Output { rhs.and_then(|a| a + self) }
    }

    impl ops::Sub<Amount> for Amount {
        type Output = NumOpResult<Amount>;

        fn sub(self, rhs: Amount) -> Self::Output { self.checked_sub(rhs).valid_or_error(MathErrorKind::Overflow { op: MathOp::Sub, is_negative: true }) }
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

        fn mul(self, rhs: u64) -> Self::Output { self.checked_mul(rhs).valid_or_error(MathErrorKind::Overflow { op: MathOp::Mul, is_negative: false }) }
    }
    impl ops::Mul<u64> for NumOpResult<Amount> {
        type Output = NumOpResult<Amount>;

        fn mul(self, rhs: u64) -> Self::Output { self.and_then(|lhs| lhs * rhs) }
    }
    impl ops::Mul<Amount> for u64 {
        type Output = NumOpResult<Amount>;

        fn mul(self, rhs: Amount) -> Self::Output { rhs.checked_mul(self).valid_or_error(MathErrorKind::Overflow { op: MathOp::Mul, is_negative: false }) }
    }
    impl ops::Mul<NumOpResult<Amount>> for u64 {
        type Output = NumOpResult<Amount>;

        fn mul(self, rhs: NumOpResult<Amount>) -> Self::Output { rhs.and_then(|rhs| self * rhs) }
    }

    impl ops::Div<u64> for Amount {
        type Output = NumOpResult<Amount>;

        fn div(self, rhs: u64) -> Self::Output { self.checked_div(rhs).valid_or_error(MathErrorKind::DivByZero) }
    }
    impl ops::Div<u64> for NumOpResult<Amount> {
        type Output = NumOpResult<Amount>;

        fn div(self, rhs: u64) -> Self::Output { self.and_then(|lhs| lhs / rhs) }
    }
    impl ops::Div<Amount> for Amount {
        type Output = NumOpResult<u64>;

        fn div(self, rhs: Amount) -> Self::Output {
            self.to_sat().checked_div(rhs.to_sat()).valid_or_error(MathErrorKind::DivByZero)
        }
    }
    impl ops::Div<NonZeroU64> for Amount {
        type Output = Amount;

        fn div(self, rhs: NonZeroU64) -> Self::Output { Self::from_sat(self.to_sat() / rhs).expect("construction after division cannot fail") }
    }
    impl ops::Div<NonZeroU64> for NumOpResult<Amount> {
        type Output = NumOpResult<Amount>;

        fn div(self, rhs: NonZeroU64) -> Self::Output { self.map(|lhs| lhs / rhs) }
    }
    impl ops::Rem<u64> for Amount {
        type Output = NumOpResult<Amount>;

        fn rem(self, modulus: u64) -> Self::Output { self.checked_rem(modulus).valid_or_error(MathErrorKind::RemByZero) }
    }
    impl ops::Rem<NonZeroU64> for Amount {
        type Output = Amount;

        fn rem(self, modulus: NonZeroU64) -> Self::Output { Self::from_sat(self.to_sat() % modulus).expect("construction from remainder cannot fail") }
    }
    impl ops::Rem<u64> for NumOpResult<Amount> {
        type Output = NumOpResult<Amount>;

        fn rem(self, modulus: u64) -> Self::Output { self.and_then(|lhs| lhs % modulus) }
    }
    impl ops::Rem<NonZeroU64> for NumOpResult<Amount> {
        type Output = NumOpResult<Amount>;

        fn rem(self, modulus: NonZeroU64) -> Self::Output { self.map(|lhs| lhs % modulus) }
    }

    impl ops::Add<SignedAmount> for SignedAmount {
        type Output = NumOpResult<SignedAmount>;

        fn add(self, rhs: SignedAmount) -> Self::Output {
            let kind = MathErrorKind::Overflow { op: MathOp::Add, is_negative: rhs.is_negative() };
            self.checked_add(rhs).valid_or_error(kind)
        }
    }
    impl ops::Add<NumOpResult<SignedAmount>> for SignedAmount {
        type Output = NumOpResult<SignedAmount>;

        fn add(self, rhs: NumOpResult<SignedAmount>) -> Self::Output { rhs.and_then(|a| a + self) }
    }

    impl ops::Sub<SignedAmount> for SignedAmount {
        type Output = NumOpResult<SignedAmount>;

        fn sub(self, rhs: SignedAmount) -> Self::Output {
            let kind = MathErrorKind::Overflow { op: MathOp::Sub, is_negative: !rhs.is_negative() };
            self.checked_sub(rhs).valid_or_error(kind)
        }
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

        fn mul(self, rhs: i64) -> Self::Output {
            let is_negative = self.is_negative() != rhs.is_negative();
            self.checked_mul(rhs).valid_or_error(MathErrorKind::Overflow { op: MathOp::Mul, is_negative })
        }
    }
    impl ops::Mul<i64> for NumOpResult<SignedAmount> {
        type Output = NumOpResult<SignedAmount>;

        fn mul(self, rhs: i64) -> Self::Output { self.and_then(|lhs| lhs * rhs) }
    }
    impl ops::Mul<SignedAmount> for i64 {
        type Output = NumOpResult<SignedAmount>;

        fn mul(self, rhs: SignedAmount) -> Self::Output {
            let is_negative = self.is_negative() != rhs.is_negative();
            rhs.checked_mul(self).valid_or_error(MathErrorKind::Overflow { op: MathOp::Mul, is_negative })
        }
    }
    impl ops::Mul<NumOpResult<SignedAmount>> for i64 {
        type Output = NumOpResult<SignedAmount>;

        fn mul(self, rhs: NumOpResult<SignedAmount>) -> Self::Output { rhs.and_then(|rhs| self * rhs) }
    }

    impl ops::Div<i64> for SignedAmount {
        type Output = NumOpResult<SignedAmount>;

        fn div(self, rhs: i64) -> Self::Output { self.checked_div(rhs).valid_or_error(MathErrorKind::DivByZero) }
    }
    impl ops::Div<i64> for NumOpResult<SignedAmount> {
        type Output = NumOpResult<SignedAmount>;

        fn div(self, rhs: i64) -> Self::Output { self.and_then(|lhs| lhs / rhs) }
    }
    impl ops::Div<SignedAmount> for SignedAmount {
        type Output = NumOpResult<i64>;

        fn div(self, rhs: SignedAmount) -> Self::Output {
            self.to_sat().checked_div(rhs.to_sat()).valid_or_error(MathErrorKind::DivByZero)
        }
    }
    impl ops::Div<NonZeroI64> for SignedAmount {
        type Output = SignedAmount;

        fn div(self, rhs: NonZeroI64) -> Self::Output { Self::from_sat(self.to_sat() / rhs.get()).expect("construction after division cannot fail") }
    }
    impl ops::Div<NonZeroI64> for NumOpResult<SignedAmount> {
        type Output = NumOpResult<SignedAmount>;

        fn div(self, rhs: NonZeroI64) -> Self::Output { self.map(|lhs| lhs / rhs) }
    }
    impl ops::Rem<i64> for SignedAmount {
        type Output = NumOpResult<SignedAmount>;

        fn rem(self, modulus: i64) -> Self::Output { self.checked_rem(modulus).valid_or_error(MathErrorKind::RemByZero) }
    }
    impl ops::Rem<NonZeroI64> for SignedAmount {
        type Output = SignedAmount;

        fn rem(self, modulus: NonZeroI64) -> Self::Output { SignedAmount::from_sat(self.to_sat() % modulus.get()).expect("construction from remainder cannot fail") }
    }
    impl ops::Rem<i64> for NumOpResult<SignedAmount> {
        type Output = NumOpResult<SignedAmount>;

        fn rem(self, modulus: i64) -> Self::Output { self.and_then(|lhs| lhs % modulus) }
    }
    impl ops::Rem<NonZeroI64> for NumOpResult<SignedAmount> {
        type Output = NumOpResult<SignedAmount>;

        fn rem(self, modulus: NonZeroI64) -> Self::Output { self.map(|lhs| lhs % modulus) }
    }
}

impl_mul_assign!(NumOpResult<Amount>, u64);
impl_mul_assign!(NumOpResult<SignedAmount>, i64);
impl_div_assign!(NumOpResult<Amount>, u64);
impl_div_assign!(NumOpResult<SignedAmount>, i64);
impl_div_assign!(Amount, NonZeroU64);
impl_div_assign!(SignedAmount, NonZeroI64);
impl_div_assign!(NumOpResult<Amount>, NonZeroU64);
impl_div_assign!(NumOpResult<SignedAmount>, NonZeroI64);
impl_rem_assign!(NumOpResult<Amount>, u64);
impl_rem_assign!(NumOpResult<SignedAmount>, i64);
impl_rem_assign!(Amount, NonZeroU64);
impl_rem_assign!(SignedAmount, NonZeroI64);
impl_rem_assign!(NumOpResult<Amount>, NonZeroU64);
impl_rem_assign!(NumOpResult<SignedAmount>, NonZeroI64);

impl_add_assign_for_results!(Amount);
impl_add_assign_for_results!(SignedAmount);
impl_sub_assign_for_results!(Amount);
impl_sub_assign_for_results!(SignedAmount);

impl ops::Neg for Amount {
    type Output = SignedAmount;

    #[inline]
    fn neg(self) -> Self::Output { self.to_signed().neg() }
}

impl ops::Neg for SignedAmount {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        Self::from_sat(self.to_sat().neg()).expect("all +ve and -ve values are valid")
    }
}

impl ops::Neg for NumOpResult<Amount> {
    type Output = NumOpResult<SignedAmount>;

    #[inline]
    fn neg(self) -> Self::Output { self.map(ops::Neg::neg) }
}

impl ops::Neg for NumOpResult<SignedAmount> {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output { self.map(ops::Neg::neg) }
}

/// Note: it's unspecified how many items from the iterator this implementation consumes if overflow occurs.
impl core::iter::Sum<Amount> for NumOpResult<Amount> {
    fn sum<I>(mut iter: I) -> Self
    where
        I: Iterator<Item = Amount>,
    {
        let result = iter.try_fold(Amount::ZERO, |acc, amount| (acc + amount).into_result());
        Self::from_result(result)
    }
}

/// Note: it's unspecified how many items from the iterator this implementation consumes if overflow occurs.
impl<'a> core::iter::Sum<&'a Amount> for NumOpResult<Amount> {
    fn sum<I>(mut iter: I) -> Self
    where
        I: Iterator<Item = &'a Amount>,
    {
        let result = iter.try_fold(Amount::ZERO, |acc, amount| (acc + amount).into_result());
        Self::from_result(result)
    }
}

/// Note: it's unspecified how many items from the iterator this implementation consumes if overflow occurs.
impl core::iter::Sum<Self> for NumOpResult<Amount> {
    fn sum<I>(mut iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        let result =
            iter.try_fold(Amount::ZERO, |acc, amount| (acc + amount.into_result()?).into_result());
        Self::from_result(result)
    }
}
/// Note: it's unspecified how many items from the iterator this implementation consumes if overflow occurs.
impl<'a> core::iter::Sum<&'a Self> for NumOpResult<Amount> {
    fn sum<I>(mut iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        let result =
            iter.try_fold(Amount::ZERO, |acc, amount| (acc + amount.into_result()?).into_result());
        Self::from_result(result)
    }
}

/// Note: it's unspecified how many items from the iterator this implementation consumes if overflow occurs.
impl core::iter::Sum<SignedAmount> for NumOpResult<SignedAmount> {
    fn sum<I>(mut iter: I) -> Self
    where
        I: Iterator<Item = SignedAmount>,
    {
        let result = iter.try_fold(SignedAmount::ZERO, |acc, amount| (acc + amount).into_result());
        Self::from_result(result)
    }
}

/// Note: it's unspecified how many items from the iterator this implementation consumes if overflow occurs.
impl<'a> core::iter::Sum<&'a SignedAmount> for NumOpResult<SignedAmount> {
    fn sum<I>(mut iter: I) -> Self
    where
        I: Iterator<Item = &'a SignedAmount>,
    {
        let result = iter.try_fold(SignedAmount::ZERO, |acc, amount| (acc + amount).into_result());
        Self::from_result(result)
    }
}

/// Note: it's unspecified how many items from the iterator this implementation consumes if overflow occurs.
impl core::iter::Sum<Self> for NumOpResult<SignedAmount> {
    fn sum<I>(mut iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        let result = iter.try_fold(SignedAmount::ZERO, |acc, amount| {
            (acc + amount.into_result()?).into_result()
        });
        Self::from_result(result)
    }
}

/// Note: it's unspecified how many items from the iterator this implementation consumes if overflow occurs.
impl<'a> core::iter::Sum<&'a Self> for NumOpResult<SignedAmount> {
    fn sum<I>(mut iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        let result = iter.try_fold(SignedAmount::ZERO, |acc, amount| {
            (acc + amount.into_result()?).into_result()
        });
        Self::from_result(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::tests::{res, sat, sres, ssat};
    use crate::result::NumOpError;

    #[test]
    fn sum_amounts() {
        let amounts = [sat(100), sat(200), sat(300)];

        let sum: NumOpResult<Amount> = amounts.into_iter().sum();
        assert_eq!(sum, res(600));
    }

    #[test]
    fn sum_amounts_with_references() {
        let amounts = [sat(100), sat(200), sat(300)];

        let sum: NumOpResult<Amount> = amounts.iter().sum();
        assert_eq!(sum, res(600));
    }

    #[test]
    fn sum_preserves_division_by_zero_error() {
        let err = [Amount::ONE_SAT / 0_u64];
        let sum: NumOpResult<Amount> = err.into_iter().sum();
        assert!(sum.unwrap_err().operation().is_division());
        let sum: NumOpResult<Amount> = err.iter().sum();
        assert!(sum.unwrap_err().operation().is_division());

        let err = [SignedAmount::ONE_SAT / 0_i64];
        let sum: NumOpResult<SignedAmount> = err.into_iter().sum();
        assert!(sum.unwrap_err().operation().is_division());
        let sum: NumOpResult<SignedAmount> = err.iter().sum();
        assert!(sum.unwrap_err().operation().is_division());
    }

    #[test]
    fn sum_amount_results() {
        let amounts = [res(100), res(200), res(300)];

        let sum: NumOpResult<Amount> = amounts.into_iter().sum();
        assert_eq!(sum, res(600));
    }

    #[test]
    fn sum_amount_results_with_references() {
        let amounts = [res(100), res(200), res(300)];

        let sum: NumOpResult<Amount> = amounts.iter().sum();
        assert_eq!(sum, res(600));
    }

    #[test]
    fn sum_amount_with_error_propagation() {
        let amounts = [
            res(100),
            NumOpResult::Error(NumOpError::while_doing(MathErrorKind::Overflow {
                op: MathOp::Add,
                is_negative: false,
            })),
            res(200),
        ];

        let sum: NumOpResult<Amount> = amounts.into_iter().sum();
        assert!(matches!(sum, NumOpResult::Error(_)));
    }

    #[test]
    fn sum_signed_amounts() {
        let amounts = [ssat(100), ssat(-50), ssat(200)];

        let sum: NumOpResult<SignedAmount> = amounts.into_iter().sum();
        assert_eq!(sum, sres(250));
    }

    #[test]
    fn sum_signed_amounts_with_references() {
        let amounts = [ssat(100), ssat(-50), ssat(200)];

        let sum: NumOpResult<SignedAmount> = amounts.iter().sum();
        assert_eq!(sum, sres(250));
    }

    #[test]
    fn sum_signed_amount_results() {
        let amounts = [sres(100), sres(-50), sres(200)];

        let sum: NumOpResult<SignedAmount> = amounts.into_iter().sum();
        assert_eq!(sum, sres(250));
    }

    #[test]
    fn sum_signed_amount_results_with_references() {
        let amounts = [sres(100), sres(-50), sres(200)];

        let sum: NumOpResult<SignedAmount> = amounts.iter().sum();
        assert_eq!(sum, sres(250));
    }

    #[test]
    fn sum_signed_amount_with_error_propagation() {
        let amounts = [
            sres(100),
            NumOpResult::Error(NumOpError::while_doing(MathErrorKind::Overflow {
                op: MathOp::Add,
                is_negative: false,
            })),
            sres(200),
        ];

        let sum: NumOpResult<SignedAmount> = amounts.into_iter().sum();
        assert!(matches!(sum, NumOpResult::Error(_)));
    }

    #[test]
    fn op_assign_amount() {
        let amount = sat(50);

        let mut result = amount + amount;
        result += sat(50);
        assert_eq!(result, res(150));

        let add_err = NumOpResult::Error(NumOpError::while_doing(MathErrorKind::Overflow {
            op: MathOp::Add,
            is_negative: false,
        }));
        result += add_err; // Add an error result
        assert_eq!(result, add_err);

        let mut result = amount + amount;
        result -= sat(20);
        assert_eq!(result, res(80));

        let sub_err = NumOpResult::Error(NumOpError::while_doing(MathErrorKind::Overflow {
            op: MathOp::Sub,
            is_negative: true,
        }));
        result -= sub_err; // Subtract an error result
        assert_eq!(result, sub_err);
    }

    #[test]
    fn op_assign_signed_amount() {
        let amount = ssat(50);

        let mut result = amount + amount;
        result += ssat(-30);
        assert_eq!(result, sres(70));

        let add_err = NumOpResult::Error(NumOpError::while_doing(MathErrorKind::Overflow {
            op: MathOp::Add,
            is_negative: false,
        }));
        result += add_err; // Add an error result
        assert_eq!(result, add_err);

        let mut result = amount + amount;
        result -= ssat(25);
        assert_eq!(result, sres(75));

        let sub_err = NumOpResult::Error(NumOpError::while_doing(MathErrorKind::Overflow {
            op: MathOp::Sub,
            is_negative: true,
        }));
        result -= sub_err; // Subtract an error result
        assert_eq!(result, sub_err);
    }

    #[test]
    fn rem_assign_amount() {
        let amount = sat(50);
        let mut result = amount + amount;
        result %= 30_u64;
        assert_eq!(result, res(10));

        result %= &4_u64;
        assert_eq!(result, res(2));

        result %= 0_u64;
        assert_eq!(result, NumOpResult::Error(NumOpError::while_doing(MathErrorKind::RemByZero)));

        result %= 5_u64;
        assert_eq!(result, NumOpResult::Error(NumOpError::while_doing(MathErrorKind::RemByZero)));
    }

    #[test]
    fn rem_assign_nz_amount() {
        fn nz(x: u64) -> NonZeroU64 { NonZeroU64::new(x).unwrap() }

        let mut amount = sat(100);
        amount %= nz(30_u64);
        assert_eq!(amount, sat(10));

        amount %= &nz(4_u64);
        assert_eq!(amount, sat(2));

        amount %= nz(5_u64);
        assert_eq!(amount, sat(2));
    }

    #[test]
    fn rem_assign_signed_amount() {
        let amount = ssat(-50);

        let mut result = amount + amount;
        result %= 30_i64;
        assert_eq!(result, sres(-10));

        result %= &4_i64;
        assert_eq!(result, sres(-2));

        result %= 0_i64;
        assert_eq!(result, NumOpResult::Error(NumOpError::while_doing(MathErrorKind::RemByZero)));

        result %= 5_i64;
        assert_eq!(result, NumOpResult::Error(NumOpError::while_doing(MathErrorKind::RemByZero)));
    }

    #[test]
    fn rem_assign_nz_signed_amount() {
        fn nz(x: i64) -> NonZeroI64 { NonZeroI64::new(x).unwrap() }

        let mut amount = ssat(-100);
        amount %= nz(30_i64);
        assert_eq!(amount, ssat(-10));

        amount %= &nz(4_i64);
        assert_eq!(amount, ssat(-2));

        amount %= nz(5_i64);
        assert_eq!(amount, ssat(-2));
    }

    #[test]
    fn div_assign_amount_nonzero() {
        let mut amount = sat(100);
        amount /= NonZeroU64::new(12).unwrap();
        assert_eq!(amount, sat(8));

        // Division truncates towards zero.
        amount /= NonZeroU64::new(10).unwrap();
        assert_eq!(amount, Amount::ZERO);

        let mut result = amount + sat(100);
        result /= NonZeroU64::new(4).unwrap();
        assert_eq!(result, res(25));

        // An error result stays an error, keeping the original operation.
        let mut result: NumOpResult<Amount> =
            NumOpResult::Error(NumOpError::while_doing(MathErrorKind::Overflow {
                op: MathOp::Add,
                is_negative: false,
            }));
        result /= NonZeroU64::new(2).unwrap();
        assert_eq!(
            result,
            NumOpResult::Error(NumOpError::while_doing(MathErrorKind::Overflow {
                op: MathOp::Add,
                is_negative: false
            }))
        );
    }

    #[test]
    fn div_assign_signed_amount_nonzero() {
        let mut amount = ssat(-100);
        amount /= NonZeroI64::new(4).unwrap();
        assert_eq!(amount, ssat(-25));

        amount /= &NonZeroI64::new(-5).unwrap();
        assert_eq!(amount, ssat(5));

        // Division truncates towards zero.
        amount /= NonZeroI64::new(-10).unwrap();
        assert_eq!(amount, SignedAmount::ZERO);

        let mut result = amount - ssat(100);
        result /= NonZeroI64::new(4).unwrap();
        assert_eq!(result, sres(-25));

        let mut result: NumOpResult<SignedAmount> =
            NumOpResult::Error(NumOpError::while_doing(MathErrorKind::Overflow {
                op: MathOp::Sub,
                is_negative: true,
            }));
        result /= NonZeroI64::new(2).unwrap();
        assert_eq!(
            result,
            NumOpResult::Error(NumOpError::while_doing(MathErrorKind::Overflow {
                op: MathOp::Sub,
                is_negative: true
            }))
        );
    }

    #[test]
    fn op_assign_amount_error() {
        let mut result: NumOpResult<Amount> =
            NumOpResult::Error(NumOpError::while_doing(MathErrorKind::Overflow {
                op: MathOp::Mul,
                is_negative: false,
            }));
        let orig_res = result;

        // All assign ops to an error should preserve the error
        result += sat(10);
        assert_eq!(result, orig_res);

        result += NumOpResult::Error(NumOpError::while_doing(MathErrorKind::Overflow {
            op: MathOp::Sub,
            is_negative: true,
        }));
        assert_eq!(result, orig_res);

        result -= sat(10);
        assert_eq!(result, orig_res);

        result -= NumOpResult::Error(NumOpError::while_doing(MathErrorKind::Overflow {
            op: MathOp::Add,
            is_negative: false,
        }));
        assert_eq!(result, orig_res);
    }
}
