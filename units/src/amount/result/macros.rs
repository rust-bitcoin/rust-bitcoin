// SPDX-License-Identifier: CC0-1.0

//! Internal amount related macros.
//!
//! Macros to implement `core::ops` traits using `Output = NumOpResult<T>`.

/// Implements `ops::Add` for various combinations.
///
/// Requires implementation of `ops::Add for $ty`.
macro_rules! impl_add_combinations {
    ($ty:ident) => {
        // E.g., let _: NumOpResult<Amount> = Amount + Amount;
        impl core::ops::Add<$ty> for &$ty {
            type Output = NumOpResult<$ty>;

            fn add(self, rhs: $ty) -> Self::Output { *self + rhs }
        }
        impl core::ops::Add<&$ty> for $ty {
            type Output = NumOpResult<$ty>;

            fn add(self, rhs: &$ty) -> Self::Output { self + *rhs }
        }
        impl<'a> core::ops::Add<&'a $ty> for &$ty {
            type Output = NumOpResult<$ty>;

            fn add(self, rhs: &'a $ty) -> Self::Output { *self + *rhs }
        }

        // E.g., let _: NumOpResult<Amount> = Amount + NumOpResultAmount;
        impl ops::Add<NumOpResult<$ty>> for $ty {
            type Output = NumOpResult<$ty>;

            fn add(self, rhs: NumOpResult<$ty>) -> Self::Output { rhs.and_then(|rhs| self + rhs) }
        }
        impl ops::Add<NumOpResult<$ty>> for &$ty {
            type Output = NumOpResult<$ty>;

            fn add(self, rhs: NumOpResult<$ty>) -> Self::Output { (*self) + rhs }
        }
        impl ops::Add<&NumOpResult<$ty>> for $ty {
            type Output = NumOpResult<$ty>;

            fn add(self, rhs: &NumOpResult<$ty>) -> Self::Output { self + (*rhs) }
        }
        impl ops::Add<&NumOpResult<$ty>> for &$ty {
            type Output = NumOpResult<$ty>;

            fn add(self, rhs: &NumOpResult<$ty>) -> Self::Output { (*self) + (*rhs) }
        }

        // E.g., let _: NumOpResult<Amount> = NumOpResult<Amount> + Amount;
        impl ops::Add<$ty> for NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn add(self, rhs: $ty) -> Self::Output { self.and_then(|lhs| lhs + rhs) }
        }
        impl ops::Add<$ty> for &NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn add(self, rhs: $ty) -> Self::Output { (*self) + rhs }
        }
        impl ops::Add<&$ty> for NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn add(self, rhs: &$ty) -> Self::Output { self + (*rhs) }
        }
        impl ops::Add<&$ty> for &NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn add(self, rhs: &$ty) -> Self::Output { (*self) + (*rhs) }
        }

        // E.g., let _: NumOpResult<Amount> = NumOpResult<Amount> + NumOpResult<Amount>;
        impl ops::Add for NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn add(self, rhs: Self) -> Self::Output {
                match (self, rhs) {
                    (R::Valid(lhs), R::Valid(rhs)) => lhs + rhs,
                    (e, R::Valid(_)) => e,
                    (R::Valid(_), e) => e,
                    (e, _) => e, // Just return the first one for now.
                }
            }
        }
        impl ops::Add<NumOpResult<$ty>> for &NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn add(self, rhs: NumOpResult<$ty>) -> Self::Output { (*self) + rhs }
        }
        impl ops::Add<&NumOpResult<$ty>> for NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn add(self, rhs: &NumOpResult<$ty>) -> Self::Output { self + (*rhs) }
        }
        impl ops::Add for &NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn add(self, rhs: &NumOpResult<$ty>) -> Self::Output { (*self) + (*rhs) }
        }
    };
}
pub(crate) use impl_add_combinations;

/// Implements `ops::Sub` for various combinations.
///
/// Requires implementation of `ops::Sub for $ty`.
macro_rules! impl_sub_combinations {
    ($ty:ident) => {
        // E.g., let _: NumOpResult<Amount> = Amount - Amount;
        impl core::ops::Sub<$ty> for &$ty {
            type Output = NumOpResult<$ty>;

            fn sub(self, rhs: $ty) -> Self::Output { *self - rhs }
        }
        impl core::ops::Sub<&$ty> for $ty {
            type Output = NumOpResult<$ty>;

            fn sub(self, rhs: &$ty) -> Self::Output { self - *rhs }
        }
        impl<'a> core::ops::Sub<&'a $ty> for &$ty {
            type Output = NumOpResult<$ty>;

            fn sub(self, rhs: &'a $ty) -> Self::Output { *self - *rhs }
        }

        // E.g., let _: NumOpResult<Amount> = Amount - NumOpResultAmount;
        impl ops::Sub<NumOpResult<$ty>> for $ty {
            type Output = NumOpResult<$ty>;

            fn sub(self, rhs: NumOpResult<$ty>) -> Self::Output { rhs.and_then(|rhs| self - rhs) }
        }
        impl ops::Sub<NumOpResult<$ty>> for &$ty {
            type Output = NumOpResult<$ty>;

            fn sub(self, rhs: NumOpResult<$ty>) -> Self::Output { (*self) - rhs }
        }
        impl ops::Sub<&NumOpResult<$ty>> for $ty {
            type Output = NumOpResult<$ty>;

            fn sub(self, rhs: &NumOpResult<$ty>) -> Self::Output { self - (*rhs) }
        }
        impl ops::Sub<&NumOpResult<$ty>> for &$ty {
            type Output = NumOpResult<$ty>;

            fn sub(self, rhs: &NumOpResult<$ty>) -> Self::Output { (*self) - (*rhs) }
        }

        // E.g., let _: NumOpResult<Amount> = NumOpResult<Amount> - Amount;
        impl ops::Sub<$ty> for NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn sub(self, rhs: $ty) -> Self::Output { self.and_then(|lhs| lhs - rhs) }
        }
        impl ops::Sub<$ty> for &NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn sub(self, rhs: $ty) -> Self::Output { (*self) - rhs }
        }
        impl ops::Sub<&$ty> for NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn sub(self, rhs: &$ty) -> Self::Output { self - (*rhs) }
        }
        impl ops::Sub<&$ty> for &NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn sub(self, rhs: &$ty) -> Self::Output { (*self) - (*rhs) }
        }

        // E.g., let _: NumOpResult<Amount> = NumOpResult<Amount> - NumOpResult<Amount>;
        impl ops::Sub for NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn sub(self, rhs: Self) -> Self::Output {
                match (self, rhs) {
                    (R::Valid(lhs), R::Valid(rhs)) => lhs - rhs,
                    (e, R::Valid(_)) => e,
                    (R::Valid(_), e) => e,
                    (e, _) => e, // Just return the first one for now.
                }
            }
        }
        impl ops::Sub<NumOpResult<$ty>> for &NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn sub(self, rhs: NumOpResult<$ty>) -> Self::Output { (*self) - rhs }
        }
        impl ops::Sub<&NumOpResult<$ty>> for NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn sub(self, rhs: &NumOpResult<$ty>) -> Self::Output { self - (*rhs) }
        }
        impl ops::Sub for &NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn sub(self, rhs: Self) -> Self::Output { (*self) - (*rhs) }
        }
    };
}
pub(crate) use impl_sub_combinations;

/// Implements `ops::Mul` for various combinations.
///
/// Requires implementation of `ops::Mul<$rhs> for $ty`.
macro_rules! impl_mul_combinations {
    ($ty:ident, $rhs:ident) => {
        // E.g., let _: NumOpResult<Amount> = Amount * 5;
        impl core::ops::Mul<$rhs> for &$ty {
            type Output = NumOpResult<$ty>;

            fn mul(self, rhs: $rhs) -> Self::Output { (*self) * rhs }
        }
        impl core::ops::Mul<&$rhs> for $ty {
            type Output = NumOpResult<$ty>;

            fn mul(self, rhs: &$rhs) -> Self::Output { self * (*rhs) }
        }
        impl<'a> core::ops::Mul<&'a $rhs> for &$ty {
            type Output = NumOpResult<$ty>;

            fn mul(self, rhs: &'a $rhs) -> Self::Output { (*self) * (*rhs) }
        }

        // E.g., let _: NumOpResult<Amount> = NumOpResult<Amount> * 5;
        impl ops::Mul<$rhs> for NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn mul(self, rhs: $rhs) -> Self::Output { self.and_then(|lhs| lhs * rhs) }
        }
        impl ops::Mul<$rhs> for &NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn mul(self, rhs: $rhs) -> Self::Output { (*self) * rhs }
        }
        impl ops::Mul<&$rhs> for NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn mul(self, rhs: &$rhs) -> Self::Output { self * (*rhs) }
        }
        impl ops::Mul<&$rhs> for &NumOpResult<$ty> {
            type Output = NumOpResult<$ty>;

            fn mul(self, rhs: &$rhs) -> Self::Output { (*self) * (*rhs) }
        }
    };
}
pub(crate) use impl_mul_combinations;

/// Implements `ops::Div` for various combinations.
///
/// Requires implementation of `ops::Div<$rhs> for $ty`.
macro_rules! impl_div_combinations {
    ($amount_ty:ident, $int_ty:ident) => {
        // E.g., Amount / 3;
        impl core::ops::Div<$int_ty> for &$amount_ty {
            type Output = NumOpResult<$amount_ty>;

            fn div(self, rhs: $int_ty) -> Self::Output { (*self) / rhs }
        }
        impl core::ops::Div<&$int_ty> for $amount_ty {
            type Output = NumOpResult<$amount_ty>;

            fn div(self, rhs: &$int_ty) -> Self::Output { self / (*rhs) }
        }
        impl<'a> core::ops::Div<&'a $int_ty> for &$amount_ty {
            type Output = NumOpResult<$amount_ty>;

            fn div(self, rhs: &'a $int_ty) -> Self::Output { (*self) / (*rhs) }
        }

        // E.g., NumOpResult<Amount> / 3;
        impl ops::Div<$int_ty> for NumOpResult<$amount_ty> {
            type Output = NumOpResult<$amount_ty>;

            fn div(self, rhs: $int_ty) -> Self::Output { self.and_then(|lhs| lhs / rhs) }
        }
        impl ops::Div<$int_ty> for &NumOpResult<$amount_ty> {
            type Output = NumOpResult<$amount_ty>;

            fn div(self, rhs: $int_ty) -> Self::Output { (*self) / rhs }
        }
        impl ops::Div<&$int_ty> for NumOpResult<$amount_ty> {
            type Output = NumOpResult<$amount_ty>;

            fn div(self, rhs: &$int_ty) -> Self::Output { self / (*rhs) }
        }
        impl ops::Div<&$int_ty> for &NumOpResult<$amount_ty> {
            type Output = NumOpResult<$amount_ty>;

            fn div(self, rhs: &$int_ty) -> Self::Output { (*self) / (*rhs) }
        }

        // E.g., Amount / Amount;
        impl ops::Div<$amount_ty> for $amount_ty {
            type Output = $int_ty;

            fn div(self, rhs: $amount_ty) -> Self::Output { self.to_sat() / rhs.to_sat() }
        }
        impl ops::Div<$amount_ty> for &$amount_ty {
            type Output = $int_ty;

            fn div(self, rhs: $amount_ty) -> Self::Output { (*self) / rhs }
        }
        impl ops::Div<&$amount_ty> for $amount_ty {
            type Output = $int_ty;

            fn div(self, rhs: &$amount_ty) -> Self::Output { self / (*rhs) }
        }
        impl ops::Div<&$amount_ty> for &$amount_ty {
            type Output = $int_ty;

            fn div(self, rhs: &$amount_ty) -> Self::Output { (*self) / (*rhs) }
        }
    };
}
pub(crate) use impl_div_combinations;
