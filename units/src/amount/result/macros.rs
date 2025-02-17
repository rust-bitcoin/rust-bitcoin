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
    };
}
pub(crate) use impl_add_combinations;
