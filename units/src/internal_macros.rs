// SPDX-License-Identifier: CC0-1.0

//! Internal macros.
//!
//! Macros meant to be used inside the `bitcoin-units` library.

/// Implements `ops::Add` for various references.
///
/// Requires `$ty` it implement `Add` e.g. 'impl Add<T> for T'. Adds impls of:
///
/// - Add<T> for &T
/// - Add<&T> for T
/// - Add<&T> for &T
macro_rules! impl_add_for_references {
    ($ty:ident) => {
        impl core::ops::Add<$ty> for &$ty {
            type Output = $ty;

            fn add(self, rhs: $ty) -> Self::Output { *self + rhs }
        }

        impl core::ops::Add<&$ty> for $ty {
            type Output = $ty;

            fn add(self, rhs: &$ty) -> Self::Output { self + *rhs }
        }

        impl<'a> core::ops::Add<&'a $ty> for &$ty {
            type Output = $ty;

            fn add(self, rhs: &'a $ty) -> Self::Output { *self + *rhs }
        }
    };
}
pub(crate) use impl_add_for_references;

/// Implement `ops::AddAssign` for `$ty` and `&$ty`.
macro_rules! impl_add_assign {
    ($ty:ident) => {
        impl core::ops::AddAssign<$ty> for $ty {
            fn add_assign(&mut self, rhs: $ty) { *self = *self + rhs }
        }

        impl core::ops::AddAssign<&$ty> for $ty {
            fn add_assign(&mut self, rhs: &$ty) { *self = *self + *rhs }
        }
    };
}
pub(crate) use impl_add_assign;

/// Implement `ops::Sub` for various references.
///
/// Requires `$ty` it implement `Sub` e.g. 'impl Sub<T> for T'. Adds impls of:
///
/// - Sub<T> for &T
/// - Sub<&T> for T
/// - Sub<&T> for &T
macro_rules! impl_sub_for_references {
    ($ty:ident) => {
        impl core::ops::Sub<$ty> for &$ty {
            type Output = $ty;

            fn sub(self, rhs: $ty) -> Self::Output { *self - rhs }
        }

        impl core::ops::Sub<&$ty> for $ty {
            type Output = $ty;

            fn sub(self, rhs: &$ty) -> Self::Output { self - *rhs }
        }

        impl<'a> core::ops::Sub<&'a $ty> for &$ty {
            type Output = $ty;

            fn sub(self, rhs: &'a $ty) -> Self::Output { *self - *rhs }
        }
    };
}
pub(crate) use impl_sub_for_references;

/// Implement `ops::Sub` for various amount references.
///
/// Requires `$ty` it implement `Sub` e.g. 'impl Sub<T> for T'. Adds impls of:
///
/// - Sub<T> for &T
/// - Sub<&T> for T
/// - Sub<&T> for &T
macro_rules! impl_sub_for_amount_references {
    ($ty:ident) => {
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
    };
}
pub(crate) use impl_sub_for_amount_references;

/// Implement `ops::SubAssign` for `$ty` and `&$ty`.
macro_rules! impl_sub_assign {
    ($ty:ident) => {
        impl core::ops::SubAssign<$ty> for $ty {
            fn sub_assign(&mut self, rhs: $ty) { *self = *self - rhs }
        }

        impl core::ops::SubAssign<&$ty> for $ty {
            fn sub_assign(&mut self, rhs: &$ty) { *self = *self - *rhs }
        }
    };
}
pub(crate) use impl_sub_assign;
