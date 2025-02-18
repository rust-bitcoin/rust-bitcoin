// SPDX-License-Identifier: CC0-1.0

//! Internal macros.
//!
//! Macros meant to be used inside the `bitcoin-units` library.

/// Implements an opcode for various reference combinations.
///
/// Given `$ty`, assumes the `$op_trait<$other_ty>` trait is implemented on it,
/// and implements the same trait with the full matrix of `&$ty` and `&$other_ty`:
///
/// - `Add<$other_ty> for &$ty`
/// - `Add<&$other_ty> for $ty`
/// - `Add<&$other_ty> for &$ty`
///
/// # Limitations
///
/// You must specify `$other_ty` and you may not use `Self`. So e.g. you need
/// to write `impl ops::Add<Amount> for Amount { ... }` when calling this macro.
macro_rules! impl_op_for_references {
    ($(
        impl $($op_trait:ident)::+<$other_ty:ty> for $ty:ty {
            type Output = $($main_output:ty)*;
            fn $op:ident($($main_args:tt)*) -> Self::Output {
                $($main_impl:tt)*
            }
        }
    )+) => {$(
        impl $($op_trait)::+<$other_ty> for $ty {
            type Output = $($main_output)*;
            fn $op($($main_args)*) -> Self::Output {
                $($main_impl)*
            }
        }

        impl $($op_trait)::+<$other_ty> for &$ty {
            type Output = <$ty as $($op_trait)::+<$other_ty>>::Output;
            fn $op(self, rhs: $other_ty) -> Self::Output {
                (*self).$op(rhs)
            }
        }

        impl $($op_trait)::+<&$other_ty> for $ty {
            type Output = <$ty as $($op_trait)::+<$other_ty>>::Output;
            fn $op(self, rhs: &$other_ty) -> Self::Output {
                self.$op(*rhs)
            }
        }

        impl<'a> $($op_trait)::+<&'a $other_ty> for &$ty {
            type Output = <$ty as $($op_trait)::+<$other_ty>>::Output;
            fn $op(self, rhs: &$other_ty) -> Self::Output {
                (*self).$op(*rhs)
            }
        }
    )+};
}
pub(crate) use impl_op_for_references;

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

/// Implements `ops::Add` for various amount references.
///
/// Requires `$ty` it implement `Add` e.g. 'impl Add<T> for T'. Adds impls of:
///
/// - Add<T> for &T
/// - Add<&T> for T
/// - Add<&T> for &T
macro_rules! impl_add_for_amount_references {
    ($ty:ident) => {
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
    };
}
pub(crate) use impl_add_for_amount_references;

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
