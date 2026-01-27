// SPDX-License-Identifier: CC0-1.0

//! Internal macros.
//!
//! Macros meant to be used inside the `bitcoin-units` library.

/// Implements a mathematical operation for various reference combinations.
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
///
/// Your where clause must include extra parenthesis, like `where (T: Copy)`.
macro_rules! impl_op_for_references {
    ($(
        impl$(<$gen:ident>)? $($op_trait:ident)::+<$other_ty:ty> for $ty:ty
        $(where ($($bounds:tt)*))?
        {
            type Output = $($main_output:ty)*;
            fn $op:ident($($main_args:tt)*) -> Self::Output {
                $($main_impl:tt)*
            }
        }
    )+) => {$(
        impl$(<$gen>)?  $($op_trait)::+<$other_ty> for $ty
        $(where $($bounds)*)?
        {
            type Output = $($main_output)*;
            fn $op($($main_args)*) -> Self::Output {
                $($main_impl)*
            }
        }

        impl$(<$gen>)?  $($op_trait)::+<$other_ty> for &$ty
        $(where $($bounds)*)?
        {
            type Output = <$ty as $($op_trait)::+<$other_ty>>::Output;
            fn $op(self, rhs: $other_ty) -> Self::Output {
                (*self).$op(rhs)
            }
        }

        impl$(<$gen>)?  $($op_trait)::+<&$other_ty> for $ty
        $(where $($bounds)*)?
        {
            type Output = <$ty as $($op_trait)::+<$other_ty>>::Output;
            fn $op(self, rhs: &$other_ty) -> Self::Output {
                self.$op(*rhs)
            }
        }

        impl<'a, $($gen)?> $($op_trait)::+<&'a $other_ty> for &$ty
        $(where $($bounds)*)?
        {
            type Output = <$ty as $($op_trait)::+<$other_ty>>::Output;
            fn $op(self, rhs: &$other_ty) -> Self::Output {
                (*self).$op(*rhs)
            }
        }
    )+};
}
pub(crate) use impl_op_for_references;

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

/// Implement `ops::AddAssign` for `$ty` and `NumOpResult<$ty>` on `NumOpResult<$ty>`
///
/// This implements the same logic as the generic `NumOpResult` implementation in result.rs,
/// but works for types that can't implement `AddAssign` on themselves (e.g. `Amount`, `SignedAmount`)
macro_rules! impl_add_assign_for_results {
    ($ty:ident) => {
        impl ops::AddAssign<$ty> for NumOpResult<$ty> {
            fn add_assign(&mut self, rhs: $ty) {
                match self {
                    Self::Error(_) => *self = Self::Error(NumOpError::while_doing(MathOp::Add)),
                    Self::Valid(ref lhs) => *self = lhs + rhs,
                }
            }
        }

        impl ops::AddAssign<Self> for NumOpResult<$ty> {
            fn add_assign(&mut self, rhs: Self) {
                match (&self, rhs) {
                    (Self::Valid(_), Self::Valid(rhs)) => *self += rhs,
                    (_, _) => *self = Self::Error(NumOpError::while_doing(MathOp::Add)),
                }
            }
        }
    };
}
pub(crate) use impl_add_assign_for_results;

/// Implement `ops::SubAssign` for `$ty` and `NumOpResult<$ty>` on `NumOpResult<$ty>`
///
/// This implements the same logic as the generic `NumOpResult` implementation in result.rs,
/// but works for types that can't implement `SubAssign` on themselves (e.g. `Amount`, `SignedAmount`)
macro_rules! impl_sub_assign_for_results {
    ($ty:ident) => {
        impl ops::SubAssign<$ty> for NumOpResult<$ty> {
            fn sub_assign(&mut self, rhs: $ty) {
                match self {
                    Self::Error(_) => *self = Self::Error(NumOpError::while_doing(MathOp::Sub)),
                    Self::Valid(ref lhs) => *self = lhs - rhs,
                }
            }
        }

        impl ops::SubAssign<Self> for NumOpResult<$ty> {
            fn sub_assign(&mut self, rhs: Self) {
                match (&self, rhs) {
                    (Self::Valid(_), Self::Valid(rhs)) => *self -= rhs,
                    (_, _) => *self = Self::Error(NumOpError::while_doing(MathOp::Sub)),
                }
            }
        }
    };
}
pub(crate) use impl_sub_assign_for_results;

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

/// Implement `ops::MulAssign` for `$ty` multiplied by `$rhs` and `&$rhs`.
macro_rules! impl_mul_assign {
    ($ty:ty, $rhs:ident) => {
        impl core::ops::MulAssign<$rhs> for $ty {
            fn mul_assign(&mut self, rhs: $rhs) { *self = *self * rhs }
        }

        impl core::ops::MulAssign<&$rhs> for $ty {
            fn mul_assign(&mut self, rhs: &$rhs) { *self = *self * *rhs }
        }
    };
}
pub(crate) use impl_mul_assign;

/// Implement `ops::DivAssign` for `$ty` divided by `$rhs` and `&$rhs`.
macro_rules! impl_div_assign {
    ($ty:ty, $rhs:ident) => {
        impl core::ops::DivAssign<$rhs> for $ty {
            fn div_assign(&mut self, rhs: $rhs) { *self = *self / rhs }
        }

        impl core::ops::DivAssign<&$rhs> for $ty {
            fn div_assign(&mut self, rhs: &$rhs) { *self = *self / *rhs }
        }
    };
}
pub(crate) use impl_div_assign;

/// Implements Lower/UpperHex, Octal and Binary for a new-type `$ty`.
///
/// This macro can be used on raw new-types (e.g. `BlockHeight`), or those encapsulated
/// per the privacy rules by accessing the inner value with a method `$fn`.
macro_rules! impl_fmt_traits_for_u32_wrapper {
    ($ty:ident) => {
        impl core::fmt::LowerHex for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
                core::fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl core::fmt::UpperHex for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
                core::fmt::UpperHex::fmt(&self.0, f)
            }
        }

        impl core::fmt::Octal for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
                core::fmt::Octal::fmt(&self.0, f)
            }
        }

        impl core::fmt::Binary for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
                core::fmt::Binary::fmt(&self.0, f)
            }
        }
    };
    ($ty:ident, $fn:ident) => {
        impl core::fmt::LowerHex for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
                core::fmt::LowerHex::fmt(&self.$fn(), f)
            }
        }

        impl core::fmt::UpperHex for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
                core::fmt::UpperHex::fmt(&self.$fn(), f)
            }
        }

        impl core::fmt::Octal for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
                core::fmt::Octal::fmt(&self.$fn(), f)
            }
        }

        impl core::fmt::Binary for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
                core::fmt::Binary::fmt(&self.$fn(), f)
            }
        }
    };
}
pub(crate) use impl_fmt_traits_for_u32_wrapper;
