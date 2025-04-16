// SPDX-License-Identifier: CC0-1.0

//! Provides a monodic type returned by mathematical operations (`core::ops`).

use core::fmt;

use NumOpResult as R;

use crate::{Amount, FeeRate, SignedAmount, Weight};

/// Result of a mathematical operation on two numeric types.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[must_use]
pub enum NumOpResult<T> {
    /// Result of a successful mathematical operation.
    Valid(T),
    /// Result of an unsuccessful mathematical operation.
    Error(NumOpError),
}

impl<T: fmt::Debug> NumOpResult<T> {
    /// Returns the contained valid numeric type, consuming `self`.
    ///
    /// # Panics
    ///
    /// Panics with `msg` if the numeric result is an `Error`.
    #[inline]
    #[track_caller]
    pub fn expect(self, msg: &str) -> T {
        match self {
            R::Valid(x) => x,
            R::Error(_) => panic!("{}", msg),
        }
    }

    /// Returns the contained valid numeric type, consuming `self`.
    ///
    /// # Panics
    ///
    /// Panics if the numeric result is an `Error`.
    #[inline]
    #[track_caller]
    pub fn unwrap(self) -> T {
        match self {
            R::Valid(x) => x,
            R::Error(e) => panic!("tried to unwrap an invalid numeric result: {:?}", e),
        }
    }

    /// Returns the contained error, consuming `self`.
    ///
    /// # Panics
    ///
    /// Panics if the numeric result is valid.
    #[inline]
    #[track_caller]
    pub fn unwrap_err(self) -> NumOpError {
        match self {
            R::Error(e) => e,
            R::Valid(a) => panic!("tried to unwrap a valid numeric result: {:?}", a),
        }
    }

    /// Converts this `NumOpResult` to an `Option<T>`.
    #[inline]
    pub fn ok(self) -> Option<T> {
        match self {
            R::Valid(x) => Some(x),
            R::Error(_) => None,
        }
    }

    /// Converts this `NumOpResult` to a `Result<T, NumOpError>`.
    #[inline]
    #[allow(clippy::missing_errors_doc)]
    pub fn into_result(self) -> Result<T, NumOpError> {
        match self {
            R::Valid(x) => Ok(x),
            R::Error(e) => Err(e),
        }
    }

    /// Calls `op` if the numeric result is `Valid`, otherwise returns the `Error` value of `self`.
    #[inline]
    pub fn and_then<F>(self, op: F) -> NumOpResult<T>
    where
        F: FnOnce(T) -> NumOpResult<T>,
    {
        match self {
            R::Valid(x) => op(x),
            R::Error(e) => R::Error(e),
        }
    }

    /// Returns `true` if the numeric result is valid.
    #[inline]
    pub fn is_valid(&self) -> bool {
        match self {
            R::Valid(_) => true,
            R::Error(_) => false,
        }
    }

    /// Returns `true` if the numeric result is invalid.
    #[inline]
    pub fn is_error(&self) -> bool { !self.is_valid() }
}

pub(crate) trait OptionExt<T> {
    fn valid_or_error(self, op: MathOp) -> NumOpResult<T>;
}

macro_rules! impl_opt_ext {
    ($($ty:ident),* $(,)?) => {
        $(
            impl OptionExt<$ty> for Option<$ty> {
                #[inline]
                fn valid_or_error(self, op: MathOp) -> NumOpResult<$ty> {
                    match self {
                        Some(amount) => R::Valid(amount),
                        None => R::Error(NumOpError(op)),
                    }
                }
            }
        )*
    }
}
impl_opt_ext!(Amount, SignedAmount, u64, i64, FeeRate, Weight);

/// Error returned when a mathematical operation fails.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NumOpError(MathOp);

impl NumOpError {
    /// Creates a [`NumOpError`] caused by `op`.
    pub fn while_doing(op: MathOp) -> Self { NumOpError(op) }

    /// Returns the [`MathOp`] that caused this error.
    pub fn operation(self) -> MathOp { self.0 }
}

impl fmt::Display for NumOpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "math operation '{}' gave an invalid numeric result", self.operation())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NumOpError {}

/// The math operation that caused the error.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MathOp {
    /// Addition failed ([`core::ops::Add`] resulted in an invalid value).
    Add,
    /// Subtraction failed ([`core::ops::Sub`] resulted in an invalid value).
    Sub,
    /// Multiplication failed ([`core::ops::Mul`] resulted in an invalid value).
    Mul,
    /// Division failed ([`core::ops::Div`] attempted div-by-zero).
    Div,
    /// Calculating the remainder failed ([`core::ops::Rem`] attempted div-by-zero).
    Rem,
    /// Negation failed ([`core::ops::Neg`] resulted in an invalid value).
    Neg,
}

impl MathOp {
    /// Returns `true` if this operation error'ed due to overflow.
    pub fn is_overflow(self) -> bool {
        matches!(self, MathOp::Add | MathOp::Sub | MathOp::Mul | MathOp::Neg)
    }

    /// Returns `true` if this operation error'ed due to division by zero.
    pub fn is_div_by_zero(self) -> bool { !self.is_overflow() }
}

impl fmt::Display for MathOp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MathOp::Add => write!(f, "add"),
            MathOp::Sub => write!(f, "sub"),
            MathOp::Mul => write!(f, "mul"),
            MathOp::Div => write!(f, "div"),
            MathOp::Rem => write!(f, "rem"),
            MathOp::Neg => write!(f, "neg"),
        }
    }
}
