// SPDX-License-Identifier: CC0-1.0

//! Provides a monodic type returned by mathematical operations (`core::ops`).

use core::fmt;

use NumOpResult as R;

use crate::{Amount, SignedAmount};

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
    fn valid_or_error(self) -> NumOpResult<T>;
}

macro_rules! impl_opt_ext {
    ($($ty:ident),* $(,)?) => {
        $(
            impl OptionExt<$ty> for Option<$ty> {
                #[inline]
                fn valid_or_error(self) -> NumOpResult<$ty> {
                    match self {
                        Some(amount) => R::Valid(amount),
                        None => R::Error(NumOpError {}),
                    }
                }
            }
        )*
    }
}
impl_opt_ext!(Amount, SignedAmount);

/// An error occurred while doing a mathematical operation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NumOpError;

impl fmt::Display for NumOpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a math operation gave an invalid numeric result")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NumOpError {}
