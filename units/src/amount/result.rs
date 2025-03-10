// SPDX-License-Identifier: CC0-1.0

//! Provides a monodic type used when mathematical operations (`core::ops`) return an amount type.

use core::{fmt, ops};

use NumOpResult as R;

use super::{Amount, SignedAmount};

/// Result of an operation on [`Amount`] or [`SignedAmount`].
///
/// The type parameter `T` should be normally `Amount` or `SignedAmount`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[must_use]
pub enum NumOpResult<T> {
    /// Result of a successful mathematical operation.
    Valid(T),
    /// Result of an unsuccessful mathematical operation.
    Error(NumOpError),
}

impl<T: fmt::Debug> NumOpResult<T> {
    /// Returns the contained valid amount, consuming `self`.
    ///
    /// # Panics
    ///
    /// Panics with `msg` if the numeric result is an `Error`.
    #[inline]
    #[track_caller]
    pub fn expect(self, msg: &str) -> T {
        match self {
            R::Valid(amount) => amount,
            R::Error(_) => panic!("{}", msg),
        }
    }

    /// Returns the contained valid amount, consuming `self`.
    ///
    /// # Panics
    ///
    /// Panics if the numeric result is an `Error`.
    #[inline]
    #[track_caller]
    pub fn unwrap(self) -> T {
        match self {
            R::Valid(amount) => amount,
            R::Error(e) => panic!("tried to unwrap an invalid numeric result: {:?}", e),
        }
    }

    /// Returns the contained error, consuming `self`.
    ///
    /// # Panics
    ///
    /// Panics if the numeric result is a valid amount.
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
            R::Valid(amount) => Some(amount),
            R::Error(_) => None,
        }
    }

    /// Converts this `NumOpResult` to a `Result<T, NumOpError>`.
    #[inline]
    #[allow(clippy::missing_errors_doc)]
    pub fn into_result(self) -> Result<T, NumOpError> {
        match self {
            R::Valid(amount) => Ok(amount),
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
            R::Valid(amount) => op(amount),
            R::Error(e) => R::Error(e),
        }
    }

    /// Returns `true` if the numeric result is a valid amount.
    #[inline]
    pub fn is_valid(&self) -> bool {
        match self {
            R::Valid(_) => true,
            R::Error(_) => false,
        }
    }

    /// Returns `true` if the numeric result is an invalid amount.
    #[inline]
    pub fn is_error(&self) -> bool { !self.is_valid() }
}

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

        fn add(self, rhs: Amount) -> Self::Output { self.checked_add(rhs).valid_or_error() }
    }
    impl ops::Add<NumOpResult<Amount>> for Amount {
        type Output = NumOpResult<Amount>;

        fn add(self, rhs: NumOpResult<Amount>) -> Self::Output { rhs.and_then(|a| a + self) }
    }

    impl ops::Sub<Amount> for Amount {
        type Output = NumOpResult<Amount>;

        fn sub(self, rhs: Amount) -> Self::Output { self.checked_sub(rhs).valid_or_error() }
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

        fn mul(self, rhs: u64) -> Self::Output { self.checked_mul(rhs).valid_or_error() }
    }
    impl ops::Mul<u64> for NumOpResult<Amount> {
        type Output = NumOpResult<Amount>;

        fn mul(self, rhs: u64) -> Self::Output { self.and_then(|lhs| lhs * rhs) }
    }
    impl ops::Mul<Amount> for u64 {
        type Output = NumOpResult<Amount>;

        fn mul(self, rhs: Amount) -> Self::Output { rhs.checked_mul(self).valid_or_error() }
    }
    impl ops::Mul<NumOpResult<Amount>> for u64 {
        type Output = NumOpResult<Amount>;

        fn mul(self, rhs: NumOpResult<Amount>) -> Self::Output { rhs.and_then(|rhs| self * rhs) }
    }

    impl ops::Div<u64> for Amount {
        type Output = NumOpResult<Amount>;

        fn div(self, rhs: u64) -> Self::Output { self.checked_div(rhs).valid_or_error() }
    }
    impl ops::Div<u64> for NumOpResult<Amount> {
        type Output = NumOpResult<Amount>;

        fn div(self, rhs: u64) -> Self::Output { self.and_then(|lhs| lhs / rhs) }
    }
    impl ops::Div<Amount> for Amount {
        type Output = u64;

        fn div(self, rhs: Amount) -> Self::Output { self.to_sat() / rhs.to_sat() }
    }

    impl ops::Rem<u64> for Amount {
        type Output = NumOpResult<Amount>;

        fn rem(self, modulus: u64) -> Self::Output { self.checked_rem(modulus).valid_or_error() }
    }
    impl ops::Rem<u64> for NumOpResult<Amount> {
        type Output = NumOpResult<Amount>;

        fn rem(self, modulus: u64) -> Self::Output { self.and_then(|lhs| lhs % modulus) }
    }

    impl ops::Add<SignedAmount> for SignedAmount {
        type Output = NumOpResult<SignedAmount>;

        fn add(self, rhs: SignedAmount) -> Self::Output { self.checked_add(rhs).valid_or_error() }
    }
    impl ops::Add<NumOpResult<SignedAmount>> for SignedAmount {
        type Output = NumOpResult<SignedAmount>;

        fn add(self, rhs: NumOpResult<SignedAmount>) -> Self::Output { rhs.and_then(|a| a + self) }
    }

    impl ops::Sub<SignedAmount> for SignedAmount {
        type Output = NumOpResult<SignedAmount>;

        fn sub(self, rhs: SignedAmount) -> Self::Output { self.checked_sub(rhs).valid_or_error() }
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

        fn mul(self, rhs: i64) -> Self::Output { self.checked_mul(rhs).valid_or_error() }
    }
    impl ops::Mul<i64> for NumOpResult<SignedAmount> {
        type Output = NumOpResult<SignedAmount>;

        fn mul(self, rhs: i64) -> Self::Output { self.and_then(|lhs| lhs * rhs) }
    }
    impl ops::Mul<SignedAmount> for i64 {
        type Output = NumOpResult<SignedAmount>;

        fn mul(self, rhs: SignedAmount) -> Self::Output { rhs.checked_mul(self).valid_or_error() }
    }
    impl ops::Mul<NumOpResult<SignedAmount>> for i64 {
        type Output = NumOpResult<SignedAmount>;

        fn mul(self, rhs: NumOpResult<SignedAmount>) -> Self::Output { rhs.and_then(|rhs| self * rhs) }
    }

    impl ops::Div<i64> for SignedAmount {
        type Output = NumOpResult<SignedAmount>;

        fn div(self, rhs: i64) -> Self::Output { self.checked_div(rhs).valid_or_error() }
    }
    impl ops::Div<i64> for NumOpResult<SignedAmount> {
        type Output = NumOpResult<SignedAmount>;

        fn div(self, rhs: i64) -> Self::Output { self.and_then(|lhs| lhs / rhs) }
    }
    impl ops::Div<SignedAmount> for SignedAmount {
        type Output = i64;

        fn div(self, rhs: SignedAmount) -> Self::Output { self.to_sat() / rhs.to_sat() }
    }

    impl ops::Rem<i64> for SignedAmount {
        type Output = NumOpResult<SignedAmount>;

        fn rem(self, modulus: i64) -> Self::Output { self.checked_rem(modulus).valid_or_error() }
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
                (_, _) => R::Error(NumOpError {}),
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
                (_, _) => R::Error(NumOpError {}),
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

impl ops::Neg for SignedAmount {
    type Output = Self;

    fn neg(self) -> Self::Output { Self::from_sat(self.to_sat().neg()) }
}

impl core::iter::Sum<NumOpResult<Amount>> for NumOpResult<Amount> {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = NumOpResult<Amount>>,
    {
        iter.fold(R::Valid(Amount::ZERO), |acc, amount| match (acc, amount) {
            (R::Valid(lhs), R::Valid(rhs)) => lhs + rhs,
            (_, _) => R::Error(NumOpError {}),
        })
    }
}
impl<'a> core::iter::Sum<&'a NumOpResult<Amount>> for NumOpResult<Amount> {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a NumOpResult<Amount>>,
    {
        iter.fold(R::Valid(Amount::ZERO), |acc, amount| match (acc, amount) {
            (R::Valid(lhs), R::Valid(rhs)) => lhs + rhs,
            (_, _) => R::Error(NumOpError {}),
        })
    }
}

impl core::iter::Sum<NumOpResult<SignedAmount>> for NumOpResult<SignedAmount> {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = NumOpResult<SignedAmount>>,
    {
        iter.fold(R::Valid(SignedAmount::ZERO), |acc, amount| match (acc, amount) {
            (R::Valid(lhs), R::Valid(rhs)) => lhs + rhs,
            (_, _) => R::Error(NumOpError {}),
        })
    }
}
impl<'a> core::iter::Sum<&'a NumOpResult<SignedAmount>> for NumOpResult<SignedAmount> {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a NumOpResult<SignedAmount>>,
    {
        iter.fold(R::Valid(SignedAmount::ZERO), |acc, amount| match (acc, amount) {
            (R::Valid(lhs), R::Valid(rhs)) => lhs + rhs,
            (_, _) => R::Error(NumOpError {}),
        })
    }
}

pub(crate) trait OptionExt<T> {
    fn valid_or_error(self) -> NumOpResult<T>;
}

impl OptionExt<Amount> for Option<Amount> {
    #[inline]
    fn valid_or_error(self) -> NumOpResult<Amount> {
        match self {
            Some(amount) => R::Valid(amount),
            None => R::Error(NumOpError {}),
        }
    }
}

impl OptionExt<SignedAmount> for Option<SignedAmount> {
    #[inline]
    fn valid_or_error(self) -> NumOpResult<SignedAmount> {
        match self {
            Some(amount) => R::Valid(amount),
            None => R::Error(NumOpError {}),
        }
    }
}

/// An error occurred while doing a mathematical operation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NumOpError;

impl fmt::Display for NumOpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a math operation on amounts gave an invalid numeric result")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NumOpError {}
