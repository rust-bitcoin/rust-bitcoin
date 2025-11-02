// SPDX-License-Identifier: CC0-1.0

//! Provides a monodic type returned by mathematical operations (`core::ops`).

use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use NumOpResult as R;

use crate::{Amount, FeeRate, SignedAmount, Weight};

/// Result of a mathematical operation on two numeric types.
///
/// In order to prevent overflow we provide a custom result type that is similar to the normal
/// [`core::result::Result`] but implements mathematical operations (e.g. [`core::ops::Add`]) so that
/// math operations can be chained ergonomically. This is very similar to how `NaN` works.
///
/// `NumOpResult` is a monadic type that contains `Valid` and `Error` (similar to `Ok` and `Err`).
/// It supports a subset of functions similar to `Result` (e.g. `unwrap`).
///
/// # Examples
///
/// The `NumOpResult` type provides protection against overflow and div-by-zero.
///
/// ### Overflow protection
///
/// ```
/// # use bitcoin_units::{amount, Amount};
/// // Example UTXO value.
/// let a1 = Amount::from_sat(1_000_000)?;
/// // And another value from some other UTXO.
/// let a2 = Amount::from_sat(765_432)?;
/// // Just an example (typically one would calculate fee using weight and fee rate).
/// let fee = Amount::from_sat(1_00)?;
/// // The amount we want to send.
/// let spend = Amount::from_sat(1_200_000)?;
///
/// // We can error if the change calculation overflows.
/// //
/// // For example if the `spend` value comes from the user and the `change` value is later
/// // used then overflow here could be an attack vector.
/// let _change = (a1 + a2 - spend - fee).into_result().expect("handle this error");
///
/// // Or if we control all the values and know they are sane we can just `unwrap`.
/// let _change = (a1 + a2 - spend - fee).unwrap();
/// // `NumOpResult` also implements `expect`.
/// let _change = (a1 + a2 - spend - fee).expect("we know values don't overflow");
/// # Ok::<_, amount::OutOfRangeError>(())
/// ```
///
/// ### Divide-by-zero (overflow in `Div` or `Rem`)
///
/// In some instances one may wish to differentiate div-by-zero from overflow.
///
/// ```
/// # use bitcoin_units::{Amount, FeeRate, NumOpResult, result::NumOpError};
/// // Two amounts that will be added to calculate the max fee.
/// let a = Amount::from_sat(123).expect("valid amount");
/// let b = Amount::from_sat(467).expect("valid amount");
/// // Fee rate for transaction.
/// let fee_rate = FeeRate::from_sat_per_vb(1);
///
/// // Somewhat contrived example to show addition operator chained with division.
/// let max_fee = a + b;
/// let _fee = match max_fee / fee_rate {
///     NumOpResult::Valid(fee) => fee,
///     NumOpResult::Error(e) if e.is_div_by_zero() => {
///         // Do something when div by zero.
///         return Err(e);
///     },
///     NumOpResult::Error(e) => {
///         // We separate div-by-zero from overflow in case it needs to be handled separately.
///         //
///         // This branch could be hit since `max_fee` came from some previous calculation. And if
///         // an input to that calculation was from the user then overflow could be an attack vector.
///         return Err(e);
///     }
/// };
/// # Ok::<_, NumOpError>(())
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[must_use]
pub enum NumOpResult<T> {
    /// Result of a successful mathematical operation.
    Valid(T),
    /// Result of an unsuccessful mathematical operation.
    Error(NumOpError),
}

impl<T> NumOpResult<T> {
    /// Maps a `NumOpResult<T>` to `NumOpResult<U>` by applying a function to a
    /// contained [`NumOpResult::Valid`] value, leaving a [`NumOpResult::Error`] value untouched.
    #[inline]
    pub fn map<U, F: FnOnce(T) -> U>(self, op: F) -> NumOpResult<U> {
        match self {
            Self::Valid(t) => NumOpResult::Valid(op(t)),
            Self::Error(e) => NumOpResult::Error(e),
        }
    }
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
            Self::Valid(x) => x,
            Self::Error(_) => panic!("{}", msg),
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
            Self::Valid(x) => x,
            Self::Error(e) => panic!("tried to unwrap an invalid numeric result: {:?}", e),
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
            Self::Error(e) => e,
            Self::Valid(a) => panic!("tried to unwrap a valid numeric result: {:?}", a),
        }
    }

    /// Returns the contained Some value or a provided default.
    ///
    /// Arguments passed to `unwrap_or` are eagerly evaluated; if you are passing the result of a
    /// function call, it is recommended to use `unwrap_or_else`, which is lazily evaluated.
    #[inline]
    #[track_caller]
    pub fn unwrap_or(self, default: T) -> T {
        match self {
            Self::Valid(x) => x,
            Self::Error(_) => default,
        }
    }

    /// Returns the contained `Some` value or computes it from a closure.
    #[inline]
    #[track_caller]
    pub fn unwrap_or_else<F>(self, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        match self {
            Self::Valid(x) => x,
            Self::Error(_) => f(),
        }
    }

    /// Converts this `NumOpResult` to an `Option<T>`.
    #[inline]
    pub fn ok(self) -> Option<T> {
        match self {
            Self::Valid(x) => Some(x),
            Self::Error(_) => None,
        }
    }

    /// Converts this `NumOpResult` to a `Result<T, NumOpError>`.
    #[inline]
    #[allow(clippy::missing_errors_doc)]
    pub fn into_result(self) -> Result<T, NumOpError> {
        match self {
            Self::Valid(x) => Ok(x),
            Self::Error(e) => Err(e),
        }
    }

    /// Calls `op` if the numeric result is `Valid`, otherwise returns the `Error` value of `self`.
    #[inline]
    pub fn and_then<F>(self, op: F) -> Self
    where
        F: FnOnce(T) -> Self,
    {
        match self {
            Self::Valid(x) => op(x),
            Self::Error(e) => Self::Error(e),
        }
    }

    /// Returns `true` if the numeric result is valid.
    #[inline]
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Valid(_) => true,
            Self::Error(_) => false,
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
    /// Constructs a [`NumOpError`] caused by `op`.
    pub(crate) const fn while_doing(op: MathOp) -> Self { Self(op) }

    /// Returns `true` if this operation error'ed due to overflow.
    pub fn is_overflow(self) -> bool { self.0.is_overflow() }

    /// Returns `true` if this operation error'ed due to division by zero.
    pub fn is_div_by_zero(self) -> bool { self.0.is_div_by_zero() }

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
    /// Stops users from casting this enum to an integer.
    // May get removed if one day Rust supports disabling casts natively.
    #[doc(hidden)]
    _DoNotUse(Infallible),
}

impl MathOp {
    /// Returns `true` if this operation error'ed due to overflow.
    pub fn is_overflow(self) -> bool {
        matches!(self, Self::Add | Self::Sub | Self::Mul | Self::Neg)
    }

    /// Returns `true` if this operation error'ed due to division by zero.
    pub fn is_div_by_zero(self) -> bool { !self.is_overflow() }

    /// Returns `true` if this operation error'ed due to addition.
    pub fn is_addition(self) -> bool { self == Self::Add }

    /// Returns `true` if this operation error'ed due to subtraction.
    pub fn is_subtraction(self) -> bool { self == Self::Sub }

    /// Returns `true` if this operation error'ed due to multiplication.
    pub fn is_multiplication(self) -> bool { self == Self::Mul }

    /// Returns `true` if this operation error'ed due to negation.
    pub fn is_negation(self) -> bool { self == Self::Neg }
}

impl fmt::Display for MathOp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Add => write!(f, "add"),
            Self::Sub => write!(f, "sub"),
            Self::Mul => write!(f, "mul"),
            Self::Div => write!(f, "div"),
            Self::Rem => write!(f, "rem"),
            Self::Neg => write!(f, "neg"),
            Self::_DoNotUse(infallible) => match infallible {},
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, T: Arbitrary<'a>> Arbitrary<'a> for NumOpResult<T> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match bool::arbitrary(u)? {
            true => Ok(Self::Valid(T::arbitrary(u)?)),
            false => Ok(Self::Error(NumOpError(MathOp::arbitrary(u)?))),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for MathOp {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=5)?;
        match choice {
            0 => Ok(Self::Add),
            1 => Ok(Self::Sub),
            2 => Ok(Self::Mul),
            3 => Ok(Self::Div),
            4 => Ok(Self::Rem),
            _ => Ok(Self::Neg),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::result::MathOp;

    #[test]
    fn mathop_predicates() {
        assert!(MathOp::Add.is_overflow());
        assert!(MathOp::Sub.is_overflow());
        assert!(MathOp::Mul.is_overflow());
        assert!(MathOp::Neg.is_overflow());
        assert!(!MathOp::Div.is_overflow());
        assert!(!MathOp::Rem.is_overflow());

        assert!(MathOp::Div.is_div_by_zero());
        assert!(MathOp::Rem.is_div_by_zero());
        assert!(!MathOp::Add.is_div_by_zero());

        assert!(MathOp::Add.is_addition());
        assert!(!MathOp::Sub.is_addition());

        assert!(MathOp::Sub.is_subtraction());
        assert!(!MathOp::Add.is_subtraction());

        assert!(MathOp::Mul.is_multiplication());
        assert!(!MathOp::Div.is_multiplication());

        assert!(MathOp::Neg.is_negation());
        assert!(!MathOp::Add.is_negation());
    }
}
