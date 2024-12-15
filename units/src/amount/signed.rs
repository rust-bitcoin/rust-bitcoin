// SPDX-License-Identifier: CC0-1.0

//! A signed bitcoin amount.

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};
use core::str::FromStr;
use core::{default, fmt, ops};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

use super::error::{ParseAmountErrorInner, ParseErrorInner};
use super::{
    parse_signed_to_satoshi, split_amount_and_denomination, Amount, Denomination, Display,
    DisplayStyle, OutOfRangeError, ParseAmountError, ParseError,
};

/// A signed amount.
///
/// The [`SignedAmount`] type can be used to express Bitcoin amounts that support arithmetic and
/// conversion to various denominations. The `Amount` type does not implement `serde` traits but we
/// do provide modules for serializing as satoshis or bitcoin.
///
/// Warning!
///
/// This type implements several arithmetic operations from [`core::ops`].
/// To prevent errors due to overflow or underflow when using these operations,
/// it is advised to instead use the checked arithmetic methods whose names
/// start with `checked_`.  The operations from [`core::ops`] that [`Amount`]
/// implements will panic when overflow or underflow occurs.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "serde")] {
/// use serde::{Serialize, Deserialize};
/// use bitcoin_units::SignedAmount;
///
/// #[derive(Serialize, Deserialize)]
/// struct Foo {
///     // If you are using `rust-bitcoin` then `bitcoin::amount::serde::as_sat` also works.
///     #[serde(with = "bitcoin_units::amount::serde::as_sat")]  // Also `serde::as_btc`.
///     amount: SignedAmount,
/// }
/// # }
/// ```
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignedAmount(i64);

impl SignedAmount {
    /// The zero amount.
    pub const ZERO: SignedAmount = SignedAmount(0);
    /// Exactly one satoshi.
    pub const ONE_SAT: SignedAmount = SignedAmount(1);
    /// Exactly one bitcoin.
    pub const ONE_BTC: SignedAmount = SignedAmount(100_000_000);
    /// The maximum value allowed as an amount. Useful for sanity checking.
    pub const MAX_MONEY: SignedAmount = SignedAmount(21_000_000 * 100_000_000);
    /// The minimum value of an amount.
    pub const MIN: SignedAmount = SignedAmount(-21_000_000 * 100_000_000);
    /// The maximum value of an amount.
    pub const MAX: SignedAmount = SignedAmount::MAX_MONEY;

    /// Constructs a new [`SignedAmount`] with satoshi precision and the given number of satoshis.
    pub const fn from_sat(satoshi: i64) -> SignedAmount { SignedAmount(satoshi) }

    /// Gets the number of satoshis in this [`SignedAmount`].
    pub const fn to_sat(self) -> i64 { self.0 }

    /// Converts from a value expressing a whole number of bitcoin to a [`SignedAmount`].
    #[cfg(feature = "alloc")]
    pub fn from_btc(btc: f64) -> Result<SignedAmount, ParseAmountError> {
        SignedAmount::from_float_in(btc, Denomination::Bitcoin)
    }

    /// Converts from a value expressing a whole number of bitcoin to a [`SignedAmount`].
    ///
    /// # Errors
    ///
    /// The function errors if the argument multiplied by the number of sats
    /// per bitcoin overflows an `i64` type.
    pub fn from_int_btc(btc: i64) -> Result<SignedAmount, OutOfRangeError> {
        match btc.checked_mul(100_000_000) {
            Some(amount) => Ok(SignedAmount::from_sat(amount)),
            None => Err(OutOfRangeError { is_signed: true, is_greater_than_max: true }),
        }
    }

    /// Converts from a value expressing a whole number of bitcoin to a [`SignedAmount`]
    /// in const context.
    ///
    /// # Panics
    ///
    /// The function panics if the argument multiplied by the number of sats
    /// per bitcoin overflows an `i64` type.
    pub const fn from_int_btc_const(btc: i64) -> SignedAmount {
        match btc.checked_mul(100_000_000) {
            Some(amount) => SignedAmount::from_sat(amount),
            None => panic!("checked_mul overflowed"),
        }
    }

    /// Parses a decimal string as a value in the given denomination.
    ///
    /// Note: This only parses the value string.  If you want to parse a value
    /// with denomination, use [`FromStr`].
    pub fn from_str_in(s: &str, denom: Denomination) -> Result<SignedAmount, ParseAmountError> {
        match parse_signed_to_satoshi(s, denom).map_err(|error| error.convert(true))? {
            // (negative, amount)
            (false, sat) if sat > SignedAmount::MAX.to_sat() as u64 => Err(ParseAmountError(
                ParseAmountErrorInner::OutOfRange(OutOfRangeError::too_big(true)),
            )),
            (false, sat) => Ok(SignedAmount(sat as i64)),
            (true, sat) if sat > SignedAmount::MIN.to_sat().unsigned_abs() => Err(
                ParseAmountError(ParseAmountErrorInner::OutOfRange(OutOfRangeError::too_small())),
            ),
            (true, sat) => Ok(SignedAmount(-(sat as i64))),
        }
    }

    /// Parses amounts with denomination suffix as produced by [`Self::to_string_with_denomination`]
    /// or with [`fmt::Display`].
    ///
    /// If you want to parse only the amount without the denomination, use [`Self::from_str_in`].
    pub fn from_str_with_denomination(s: &str) -> Result<SignedAmount, ParseError> {
        let (amt, denom) = split_amount_and_denomination(s)?;
        SignedAmount::from_str_in(amt, denom).map_err(Into::into)
    }

    /// Express this [`SignedAmount`] as a floating-point value in the given denomination.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    #[cfg(feature = "alloc")]
    pub fn to_float_in(self, denom: Denomination) -> f64 {
        self.to_string_in(denom).parse::<f64>().unwrap()
    }

    /// Express this [`SignedAmount`] as a floating-point value in Bitcoin.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::amount::{SignedAmount, Denomination};
    /// let amount = SignedAmount::from_sat(100_000);
    /// assert_eq!(amount.to_btc(), amount.to_float_in(Denomination::Bitcoin))
    /// ```
    #[cfg(feature = "alloc")]
    pub fn to_btc(self) -> f64 { self.to_float_in(Denomination::Bitcoin) }

    /// Convert this [`SignedAmount`] in floating-point notation with a given
    /// denomination.
    ///
    /// # Errors
    ///
    /// If the amount is too big, too precise or negative.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    #[cfg(feature = "alloc")]
    pub fn from_float_in(
        value: f64,
        denom: Denomination,
    ) -> Result<SignedAmount, ParseAmountError> {
        // This is inefficient, but the safest way to deal with this. The parsing logic is safe.
        // Any performance-critical application should not be dealing with floats.
        SignedAmount::from_str_in(&value.to_string(), denom)
    }

    /// Constructs a new object that implements [`fmt::Display`] using specified denomination.
    #[must_use]
    pub fn display_in(self, denomination: Denomination) -> Display {
        Display {
            sats_abs: self.unsigned_abs().to_sat(),
            is_negative: self.is_negative(),
            style: DisplayStyle::FixedDenomination { denomination, show_denomination: false },
        }
    }

    /// Constructs a new object that implements [`fmt::Display`] dynamically selecting denomination.
    ///
    /// This will use BTC for values greater than or equal to 1 BTC and satoshis otherwise. To
    /// avoid confusion the denomination is always shown.
    #[must_use]
    pub fn display_dynamic(self) -> Display {
        Display {
            sats_abs: self.unsigned_abs().to_sat(),
            is_negative: self.is_negative(),
            style: DisplayStyle::DynamicDenomination,
        }
    }

    /// Returns a formatted string representing this [`SignedAmount`] in the given denomination.
    ///
    /// Does not include the denomination.
    #[cfg(feature = "alloc")]
    pub fn to_string_in(self, denom: Denomination) -> String { self.display_in(denom).to_string() }

    /// Returns a formatted string representing this [`Amount`] in the given denomination, suffixed
    /// with the abbreviation for the denomination.
    #[cfg(feature = "alloc")]
    pub fn to_string_with_denomination(self, denom: Denomination) -> String {
        self.display_in(denom).show_denomination().to_string()
    }

    // Some arithmetic that doesn't fit in [`core::ops`] traits.

    /// Get the absolute value of this [`SignedAmount`].
    #[must_use]
    pub fn abs(self) -> SignedAmount { SignedAmount(self.0.abs()) }

    /// Gets the absolute value of this [`SignedAmount`] returning [`Amount`].
    #[must_use]
    pub fn unsigned_abs(self) -> Amount { Amount::from_sat(self.0.unsigned_abs()) }

    /// Returns a number representing sign of this [`SignedAmount`].
    ///
    /// - `0` if the amount is zero
    /// - `1` if the amount is positive
    /// - `-1` if the amount is negative
    #[must_use]
    pub fn signum(self) -> i64 { self.0.signum() }

    /// Checks if this [`SignedAmount`] is positive.
    ///
    /// Returns `true` if this [`SignedAmount`] is positive and `false` if
    /// this [`SignedAmount`] is zero or negative.
    pub fn is_positive(self) -> bool { self.0.is_positive() }

    /// Checks if this [`SignedAmount`] is negative.
    ///
    /// Returns `true` if this [`SignedAmount`] is negative and `false` if
    /// this [`SignedAmount`] is zero or positive.
    pub fn is_negative(self) -> bool { self.0.is_negative() }

    /// Returns the absolute value of this [`SignedAmount`].
    ///
    /// Consider using `unsigned_abs` which is often more practical.
    ///
    /// Returns [`None`] if overflow occurred. (`self == MIN`)
    #[must_use]
    pub const fn checked_abs(self) -> Option<SignedAmount> {
        // No `map()` in const context.
        match self.0.checked_abs() {
            Some(res) => Some(SignedAmount(res)),
            None => None,
        }
    }

    /// Checked addition.
    ///
    /// Returns [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_add(self, rhs: SignedAmount) -> Option<SignedAmount> {
        // No `map()` in const context.
        match self.0.checked_add(rhs.0) {
            Some(res) => SignedAmount(res).check_min_max(),
            None => None,
        }
    }

    /// Checked subtraction.
    ///
    /// Returns [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_sub(self, rhs: SignedAmount) -> Option<SignedAmount> {
        // No `map()` in const context.
        match self.0.checked_sub(rhs.0) {
            Some(res) => SignedAmount(res).check_min_max(),
            None => None,
        }
    }

    /// Checked multiplication.
    ///
    /// Returns [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_mul(self, rhs: i64) -> Option<SignedAmount> {
        // No `map()` in const context.
        match self.0.checked_mul(rhs) {
            Some(res) => SignedAmount(res).check_min_max(),
            None => None,
        }
    }

    /// Checked integer division.
    ///
    /// Be aware that integer division loses the remainder if no exact division can be made.
    ///
    /// Returns [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_div(self, rhs: i64) -> Option<SignedAmount> {
        // No `map()` in const context.
        match self.0.checked_div(rhs) {
            Some(res) => Some(SignedAmount(res)),
            None => None,
        }
    }

    /// Checked remainder.
    ///
    /// Returns [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_rem(self, rhs: i64) -> Option<SignedAmount> {
        // No `map()` in const context.
        match self.0.checked_rem(rhs) {
            Some(res) => Some(SignedAmount(res)),
            None => None,
        }
    }

    /// Unchecked addition.
    ///
    /// Computes `self + rhs`.
    ///
    /// # Panics
    ///
    /// On overflow, panics in debug mode, wraps in release mode.
    #[must_use]
    pub fn unchecked_add(self, rhs: SignedAmount) -> SignedAmount { Self(self.0 + rhs.0) }

    /// Unchecked subtraction.
    ///
    /// Computes `self - rhs`.
    ///
    /// # Panics
    ///
    /// On overflow, panics in debug mode, wraps in release mode.
    #[must_use]
    pub fn unchecked_sub(self, rhs: SignedAmount) -> SignedAmount { Self(self.0 - rhs.0) }

    /// Subtraction that doesn't allow negative [`SignedAmount`]s.
    ///
    /// Returns [`None`] if either `self`, `rhs` or the result is strictly negative.
    #[must_use]
    pub fn positive_sub(self, rhs: SignedAmount) -> Option<SignedAmount> {
        if self.is_negative() || rhs.is_negative() || rhs > self {
            None
        } else {
            self.checked_sub(rhs)
        }
    }

    /// Converts to an unsigned amount.
    pub fn to_unsigned(self) -> Result<Amount, OutOfRangeError> {
        if self.is_negative() {
            Err(OutOfRangeError::negative())
        } else {
            Ok(Amount::from_sat(self.to_sat() as u64))
        }
    }

    /// Checks the amount is within the allowed range.
    const fn check_min_max(self) -> Option<SignedAmount> {
        if self.0 < Self::MIN.0 || self.0 > Self::MAX.0 {
            None
        } else {
            Some(self)
        }
    }
}

impl default::Default for SignedAmount {
    fn default() -> Self { SignedAmount::ZERO }
}

impl fmt::Debug for SignedAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SignedAmount({} SAT)", self.to_sat())
    }
}

// No one should depend on a binding contract for Display for this type.
// Just using Bitcoin denominated string.
impl fmt::Display for SignedAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.display_in(Denomination::Bitcoin).show_denomination(), f)
    }
}

impl ops::Add for SignedAmount {
    type Output = SignedAmount;

    fn add(self, rhs: SignedAmount) -> Self::Output {
        self.checked_add(rhs).expect("SignedAmount addition error")
    }
}

impl ops::AddAssign for SignedAmount {
    fn add_assign(&mut self, other: SignedAmount) { *self = *self + other }
}

impl ops::Sub for SignedAmount {
    type Output = SignedAmount;

    fn sub(self, rhs: SignedAmount) -> Self::Output {
        self.checked_sub(rhs).expect("SignedAmount subtraction error")
    }
}

impl ops::SubAssign for SignedAmount {
    fn sub_assign(&mut self, other: SignedAmount) { *self = *self - other }
}

impl ops::Rem<i64> for SignedAmount {
    type Output = SignedAmount;

    fn rem(self, modulus: i64) -> Self {
        self.checked_rem(modulus).expect("SignedAmount remainder error")
    }
}

impl ops::RemAssign<i64> for SignedAmount {
    fn rem_assign(&mut self, modulus: i64) { *self = *self % modulus }
}

impl ops::Mul<i64> for SignedAmount {
    type Output = SignedAmount;

    fn mul(self, rhs: i64) -> Self::Output {
        self.checked_mul(rhs).expect("SignedAmount multiplication error")
    }
}

impl ops::MulAssign<i64> for SignedAmount {
    fn mul_assign(&mut self, rhs: i64) { *self = *self * rhs }
}

impl ops::Div<i64> for SignedAmount {
    type Output = SignedAmount;

    fn div(self, rhs: i64) -> Self::Output {
        self.checked_div(rhs).expect("SignedAmount division error")
    }
}

impl ops::DivAssign<i64> for SignedAmount {
    fn div_assign(&mut self, rhs: i64) { *self = *self / rhs }
}

impl ops::Neg for SignedAmount {
    type Output = Self;

    fn neg(self) -> Self::Output { Self(self.0.neg()) }
}

impl FromStr for SignedAmount {
    type Err = ParseError;

    /// Parses a string slice where the slice includes a denomination.
    ///
    /// If the returned value would be zero or negative zero, then no denomination is required.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let result = SignedAmount::from_str_with_denomination(s);

        match result {
            Err(ParseError(ParseErrorInner::MissingDenomination(_))) => {
                let d = SignedAmount::from_str_in(s, Denomination::Satoshi);

                if d == Ok(SignedAmount::ZERO) {
                    Ok(SignedAmount::ZERO)
                } else {
                    result
                }
            }
            _ => result,
        }
    }
}

impl TryFrom<Amount> for SignedAmount {
    type Error = OutOfRangeError;

    fn try_from(value: Amount) -> Result<Self, Self::Error> { value.to_signed() }
}

impl core::iter::Sum for SignedAmount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let sats: i64 = iter.map(|amt| amt.0).sum();
        SignedAmount::from_sat(sats)
    }
}

impl<'a> core::iter::Sum<&'a SignedAmount> for SignedAmount {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a SignedAmount>,
    {
        let sats: i64 = iter.map(|amt| amt.0).sum();
        SignedAmount::from_sat(sats)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for SignedAmount {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let s = i64::arbitrary(u)?;
        Ok(SignedAmount(s))
    }
}
