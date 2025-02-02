// SPDX-License-Identifier: CC0-1.0

//! An unsigned bitcoin amount.

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};
use core::str::FromStr;
use core::{default, fmt, ops};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

use super::error::{ParseAmountErrorInner, ParseErrorInner};
use super::{
    parse_signed_to_satoshi, split_amount_and_denomination, Denomination, Display, DisplayStyle,
    OutOfRangeError, ParseAmountError, ParseError, SignedAmount,
};

/// An amount.
///
/// The [`Amount`] type can be used to express Bitcoin amounts that support arithmetic and
/// conversion to various denominations. The [`Amount`] type does not implement [`serde`] traits
/// but we do provide modules for serializing as satoshis or bitcoin.
///
/// Warning!
///
/// This type implements several arithmetic operations from [`core::ops`].
/// To prevent errors due to overflow or underflow when using these operations,
/// it is advised to instead use the checked arithmetic methods whose names
/// start with `checked_`. The operations from [`core::ops`] that [`Amount`]
/// implements will panic when overflow or underflow occurs. Also note that
/// since the internal representation of amounts is unsigned, subtracting below
/// zero is considered an underflow and will cause a panic if you're not using
/// the checked arithmetic methods.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "serde")] {
/// use serde::{Serialize, Deserialize};
/// use bitcoin_units::Amount;
///
/// #[derive(Serialize, Deserialize)]
/// struct Foo {
///     // If you are using `rust-bitcoin` then `bitcoin::amount::serde::as_sat` also works.
///     #[serde(with = "bitcoin_units::amount::serde::as_sat")]  // Also `serde::as_btc`.
///     amount: Amount,
/// }
/// # }
/// ```
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(u64);

impl Amount {
    /// The zero amount.
    pub const ZERO: Self = Amount(0);
    /// Exactly one satoshi.
    pub const ONE_SAT: Self = Amount(1);
    /// Exactly one bitcoin.
    pub const ONE_BTC: Self = Self::from_int_btc_const(1);
    /// Exactly fifty bitcoin.
    pub const FIFTY_BTC: Self = Self::from_sat(50 * 100_000_000);
    /// The maximum value allowed as an amount. Useful for sanity checking.
    pub const MAX_MONEY: Self = Self::from_int_btc_const(21_000_000);
    /// The minimum value of an amount.
    pub const MIN: Self = Amount::ZERO;
    /// The maximum value of an amount.
    pub const MAX: Amount = Amount(u64::MAX);
    /// The number of bytes that an amount contributes to the size of a transaction.
    pub const SIZE: usize = 8; // Serialized length of a u64.

    /// Constructs a new [`Amount`] with satoshi precision and the given number of satoshis.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::Amount;
    /// let amount = Amount::from_sat(100_000);
    /// assert_eq!(amount.to_sat(), 100_000);
    /// ```
    pub const fn from_sat(satoshi: u64) -> Amount { Amount(satoshi) }

    /// Gets the number of satoshis in this [`Amount`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::Amount;
    /// assert_eq!(Amount::ONE_BTC.to_sat(), 100_000_000);
    /// ```
    pub const fn to_sat(self) -> u64 { self.0 }

    /// Converts from a value expressing a decimal number of bitcoin to an [`Amount`].
    ///
    /// # Errors
    ///
    /// If the amount is too big, too precise or negative.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::Amount;
    /// let amount = Amount::from_btc(0.01).expect("we know 0.01 is valid");
    /// assert_eq!(amount.to_sat(), 1_000_000);
    /// ```
    #[cfg(feature = "alloc")]
    pub fn from_btc(btc: f64) -> Result<Amount, ParseAmountError> {
        Self::from_float_in(btc, Denomination::Bitcoin)
    }

    /// Converts from a value expressing a whole number of bitcoin to an [`Amount`].
    ///
    /// # Errors
    ///
    /// The function errors if the argument multiplied by the number of sats
    /// per bitcoin overflows a `u64` type.
    pub fn from_int_btc<T: Into<u64>>(whole_bitcoin: T) -> Result<Amount, OutOfRangeError> {
        match whole_bitcoin.into().checked_mul(100_000_000) {
            Some(amount) => Ok(Self::from_sat(amount)),
            None => Err(OutOfRangeError { is_signed: false, is_greater_than_max: true }),
        }
    }

    /// Converts from a value expressing a whole number of bitcoin to an [`Amount`]
    /// in const context.
    ///
    /// # Panics
    ///
    /// The function panics if the argument multiplied by the number of sats
    /// per bitcoin overflows a `u64` type.
    pub const fn from_int_btc_const(whole_bitcoin: u32) -> Amount {
        let btc = whole_bitcoin as u64; // Can't call u64::from in const context.
        match btc.checked_mul(100_000_000) {
            Some(amount) => Amount::from_sat(amount),
            None => panic!("checked_mul overflowed"),
        }
    }

    /// Parses a decimal string as a value in the given [`Denomination`].
    ///
    /// Note: This only parses the value string. If you want to parse a string
    /// containing the value with denomination, use [`FromStr`].
    ///
    /// # Errors
    ///
    /// If the amount is too big, too precise or negative.
    pub fn from_str_in(s: &str, denom: Denomination) -> Result<Amount, ParseAmountError> {
        let (negative, sats) =
            parse_signed_to_satoshi(s, denom).map_err(|error| error.convert(false))?;
        if negative {
            return Err(ParseAmountError(ParseAmountErrorInner::OutOfRange(
                OutOfRangeError::negative(),
            )));
        }
        Ok(Amount::from_sat(sats))
    }

    /// Parses amounts with denomination suffix as produced by [`Self::to_string_with_denomination`]
    /// or with [`fmt::Display`].
    ///
    /// If you want to parse only the amount without the denomination, use [`Self::from_str_in`].
    ///
    /// # Errors
    ///
    /// If the amount is too big, too precise or negative.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::{amount, Amount};
    /// let amount = Amount::from_str_with_denomination("0.1 BTC")?;
    /// assert_eq!(amount, Amount::from_sat(10_000_000));
    /// # Ok::<_, amount::ParseError>(())
    /// ```
    pub fn from_str_with_denomination(s: &str) -> Result<Amount, ParseError> {
        let (amt, denom) = split_amount_and_denomination(s)?;
        Self::from_str_in(amt, denom).map_err(Into::into)
    }

    /// Expresses this [`Amount`] as a floating-point value in the given [`Denomination`].
    ///
    /// Please be aware of the risk of using floating-point numbers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::amount::{Amount, Denomination};
    /// let amount = Amount::from_sat(100_000);
    /// assert_eq!(amount.to_float_in(Denomination::Bitcoin), 0.001)
    /// ```
    #[cfg(feature = "alloc")]
    #[allow(clippy::missing_panics_doc)]
    pub fn to_float_in(self, denom: Denomination) -> f64 {
        self.to_string_in(denom).parse::<f64>().unwrap()
    }

    /// Expresses this [`Amount`] as a floating-point value in Bitcoin.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::amount::{Amount, Denomination};
    /// let amount = Amount::from_sat(100_000);
    /// assert_eq!(amount.to_btc(), amount.to_float_in(Denomination::Bitcoin))
    /// ```
    #[cfg(feature = "alloc")]
    pub fn to_btc(self) -> f64 { self.to_float_in(Denomination::Bitcoin) }

    /// Converts this [`Amount`] in floating-point notation in the given [`Denomination`].
    ///
    /// # Errors
    ///
    /// If the amount is too big, too precise or negative.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    #[cfg(feature = "alloc")]
    pub fn from_float_in(value: f64, denom: Denomination) -> Result<Amount, ParseAmountError> {
        if value < 0.0 {
            return Err(OutOfRangeError::negative().into());
        }
        // This is inefficient, but the safest way to deal with this. The parsing logic is safe.
        // Any performance-critical application should not be dealing with floats.
        Self::from_str_in(&value.to_string(), denom)
    }

    /// Constructs a new object that implements [`fmt::Display`] in the given [`Denomination`].
    ///
    /// This function is useful if you do not wish to allocate. See also [`Self::to_string_in`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::amount::{Amount, Denomination};
    /// # use std::fmt::Write;
    /// let amount = Amount::from_sat(10_000_000);
    /// let mut output = String::new();
    /// write!(&mut output, "{}", amount.display_in(Denomination::Bitcoin))?;
    /// assert_eq!(output, "0.1");
    /// # Ok::<(), std::fmt::Error>(())
    /// ```
    #[must_use]
    pub fn display_in(self, denomination: Denomination) -> Display {
        Display {
            sats_abs: self.to_sat(),
            is_negative: false,
            style: DisplayStyle::FixedDenomination { denomination, show_denomination: false },
        }
    }

    /// Constructs a new object that implements [`fmt::Display`] dynamically selecting
    /// [`Denomination`].
    ///
    /// This will use BTC for values greater than or equal to 1 BTC and satoshis otherwise. To
    /// avoid confusion the denomination is always shown.
    #[must_use]
    pub fn display_dynamic(self) -> Display {
        Display {
            sats_abs: self.to_sat(),
            is_negative: false,
            style: DisplayStyle::DynamicDenomination,
        }
    }

    /// Returns a formatted string representing this [`Amount`] in the given [`Denomination`].
    ///
    /// Returned string does not include the denomination.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::amount::{Amount, Denomination};
    /// let amount = Amount::from_sat(10_000_000);
    /// assert_eq!(amount.to_string_in(Denomination::Bitcoin), "0.1")
    /// ```
    #[cfg(feature = "alloc")]
    pub fn to_string_in(self, denom: Denomination) -> String { self.display_in(denom).to_string() }

    /// Returns a formatted string representing this [`Amount`] in the given [`Denomination`],
    /// suffixed with the abbreviation for the denomination.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::amount::{Amount, Denomination};
    /// let amount = Amount::from_sat(10_000_000);
    /// assert_eq!(amount.to_string_with_denomination(Denomination::Bitcoin), "0.1 BTC")
    /// ```
    #[cfg(feature = "alloc")]
    pub fn to_string_with_denomination(self, denom: Denomination) -> String {
        self.display_in(denom).show_denomination().to_string()
    }

    /// Checked addition.
    ///
    /// Returns [`None`] if the sum is larger than [`Amount::MAX`].
    #[must_use]
    pub const fn checked_add(self, rhs: Amount) -> Option<Amount> {
        // No `map()` in const context.
        match self.0.checked_add(rhs.0) {
            Some(res) => Some(Amount(res)),
            None => None,
        }
    }

    /// Checked subtraction.
    ///
    /// Returns [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_sub(self, rhs: Amount) -> Option<Amount> {
        // No `map()` in const context.
        match self.0.checked_sub(rhs.0) {
            Some(res) => Some(Amount(res)),
            None => None,
        }
    }

    /// Checked multiplication.
    ///
    /// Returns [`None`] if the product is larger than [`Amount::MAX`].
    #[must_use]
    pub const fn checked_mul(self, rhs: u64) -> Option<Amount> {
        // No `map()` in const context.
        match self.0.checked_mul(rhs) {
            Some(res) => Some(Amount(res)),
            None => None,
        }
    }

    /// Checked integer division.
    ///
    /// Be aware that integer division loses the remainder if no exact division can be made.
    ///
    /// Returns [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_div(self, rhs: u64) -> Option<Amount> {
        // No `map()` in const context.
        match self.0.checked_div(rhs) {
            Some(res) => Some(Amount(res)),
            None => None,
        }
    }

    /// Checked remainder.
    ///
    /// Returns [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_rem(self, rhs: u64) -> Option<Amount> {
        // No `map()` in const context.
        match self.0.checked_rem(rhs) {
            Some(res) => Some(Amount(res)),
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
    #[deprecated(since = "TBD", note = "consider converting to u64 using `to_sat`")]
    pub fn unchecked_add(self, rhs: Amount) -> Amount { Self(self.0 + rhs.0) }

    /// Unchecked subtraction.
    ///
    /// Computes `self - rhs`.
    ///
    /// # Panics
    ///
    /// On overflow, panics in debug mode, wraps in release mode.
    #[must_use]
    #[deprecated(since = "TBD", note = "consider converting to u64 using `to_sat`")]
    pub fn unchecked_sub(self, rhs: Amount) -> Amount { Self(self.0 - rhs.0) }

    /// Converts to a signed amount.
    ///
    /// # Errors
    ///
    /// If the amount is too big.
    #[rustfmt::skip] // Moves code comments to the wrong line.
    pub fn to_signed(self) -> Result<SignedAmount, OutOfRangeError> {
        if self.to_sat() > SignedAmount::MAX.to_sat() as u64 { // Cast ok, signed max is positive and fits in u64.
            Err(OutOfRangeError::too_big(true))
        } else {
            Ok(SignedAmount::from_sat(self.to_sat() as i64)) // Cast ok, checked not too big above.
        }
    }
}

impl default::Default for Amount {
    fn default() -> Self { Amount::ZERO }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Amount({} SAT)", self.to_sat())
    }
}

// No one should depend on a binding contract for Display for this type.
// Just using Bitcoin denominated string.
impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.display_in(Denomination::Bitcoin).show_denomination(), f)
    }
}

impl ops::Add for Amount {
    type Output = Amount;

    fn add(self, rhs: Amount) -> Self::Output {
        self.checked_add(rhs).expect("Amount addition error")
    }
}
crate::internal_macros::impl_add_for_references!(Amount);
crate::internal_macros::impl_add_assign!(Amount);

impl ops::Sub for Amount {
    type Output = Amount;

    fn sub(self, rhs: Amount) -> Self::Output {
        self.checked_sub(rhs).expect("Amount subtraction error")
    }
}
crate::internal_macros::impl_sub_for_references!(Amount);
crate::internal_macros::impl_sub_assign!(Amount);

impl ops::Rem<u64> for Amount {
    type Output = Amount;

    fn rem(self, modulus: u64) -> Self {
        self.checked_rem(modulus).expect("Amount remainder error")
    }
}

impl ops::RemAssign<u64> for Amount {
    fn rem_assign(&mut self, modulus: u64) { *self = *self % modulus }
}

impl ops::Mul<u64> for Amount {
    type Output = Amount;

    fn mul(self, rhs: u64) -> Self::Output {
        self.checked_mul(rhs).expect("Amount multiplication error")
    }
}

impl ops::MulAssign<u64> for Amount {
    fn mul_assign(&mut self, rhs: u64) { *self = *self * rhs }
}

impl ops::Div<u64> for Amount {
    type Output = Amount;

    fn div(self, rhs: u64) -> Self::Output { self.checked_div(rhs).expect("Amount division error") }
}

impl ops::DivAssign<u64> for Amount {
    fn div_assign(&mut self, rhs: u64) { *self = *self / rhs }
}

impl FromStr for Amount {
    type Err = ParseError;

    /// Parses a string slice where the slice includes a denomination.
    ///
    /// If the returned value would be zero or negative zero, then no denomination is required.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let result = Self::from_str_with_denomination(s);

        match result {
            Err(ParseError(ParseErrorInner::MissingDenomination(_))) => {
                let d = Self::from_str_in(s, Denomination::Satoshi);

                if d == Ok(Self::ZERO) {
                    Ok(Self::ZERO)
                } else {
                    result
                }
            }
            _ => result,
        }
    }
}

impl TryFrom<SignedAmount> for Amount {
    type Error = OutOfRangeError;

    fn try_from(value: SignedAmount) -> Result<Self, Self::Error> { value.to_unsigned() }
}

impl core::iter::Sum for Amount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let sats: u64 = iter.map(|amt| amt.0).sum();
        Self::from_sat(sats)
    }
}

impl<'a> core::iter::Sum<&'a Amount> for Amount {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Amount>,
    {
        let sats: u64 = iter.map(|amt| amt.0).sum();
        Self::from_sat(sats)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Amount {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let a = u64::arbitrary(u)?;
        Ok(Self(a))
    }
}
