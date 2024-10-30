// SPDX-License-Identifier: CC0-1.0

//! Bitcoin amounts.
//!
//! This module mainly introduces the [`Amount`] and [`SignedAmount`] types.
//! We refer to the documentation on the types for more information.

pub mod error;

#[cfg(test)]
mod tests;
#[cfg(kani)]
mod verification;

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};
use core::cmp::Ordering;
use core::str::FromStr;
use core::{default, fmt, ops};

#[cfg(feature = "serde")]
use ::serde::{Deserialize, Serialize};
#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

use self::error::MissingDigitsKind;
#[cfg(feature = "alloc")]
use crate::{FeeRate, Weight};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::error::{
    InputTooLargeError, InvalidCharacterError, MissingDenominationError, MissingDigitsError,
    OutOfRangeError, ParseAmountError, ParseDenominationError, ParseError,
    PossiblyConfusingDenominationError, TooPreciseError, UnknownDenominationError,
};

/// A set of denominations in which amounts can be expressed.
///
/// # Accepted Denominations
///
/// All upper or lower case, excluding SI prefix (c, m, u) which must be lower case.
/// - Singular: BTC, cBTC, mBTC, uBTC
/// - Plural or singular: sat, satoshi, bit
///
/// # Note
///
/// Due to ambiguity between mega and milli we prohibit usage of leading capital 'M'.  It is
/// more important to protect users from incorrectly using a capital M to mean milli than to
/// allow Megabitcoin which is not a realistic denomination, and Megasatoshi which is
/// equivalent to cBTC which is allowed.
///
/// # Examples
///
/// ```
/// # use bitcoin_units::Amount;
///
/// assert_eq!("1 BTC".parse::<Amount>().unwrap(), Amount::from_sat(100_000_000));
/// assert_eq!("1 cBTC".parse::<Amount>().unwrap(), Amount::from_sat(1_000_000));
/// assert_eq!("1 mBTC".parse::<Amount>().unwrap(), Amount::from_sat(100_000));
/// assert_eq!("1 uBTC".parse::<Amount>().unwrap(), Amount::from_sat(100));
/// assert_eq!("1 bit".parse::<Amount>().unwrap(), Amount::from_sat(100));
/// assert_eq!("1 sat".parse::<Amount>().unwrap(), Amount::from_sat(1));
/// ```
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Denomination {
    /// BTC
    Bitcoin,
    /// cBTC
    CentiBitcoin,
    /// mBTC
    MilliBitcoin,
    /// uBTC
    MicroBitcoin,
    /// bits
    Bit,
    /// satoshi
    Satoshi,
}

impl Denomination {
    /// Convenience alias for `Denomination::Bitcoin`.
    pub const BTC: Self = Denomination::Bitcoin;

    /// Convenience alias for `Denomination::Satoshi`.
    pub const SAT: Self = Denomination::Satoshi;

    /// The number of decimal places more than a satoshi.
    fn precision(self) -> i8 {
        match self {
            Denomination::Bitcoin => -8,
            Denomination::CentiBitcoin => -6,
            Denomination::MilliBitcoin => -5,
            Denomination::MicroBitcoin => -2,
            Denomination::Bit => -2,
            Denomination::Satoshi => 0,
        }
    }

    /// Returns a string representation of this denomination.
    fn as_str(self) -> &'static str {
        match self {
            Denomination::Bitcoin => "BTC",
            Denomination::CentiBitcoin => "cBTC",
            Denomination::MilliBitcoin => "mBTC",
            Denomination::MicroBitcoin => "uBTC",
            Denomination::Bit => "bits",
            Denomination::Satoshi => "satoshi",
        }
    }

    /// The different `str` forms of denominations that are recognized.
    fn forms(s: &str) -> Option<Self> {
        match s {
            "BTC" | "btc" => Some(Denomination::Bitcoin),
            "cBTC" | "cbtc" => Some(Denomination::CentiBitcoin),
            "mBTC" | "mbtc" => Some(Denomination::MilliBitcoin),
            "uBTC" | "ubtc" => Some(Denomination::MicroBitcoin),
            "bit" | "bits" | "BIT" | "BITS" => Some(Denomination::Bit),
            "SATOSHI" | "satoshi" | "SATOSHIS" | "satoshis" | "SAT" | "sat" | "SATS" | "sats" =>
                Some(Denomination::Satoshi),
            _ => None,
        }
    }
}

/// These form are ambigous and could have many meanings.  For example, M could denote Mega or Milli.
/// If any of these forms are used, an error type PossiblyConfusingDenomination is returned.
const CONFUSING_FORMS: [&str; 6] = ["MBTC", "Mbtc", "CBTC", "Cbtc", "UBTC", "Ubtc"];

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str(self.as_str()) }
}

impl FromStr for Denomination {
    type Err = ParseDenominationError;

    /// Converts from a `str` to a `Denomination`.
    ///
    /// # Errors
    ///
    /// - If the denomination begins with a capital `M` a [`PossiblyConfusingDenominationError`] is
    ///   returned.
    ///
    /// - If an unknown denomination is used, an [`UnknownDenominationError`] is returned.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::ParseDenominationError::*;

        if CONFUSING_FORMS.contains(&s) {
            return Err(PossiblyConfusing(PossiblyConfusingDenominationError(s.into())));
        };

        let form = self::Denomination::forms(s);

        form.ok_or_else(|| Unknown(UnknownDenominationError(s.into())))
    }
}

/// Returns `Some(position)` if the precision is not supported.
///
/// The position indicates the first digit that is too precise.
fn is_too_precise(s: &str, precision: usize) -> Option<usize> {
    match s.find('.') {
        Some(pos) if precision >= pos => Some(0),
        Some(pos) => s[..pos]
            .char_indices()
            .rev()
            .take(precision)
            .find(|(_, d)| *d != '0')
            .map(|(i, _)| i)
            .or_else(|| {
                s[(pos + 1)..].char_indices().find(|(_, d)| *d != '0').map(|(i, _)| i + pos + 1)
            }),
        None if precision >= s.len() => Some(0),
        None => s.char_indices().rev().take(precision).find(|(_, d)| *d != '0').map(|(i, _)| i),
    }
}

const INPUT_STRING_LEN_LIMIT: usize = 50;

/// Parses a decimal string in the given denomination into a satoshi value and a
/// [`bool`] indicator for a negative amount.
fn parse_signed_to_satoshi(
    mut s: &str,
    denom: Denomination,
) -> Result<(bool, u64), InnerParseError> {
    if s.is_empty() {
        return Err(InnerParseError::MissingDigits(MissingDigitsError {
            kind: MissingDigitsKind::Empty,
        }));
    }
    if s.len() > INPUT_STRING_LEN_LIMIT {
        return Err(InnerParseError::InputTooLarge(s.len()));
    }

    let is_negative = s.starts_with('-');
    if is_negative {
        if s.len() == 1 {
            return Err(InnerParseError::MissingDigits(MissingDigitsError {
                kind: MissingDigitsKind::OnlyMinusSign,
            }));
        }
        s = &s[1..];
    }

    let max_decimals = {
        // The difference in precision between native (satoshi)
        // and desired denomination.
        let precision_diff = -denom.precision();
        if precision_diff <= 0 {
            // If precision diff is negative, this means we are parsing
            // into a less precise amount. That is not allowed unless
            // there are no decimals and the last digits are zeroes as
            // many as the difference in precision.
            let last_n = precision_diff.unsigned_abs().into();
            if let Some(position) = is_too_precise(s, last_n) {
                match s.parse::<i64>() {
                    Ok(0) => return Ok((is_negative, 0)),
                    _ =>
                        return Err(InnerParseError::TooPrecise(TooPreciseError {
                            position: position + is_negative as usize,
                        })),
                }
            }
            s = &s[0..s.find('.').unwrap_or(s.len()) - last_n];
            0
        } else {
            precision_diff
        }
    };

    let mut decimals = None;
    let mut value: u64 = 0; // as satoshis
    for (i, c) in s.char_indices() {
        match c {
            '0'..='9' => {
                // Do `value = 10 * value + digit`, catching overflows.
                match 10_u64.checked_mul(value) {
                    None => return Err(InnerParseError::Overflow { is_negative }),
                    Some(val) => match val.checked_add((c as u8 - b'0') as u64) {
                        None => return Err(InnerParseError::Overflow { is_negative }),
                        Some(val) => value = val,
                    },
                }
                // Increment the decimal digit counter if past decimal.
                decimals = match decimals {
                    None => None,
                    Some(d) if d < max_decimals => Some(d + 1),
                    _ =>
                        return Err(InnerParseError::TooPrecise(TooPreciseError {
                            position: i + is_negative as usize,
                        })),
                };
            }
            '.' => match decimals {
                None if max_decimals <= 0 => break,
                None => decimals = Some(0),
                // Double decimal dot.
                _ =>
                    return Err(InnerParseError::InvalidCharacter(InvalidCharacterError {
                        invalid_char: '.',
                        position: i + is_negative as usize,
                    })),
            },
            c =>
                return Err(InnerParseError::InvalidCharacter(InvalidCharacterError {
                    invalid_char: c,
                    position: i + is_negative as usize,
                })),
        }
    }

    // Decimally shift left by `max_decimals - decimals`.
    let scale_factor = max_decimals - decimals.unwrap_or(0);
    for _ in 0..scale_factor {
        value = match 10_u64.checked_mul(value) {
            Some(v) => v,
            None => return Err(InnerParseError::Overflow { is_negative }),
        };
    }

    Ok((is_negative, value))
}

enum InnerParseError {
    Overflow { is_negative: bool },
    TooPrecise(TooPreciseError),
    MissingDigits(MissingDigitsError),
    InputTooLarge(usize),
    InvalidCharacter(InvalidCharacterError),
}

internals::impl_from_infallible!(InnerParseError);

impl InnerParseError {
    fn convert(self, is_signed: bool) -> ParseAmountError {
        match self {
            Self::Overflow { is_negative } =>
                OutOfRangeError { is_signed, is_greater_than_max: !is_negative }.into(),
            Self::TooPrecise(error) => ParseAmountError::TooPrecise(error),
            Self::MissingDigits(error) => ParseAmountError::MissingDigits(error),
            Self::InputTooLarge(len) => ParseAmountError::InputTooLarge(InputTooLargeError { len }),
            Self::InvalidCharacter(error) => ParseAmountError::InvalidCharacter(error),
        }
    }
}

fn split_amount_and_denomination(s: &str) -> Result<(&str, Denomination), ParseError> {
    let (i, j) = if let Some(i) = s.find(' ') {
        (i, i + 1)
    } else {
        let i = s
            .find(|c: char| c.is_alphabetic())
            .ok_or(ParseError::MissingDenomination(MissingDenominationError))?;
        (i, i)
    };
    Ok((&s[..i], s[j..].parse()?))
}

/// Options given by `fmt::Formatter`
struct FormatOptions {
    fill: char,
    align: Option<fmt::Alignment>,
    width: Option<usize>,
    precision: Option<usize>,
    sign_plus: bool,
    sign_aware_zero_pad: bool,
}

impl FormatOptions {
    fn from_formatter(f: &fmt::Formatter) -> Self {
        FormatOptions {
            fill: f.fill(),
            align: f.align(),
            width: f.width(),
            precision: f.precision(),
            sign_plus: f.sign_plus(),
            sign_aware_zero_pad: f.sign_aware_zero_pad(),
        }
    }
}

impl Default for FormatOptions {
    fn default() -> Self {
        FormatOptions {
            fill: ' ',
            align: None,
            width: None,
            precision: None,
            sign_plus: false,
            sign_aware_zero_pad: false,
        }
    }
}

fn dec_width(mut num: u64) -> usize {
    let mut width = 1;
    loop {
        num /= 10;
        if num == 0 {
            break;
        }
        width += 1;
    }
    width
}

fn repeat_char(f: &mut dyn fmt::Write, c: char, count: usize) -> fmt::Result {
    for _ in 0..count {
        f.write_char(c)?;
    }
    Ok(())
}

/// Format the given satoshi amount in the given denomination.
fn fmt_satoshi_in(
    mut satoshi: u64,
    negative: bool,
    f: &mut dyn fmt::Write,
    denom: Denomination,
    show_denom: bool,
    options: FormatOptions,
) -> fmt::Result {
    let precision = denom.precision();
    // First we normalize the number:
    // {num_before_decimal_point}{:0exp}{"." if nb_decimals > 0}{:0nb_decimals}{num_after_decimal_point}{:0trailing_decimal_zeros}
    let mut num_after_decimal_point = 0;
    let mut norm_nb_decimals = 0;
    let mut num_before_decimal_point = satoshi;
    let trailing_decimal_zeros;
    let mut exp = 0;
    match precision.cmp(&0) {
        // We add the number of zeroes to the end
        Ordering::Greater => {
            if satoshi > 0 {
                exp = precision as usize;
            }
            trailing_decimal_zeros = options.precision.unwrap_or(0);
        }
        Ordering::Less => {
            let precision = precision.unsigned_abs();
            // round the number if needed
            // rather than fiddling with chars, we just modify satoshi and let the simpler algorithm take over.
            if let Some(format_precision) = options.precision {
                if usize::from(precision) > format_precision {
                    // precision is u8 so in this branch options.precision() < 255 which fits in u32
                    let rounding_divisor =
                        10u64.pow(u32::from(precision) - format_precision as u32);
                    let remainder = satoshi % rounding_divisor;
                    satoshi -= remainder;
                    if remainder / (rounding_divisor / 10) >= 5 {
                        satoshi += rounding_divisor;
                    }
                }
            }
            let divisor = 10u64.pow(precision.into());
            num_before_decimal_point = satoshi / divisor;
            num_after_decimal_point = satoshi % divisor;
            // normalize by stripping trailing zeros
            if num_after_decimal_point == 0 {
                norm_nb_decimals = 0;
            } else {
                norm_nb_decimals = usize::from(precision);
                while num_after_decimal_point % 10 == 0 {
                    norm_nb_decimals -= 1;
                    num_after_decimal_point /= 10
                }
            }
            // compute requested precision
            let opt_precision = options.precision.unwrap_or(0);
            trailing_decimal_zeros = opt_precision.saturating_sub(norm_nb_decimals);
        }
        Ordering::Equal => trailing_decimal_zeros = options.precision.unwrap_or(0),
    }
    let total_decimals = norm_nb_decimals + trailing_decimal_zeros;
    // Compute expected width of the number
    let mut num_width = if total_decimals > 0 {
        // 1 for decimal point
        1 + total_decimals
    } else {
        0
    };
    num_width += dec_width(num_before_decimal_point) + exp;
    if options.sign_plus || negative {
        num_width += 1;
    }

    if show_denom {
        // + 1 for space
        num_width += denom.as_str().len() + 1;
    }

    let width = options.width.unwrap_or(0);
    let align = options.align.unwrap_or(fmt::Alignment::Right);
    let (left_pad, pad_right) = match (num_width < width, options.sign_aware_zero_pad, align) {
        (false, _, _) => (0, 0),
        // Alignment is always right (ignored) when zero-padding
        (true, true, _) | (true, false, fmt::Alignment::Right) => (width - num_width, 0),
        (true, false, fmt::Alignment::Left) => (0, width - num_width),
        // If the required padding is odd it needs to be skewed to the left
        (true, false, fmt::Alignment::Center) =>
            ((width - num_width) / 2, (width - num_width + 1) / 2),
    };

    if !options.sign_aware_zero_pad {
        repeat_char(f, options.fill, left_pad)?;
    }

    if negative {
        write!(f, "-")?;
    } else if options.sign_plus {
        write!(f, "+")?;
    }

    if options.sign_aware_zero_pad {
        repeat_char(f, '0', left_pad)?;
    }

    write!(f, "{}", num_before_decimal_point)?;

    repeat_char(f, '0', exp)?;

    if total_decimals > 0 {
        write!(f, ".")?;
    }
    if norm_nb_decimals > 0 {
        write!(f, "{:0width$}", num_after_decimal_point, width = norm_nb_decimals)?;
    }
    repeat_char(f, '0', trailing_decimal_zeros)?;

    if show_denom {
        write!(f, " {}", denom.as_str())?;
    }

    repeat_char(f, options.fill, pad_right)?;
    Ok(())
}

/// An amount.
///
/// The [`Amount`] type can be used to express Bitcoin amounts that support
/// arithmetic and conversion to various denominations.
///
///
/// Warning!
///
/// This type implements several arithmetic operations from [`core::ops`].
/// To prevent errors due to overflow or underflow when using these operations,
/// it is advised to instead use the checked arithmetic methods whose names
/// start with `checked_`.  The operations from [`core::ops`] that [`Amount`]
/// implements will panic when overflow or underflow occurs.  Also note that
/// since the internal representation of amounts is unsigned, subtracting below
/// zero is considered an underflow and will cause a panic if you're not using
/// the checked arithmetic methods.
///
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Amount(u64);

impl Amount {
    /// The zero amount.
    pub const ZERO: Amount = Amount(0);
    /// Exactly one satoshi.
    pub const ONE_SAT: Amount = Amount(1);
    /// Exactly one bitcoin.
    pub const ONE_BTC: Amount = Self::from_int_btc(1);
    /// The maximum value allowed as an amount. Useful for sanity checking.
    pub const MAX_MONEY: Amount = Self::from_int_btc(21_000_000);
    /// The minimum value of an amount.
    pub const MIN: Amount = Amount::ZERO;
    /// The maximum value of an amount.
    pub const MAX: Amount = Amount(u64::MAX);
    /// The number of bytes that an amount contributes to the size of a transaction.
    pub const SIZE: usize = 8; // Serialized length of a u64.

    /// Creates an [`Amount`] with satoshi precision and the given number of satoshis.
    pub const fn from_sat(satoshi: u64) -> Amount { Amount(satoshi) }

    /// Gets the number of satoshis in this [`Amount`].
    pub const fn to_sat(self) -> u64 { self.0 }

    /// Converts from a value expressing bitcoins to an [`Amount`].
    #[cfg(feature = "alloc")]
    pub fn from_btc(btc: f64) -> Result<Amount, ParseAmountError> {
        Amount::from_float_in(btc, Denomination::Bitcoin)
    }

    /// Converts from a value expressing integer values of bitcoins to an [`Amount`]
    /// in const context.
    ///
    /// # Panics
    ///
    /// The function panics if the argument multiplied by the number of sats
    /// per bitcoin overflows a u64 type.
    pub const fn from_int_btc(btc: u64) -> Amount {
        match btc.checked_mul(100_000_000) {
            Some(amount) => Amount::from_sat(amount),
            None => panic!("checked_mul overflowed"),
        }
    }

    /// Parses a decimal string as a value in the given denomination.
    ///
    /// Note: This only parses the value string.  If you want to parse a value
    /// with denomination, use [`FromStr`].
    pub fn from_str_in(s: &str, denom: Denomination) -> Result<Amount, ParseAmountError> {
        let (negative, satoshi) =
            parse_signed_to_satoshi(s, denom).map_err(|error| error.convert(false))?;
        if negative {
            return Err(ParseAmountError::OutOfRange(OutOfRangeError::negative()));
        }
        Ok(Amount::from_sat(satoshi))
    }

    /// Parses amounts with denomination suffix like they are produced with
    /// [`Self::to_string_with_denomination`] or with [`fmt::Display`].
    /// If you want to parse only the amount without the denomination,
    /// use [`Self::from_str_in`].
    pub fn from_str_with_denomination(s: &str) -> Result<Amount, ParseError> {
        let (amt, denom) = split_amount_and_denomination(s)?;
        Amount::from_str_in(amt, denom).map_err(Into::into)
    }

    /// Expresses this [`Amount`] as a floating-point value in the given denomination.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    #[cfg(feature = "alloc")]
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

    /// Converts this [`Amount`] in floating-point notation with a given
    /// denomination.
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
        Amount::from_str_in(&value.to_string(), denom)
    }

    /// Creates an object that implements [`fmt::Display`] using specified denomination.
    pub fn display_in(self, denomination: Denomination) -> Display {
        Display {
            sats_abs: self.to_sat(),
            is_negative: false,
            style: DisplayStyle::FixedDenomination { denomination, show_denomination: false },
        }
    }

    /// Creates an object that implements [`fmt::Display`] dynamically selecting denomination.
    ///
    /// This will use BTC for values greater than or equal to 1 BTC and satoshis otherwise. To
    /// avoid confusion the denomination is always shown.
    pub fn display_dynamic(self) -> Display {
        Display {
            sats_abs: self.to_sat(),
            is_negative: false,
            style: DisplayStyle::DynamicDenomination,
        }
    }

    /// Formats the value of this [`Amount`] in the given denomination.
    ///
    /// Does not include the denomination.
    #[rustfmt::skip]
    #[deprecated(since = "TBD", note = "use `display_in()` instead")]
    pub fn fmt_value_in(self, f: &mut dyn fmt::Write, denom: Denomination) -> fmt::Result {
        fmt_satoshi_in(self.to_sat(), false, f, denom, false, FormatOptions::default())
    }

    /// Returns a formatted string of this [`Amount`] in the given denomination.
    ///
    /// Does not include the denomination.
    #[cfg(feature = "alloc")]
    pub fn to_string_in(self, denom: Denomination) -> String { self.display_in(denom).to_string() }

    /// Returns a formatted string of this [`Amount`] in the given denomination,
    /// suffixed with the abbreviation for the denomination.
    #[cfg(feature = "alloc")]
    pub fn to_string_with_denomination(self, denom: Denomination) -> String {
        self.display_in(denom).show_denomination().to_string()
    }

    // Some arithmetic that doesn't fit in [`core::ops`] traits.

    /// Checked addition.
    ///
    /// Returns [`None`] if overflow occurred.
    pub fn checked_add(self, rhs: Amount) -> Option<Amount> {
        self.0.checked_add(rhs.0).map(Amount)
    }

    /// Checked subtraction.
    ///
    /// Returns [`None`] if overflow occurred.
    pub fn checked_sub(self, rhs: Amount) -> Option<Amount> {
        self.0.checked_sub(rhs.0).map(Amount)
    }

    /// Checked multiplication.
    ///
    /// Returns [`None`] if overflow occurred.
    pub fn checked_mul(self, rhs: u64) -> Option<Amount> { self.0.checked_mul(rhs).map(Amount) }

    /// Checked integer division.
    ///
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made.
    /// Returns [`None`] if overflow occurred.
    pub fn checked_div(self, rhs: u64) -> Option<Amount> { self.0.checked_div(rhs).map(Amount) }

    /// Checked weight division.
    ///
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made.  This method rounds up ensuring the transaction fee-rate is
    /// sufficient.  If you wish to round-down, use the unchecked version instead.
    ///
    /// [`None`] is returned if an overflow occurred.
    #[cfg(feature = "alloc")]
    pub fn checked_div_by_weight(self, rhs: Weight) -> Option<FeeRate> {
        let sats = self.0.checked_mul(1000)?;
        let wu = rhs.to_wu();

        let fee_rate = sats.checked_add(wu.checked_sub(1)?)?.checked_div(wu)?;
        Some(FeeRate::from_sat_per_kwu(fee_rate))
    }

    /// Checked remainder.
    ///
    /// Returns [`None`] if overflow occurred.
    pub fn checked_rem(self, rhs: u64) -> Option<Amount> { self.0.checked_rem(rhs).map(Amount) }

    /// Unchecked addition.
    ///
    /// Computes `self + rhs`.
    ///
    /// # Panics
    ///
    /// On overflow, panics in debug mode, wraps in release mode.
    pub fn unchecked_add(self, rhs: Amount) -> Amount { Self(self.0 + rhs.0) }

    /// Unchecked subtraction.
    ///
    /// Computes `self - rhs`.
    ///
    /// # Panics
    ///
    /// On overflow, panics in debug mode, wraps in release mode.
    pub fn unchecked_sub(self, rhs: Amount) -> Amount { Self(self.0 - rhs.0) }

    /// Converts to a signed amount.
    pub fn to_signed(self) -> Result<SignedAmount, OutOfRangeError> {
        if self.to_sat() > SignedAmount::MAX.to_sat() as u64 {
            Err(OutOfRangeError::too_big(true))
        } else {
            Ok(SignedAmount::from_sat(self.to_sat() as i64))
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Amount {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let a = u64::arbitrary(u)?;
        Ok(Amount(a))
    }
}

impl default::Default for Amount {
    fn default() -> Self { Amount::ZERO }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{} SAT", self.to_sat()) }
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

impl ops::AddAssign for Amount {
    fn add_assign(&mut self, other: Amount) { *self = *self + other }
}

impl ops::Sub for Amount {
    type Output = Amount;

    fn sub(self, rhs: Amount) -> Self::Output {
        self.checked_sub(rhs).expect("Amount subtraction error")
    }
}

impl ops::SubAssign for Amount {
    fn sub_assign(&mut self, other: Amount) { *self = *self - other }
}

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
    /// If the string slice is zero, then no denomination is required.
    ///
    /// # Returns
    ///
    /// `Ok(Amount)` if the string amount and denomination parse successfully,
    /// otherwise, return `Err(ParseError)`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let result = Amount::from_str_with_denomination(s);

        match result {
            Err(ParseError::MissingDenomination(_)) => {
                let d = Amount::from_str_in(s, Denomination::Satoshi);

                if d == Ok(Amount::ZERO) {
                    Ok(Amount::ZERO)
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
        Amount::from_sat(sats)
    }
}

/// A helper/builder that displays amount with specified settings.
///
/// This provides richer interface than [`fmt::Formatter`]:
///
/// * Ability to select denomination
/// * Show or hide denomination
/// * Dynamically-selected denomination - show in sats if less than 1 BTC.
///
/// However, this can still be combined with [`fmt::Formatter`] options to precisely control zeros,
/// padding, alignment... The formatting works like floats from `core` but note that precision will
/// **never** be lossy - that means no rounding.
///
/// Note: This implementation is currently **unstable**. The only thing that we can promise is that
/// unless the precision is changed, this will display an accurate, human-readable number, and the
/// default serialization (one with unmodified [`fmt::Formatter`] options) will round-trip with [`FromStr`]
///
/// See [`Amount::display_in`] and [`Amount::display_dynamic`] on how to construct this.
#[derive(Debug, Clone)]
pub struct Display {
    /// Absolute value of satoshis to display (sign is below)
    sats_abs: u64,
    /// The sign
    is_negative: bool,
    /// How to display the value
    style: DisplayStyle,
}

impl Display {
    /// Makes subsequent calls to `Display::fmt` display denomination.
    pub fn show_denomination(mut self) -> Self {
        match &mut self.style {
            DisplayStyle::FixedDenomination { show_denomination, .. } => *show_denomination = true,
            // No-op because dynamic denomination is always shown
            DisplayStyle::DynamicDenomination => (),
        }
        self
    }
}

impl fmt::Display for Display {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let format_options = FormatOptions::from_formatter(f);
        match &self.style {
            DisplayStyle::FixedDenomination { show_denomination, denomination } => {
                fmt_satoshi_in(self.sats_abs, self.is_negative, f, *denomination, *show_denomination, format_options)
            },
            DisplayStyle::DynamicDenomination if self.sats_abs >= Amount::ONE_BTC.to_sat() => {
                fmt_satoshi_in(self.sats_abs, self.is_negative, f, Denomination::Bitcoin, true, format_options)
            },
            DisplayStyle::DynamicDenomination => {
                fmt_satoshi_in(self.sats_abs, self.is_negative, f, Denomination::Satoshi, true, format_options)
            },
        }
    }
}

#[derive(Clone, Debug)]
enum DisplayStyle {
    FixedDenomination { denomination: Denomination, show_denomination: bool },
    DynamicDenomination,
}

/// A signed amount.
///
/// The [`SignedAmount`] type can be used to express Bitcoin amounts that support
/// arithmetic and conversion to various denominations.
///
///
/// Warning!
///
/// This type implements several arithmetic operations from [`core::ops`].
/// To prevent errors due to overflow or underflow when using these operations,
/// it is advised to instead use the checked arithmetic methods whose names
/// start with `checked_`.  The operations from [`core::ops`] that [`Amount`]
/// implements will panic when overflow or underflow occurs.
///
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
    pub const MIN: SignedAmount = SignedAmount(i64::MIN);
    /// The maximum value of an amount.
    pub const MAX: SignedAmount = SignedAmount(i64::MAX);

    /// Create an [`SignedAmount`] with satoshi precision and the given number of satoshis.
    pub const fn from_sat(satoshi: i64) -> SignedAmount { SignedAmount(satoshi) }

    /// Gets the number of satoshis in this [`SignedAmount`].
    pub const fn to_sat(self) -> i64 { self.0 }

    /// Convert from a value expressing bitcoins to an [`SignedAmount`].
    #[cfg(feature = "alloc")]
    pub fn from_btc(btc: f64) -> Result<SignedAmount, ParseAmountError> {
        SignedAmount::from_float_in(btc, Denomination::Bitcoin)
    }

    /// Parse a decimal string as a value in the given denomination.
    ///
    /// Note: This only parses the value string.  If you want to parse a value
    /// with denomination, use [`FromStr`].
    pub fn from_str_in(s: &str, denom: Denomination) -> Result<SignedAmount, ParseAmountError> {
        match parse_signed_to_satoshi(s, denom).map_err(|error| error.convert(true))? {
            // (negative, amount)
            (false, sat) if sat > i64::MAX as u64 =>
                Err(ParseAmountError::OutOfRange(OutOfRangeError::too_big(true))),
            (false, sat) => Ok(SignedAmount(sat as i64)),
            (true, sat) if sat == i64::MIN.unsigned_abs() => Ok(SignedAmount(i64::MIN)),
            (true, sat) if sat > i64::MIN.unsigned_abs() =>
                Err(ParseAmountError::OutOfRange(OutOfRangeError::too_small())),
            (true, sat) => Ok(SignedAmount(-(sat as i64))),
        }
    }

    /// Parses amounts with denomination suffix like they are produced with
    /// [`Self::to_string_with_denomination`] or with [`fmt::Display`].
    /// If you want to parse only the amount without the denomination,
    /// use [`Self::from_str_in`].
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
    /// Equivalent to `to_float_in(Denomination::Bitcoin)`.
    ///
    /// Please be aware of the risk of using floating-point numbers.
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

    /// Create an object that implements [`fmt::Display`] using specified denomination.
    pub fn display_in(self, denomination: Denomination) -> Display {
        Display {
            sats_abs: self.unsigned_abs().to_sat(),
            is_negative: self.is_negative(),
            style: DisplayStyle::FixedDenomination { denomination, show_denomination: false },
        }
    }

    /// Create an object that implements [`fmt::Display`] dynamically selecting denomination.
    ///
    /// This will use BTC for values greater than or equal to 1 BTC and satoshis otherwise. To
    /// avoid confusion the denomination is always shown.
    pub fn display_dynamic(self) -> Display {
        Display {
            sats_abs: self.unsigned_abs().to_sat(),
            is_negative: self.is_negative(),
            style: DisplayStyle::DynamicDenomination,
        }
    }

    /// Format the value of this [`SignedAmount`] in the given denomination.
    ///
    /// Does not include the denomination.
    #[rustfmt::skip]
    #[deprecated(since = "TBD", note = "use `display_in()` instead")]
    pub fn fmt_value_in(self, f: &mut dyn fmt::Write, denom: Denomination) -> fmt::Result {
        fmt_satoshi_in(self.unsigned_abs().to_sat(), self.is_negative(), f, denom, false, FormatOptions::default())
    }

    /// Get a string number of this [`SignedAmount`] in the given denomination.
    ///
    /// Does not include the denomination.
    #[cfg(feature = "alloc")]
    pub fn to_string_in(self, denom: Denomination) -> String { self.display_in(denom).to_string() }

    /// Get a formatted string of this [`SignedAmount`] in the given denomination,
    /// suffixed with the abbreviation for the denomination.
    #[cfg(feature = "alloc")]
    pub fn to_string_with_denomination(self, denom: Denomination) -> String {
        self.display_in(denom).show_denomination().to_string()
    }

    // Some arithmetic that doesn't fit in [`core::ops`] traits.

    /// Get the absolute value of this [`SignedAmount`].
    pub fn abs(self) -> SignedAmount { SignedAmount(self.0.abs()) }

    /// Get the absolute value of this [`SignedAmount`] returning [`Amount`].
    pub fn unsigned_abs(self) -> Amount { Amount(self.0.unsigned_abs()) }

    /// Returns a number representing sign of this [`SignedAmount`].
    ///
    /// - `0` if the amount is zero
    /// - `1` if the amount is positive
    /// - `-1` if the amount is negative
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
    pub fn checked_abs(self) -> Option<SignedAmount> { self.0.checked_abs().map(SignedAmount) }

    /// Checked addition.
    ///
    /// Returns [`None`] if overflow occurred.
    pub fn checked_add(self, rhs: SignedAmount) -> Option<SignedAmount> {
        self.0.checked_add(rhs.0).map(SignedAmount)
    }

    /// Checked subtraction.
    ///
    /// Returns [`None`] if overflow occurred.
    pub fn checked_sub(self, rhs: SignedAmount) -> Option<SignedAmount> {
        self.0.checked_sub(rhs.0).map(SignedAmount)
    }

    /// Checked multiplication.
    ///
    /// Returns [`None`] if overflow occurred.
    pub fn checked_mul(self, rhs: i64) -> Option<SignedAmount> {
        self.0.checked_mul(rhs).map(SignedAmount)
    }

    /// Checked integer division.
    ///
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made.
    ///
    /// Returns [`None`] if overflow occurred.
    pub fn checked_div(self, rhs: i64) -> Option<SignedAmount> {
        self.0.checked_div(rhs).map(SignedAmount)
    }

    /// Checked remainder.
    ///
    /// Returns [`None`] if overflow occurred.
    pub fn checked_rem(self, rhs: i64) -> Option<SignedAmount> {
        self.0.checked_rem(rhs).map(SignedAmount)
    }

    /// Unchecked addition.
    ///
    /// Computes `self + rhs`.
    ///
    /// # Panics
    ///
    /// On overflow, panics in debug mode, wraps in release mode.
    pub fn unchecked_add(self, rhs: SignedAmount) -> SignedAmount { Self(self.0 + rhs.0) }

    /// Unchecked subtraction.
    ///
    /// Computes `self - rhs`.
    ///
    /// # Panics
    ///
    /// On overflow, panics in debug mode, wraps in release mode.
    pub fn unchecked_sub(self, rhs: SignedAmount) -> SignedAmount { Self(self.0 - rhs.0) }

    /// Subtraction that doesn't allow negative [`SignedAmount`]s.
    ///
    /// Returns [`None`] if either [`self`], `rhs` or the result is strictly negative.
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
    /// If the string slice is zero or negative zero, then no denomination is required.
    ///
    /// # Returns
    ///
    /// `Ok(Amount)` if the string amount and denomination parse successfully,
    /// otherwise, return `Err(ParseError)`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let result = SignedAmount::from_str_with_denomination(s);

        match result {
            Err(ParseError::MissingDenomination(_)) => {
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

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for SignedAmount {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let s = i64::arbitrary(u)?;
        Ok(SignedAmount(s))
    }
}

/// Calculates the sum over the iterator using checked arithmetic.
pub trait CheckedSum<R>: private::SumSeal<R> {
    /// Calculates the sum over the iterator using checked arithmetic. If an over or underflow would
    /// happen it returns [`None`].
    fn checked_sum(self) -> Option<R>;
}

impl<T> CheckedSum<Amount> for T
where
    T: Iterator<Item = Amount>,
{
    fn checked_sum(mut self) -> Option<Amount> {
        let first = Some(self.next().unwrap_or_default());

        self.fold(first, |acc, item| acc.and_then(|acc| acc.checked_add(item)))
    }
}

impl<T> CheckedSum<SignedAmount> for T
where
    T: Iterator<Item = SignedAmount>,
{
    fn checked_sum(mut self) -> Option<SignedAmount> {
        let first = Some(self.next().unwrap_or_default());

        self.fold(first, |acc, item| acc.and_then(|acc| acc.checked_add(item)))
    }
}

mod private {
    use super::{Amount, SignedAmount};

    /// Used to seal the `CheckedSum` trait
    pub trait SumSeal<A> {}

    impl<T> SumSeal<Amount> for T where T: Iterator<Item = Amount> {}
    impl<T> SumSeal<SignedAmount> for T where T: Iterator<Item = SignedAmount> {}
}

#[cfg(feature = "serde")]
pub mod serde {
    // methods are implementation of a standardized serde-specific signature
    #![allow(missing_docs)]

    //! This module adds serde serialization and deserialization support for Amounts.
    //!
    //! Since there is not a default way to serialize and deserialize Amounts, multiple
    //! ways are supported and it's up to the user to decide which serialiation to use.
    //! The provided modules can be used as follows:
    //!
    //! ```rust,ignore
    //! use serde::{Serialize, Deserialize};
    //! use bitcoin_units::Amount;
    //!
    //! #[derive(Serialize, Deserialize)]
    //! pub struct HasAmount {
    //!     #[serde(with = "bitcoin_units::amount::serde::as_btc")]
    //!     pub amount: Amount,
    //! }
    //! ```

    use core::fmt;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[cfg(feature = "alloc")]
    use super::Denomination;
    use super::{Amount, ParseAmountError, SignedAmount};

    /// This trait is used only to avoid code duplication and naming collisions
    /// of the different serde serialization crates.
    pub trait SerdeAmount: Copy + Sized {
        fn ser_sat<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error>;
        fn des_sat<'d, D: Deserializer<'d>>(d: D, _: private::Token) -> Result<Self, D::Error>;
        #[cfg(feature = "alloc")]
        fn ser_btc<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error>;
        #[cfg(feature = "alloc")]
        fn des_btc<'d, D: Deserializer<'d>>(d: D, _: private::Token) -> Result<Self, D::Error>;
    }

    mod private {
        /// Controls access to the trait methods.
        pub struct Token;
    }

    /// This trait is only for internal Amount type serialization/deserialization
    pub trait SerdeAmountForOpt: Copy + Sized + SerdeAmount {
        fn type_prefix(_: private::Token) -> &'static str;
        fn ser_sat_opt<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error>;
        #[cfg(feature = "alloc")]
        fn ser_btc_opt<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error>;
    }

    struct DisplayFullError(ParseAmountError);

    #[cfg(feature = "std")]
    impl fmt::Display for DisplayFullError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            use std::error::Error;

            fmt::Display::fmt(&self.0, f)?;
            let mut source_opt = self.0.source();
            while let Some(source) = source_opt {
                write!(f, ": {}", source)?;
                source_opt = source.source();
            }
            Ok(())
        }
    }

    #[cfg(not(feature = "std"))]
    impl fmt::Display for DisplayFullError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
    }

    impl SerdeAmount for Amount {
        fn ser_sat<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error> {
            u64::serialize(&self.to_sat(), s)
        }
        fn des_sat<'d, D: Deserializer<'d>>(d: D, _: private::Token) -> Result<Self, D::Error> {
            Ok(Amount::from_sat(u64::deserialize(d)?))
        }
        #[cfg(feature = "alloc")]
        fn ser_btc<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error> {
            f64::serialize(&self.to_float_in(Denomination::Bitcoin), s)
        }
        #[cfg(feature = "alloc")]
        fn des_btc<'d, D: Deserializer<'d>>(d: D, _: private::Token) -> Result<Self, D::Error> {
            use serde::de::Error;
            Amount::from_btc(f64::deserialize(d)?)
                .map_err(DisplayFullError)
                .map_err(D::Error::custom)
        }
    }

    impl SerdeAmountForOpt for Amount {
        fn type_prefix(_: private::Token) -> &'static str { "u" }
        fn ser_sat_opt<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error> {
            s.serialize_some(&self.to_sat())
        }
        #[cfg(feature = "alloc")]
        fn ser_btc_opt<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error> {
            s.serialize_some(&self.to_btc())
        }
    }

    impl SerdeAmount for SignedAmount {
        fn ser_sat<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error> {
            i64::serialize(&self.to_sat(), s)
        }
        fn des_sat<'d, D: Deserializer<'d>>(d: D, _: private::Token) -> Result<Self, D::Error> {
            Ok(SignedAmount::from_sat(i64::deserialize(d)?))
        }
        #[cfg(feature = "alloc")]
        fn ser_btc<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error> {
            f64::serialize(&self.to_float_in(Denomination::Bitcoin), s)
        }
        #[cfg(feature = "alloc")]
        fn des_btc<'d, D: Deserializer<'d>>(d: D, _: private::Token) -> Result<Self, D::Error> {
            use serde::de::Error;
            SignedAmount::from_btc(f64::deserialize(d)?)
                .map_err(DisplayFullError)
                .map_err(D::Error::custom)
        }
    }

    impl SerdeAmountForOpt for SignedAmount {
        fn type_prefix(_: private::Token) -> &'static str { "i" }
        fn ser_sat_opt<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error> {
            s.serialize_some(&self.to_sat())
        }
        #[cfg(feature = "alloc")]
        fn ser_btc_opt<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error> {
            s.serialize_some(&self.to_btc())
        }
    }

    pub mod as_sat {
        //! Serialize and deserialize [`Amount`](crate::Amount) as real numbers denominated in satoshi.
        //! Use with `#[serde(with = "amount::serde::as_sat")]`.

        use serde::{Deserializer, Serializer};

        use super::private;
        use crate::amount::serde::SerdeAmount;

        pub fn serialize<A: SerdeAmount, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error> {
            a.ser_sat(s, private::Token)
        }

        pub fn deserialize<'d, A: SerdeAmount, D: Deserializer<'d>>(d: D) -> Result<A, D::Error> {
            A::des_sat(d, private::Token)
        }

        pub mod opt {
            //! Serialize and deserialize [`Option<Amount>`](crate::Amount) as real numbers denominated in satoshi.
            //! Use with `#[serde(default, with = "amount::serde::as_sat::opt")]`.

            use core::fmt;
            use core::marker::PhantomData;

            use serde::{de, Deserializer, Serializer};

            use super::private;
            use crate::amount::serde::SerdeAmountForOpt;

            pub fn serialize<A: SerdeAmountForOpt, S: Serializer>(
                a: &Option<A>,
                s: S,
            ) -> Result<S::Ok, S::Error> {
                match *a {
                    Some(a) => a.ser_sat_opt(s, private::Token),
                    None => s.serialize_none(),
                }
            }

            pub fn deserialize<'d, A: SerdeAmountForOpt, D: Deserializer<'d>>(
                d: D,
            ) -> Result<Option<A>, D::Error> {
                struct VisitOptAmt<X>(PhantomData<X>);

                impl<'de, X: SerdeAmountForOpt> de::Visitor<'de> for VisitOptAmt<X> {
                    type Value = Option<X>;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        write!(formatter, "An Option<{}64>", X::type_prefix(private::Token))
                    }

                    fn visit_none<E>(self) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        Ok(None)
                    }
                    fn visit_some<D>(self, d: D) -> Result<Self::Value, D::Error>
                    where
                        D: Deserializer<'de>,
                    {
                        Ok(Some(X::des_sat(d, private::Token)?))
                    }
                }
                d.deserialize_option(VisitOptAmt::<A>(PhantomData))
            }
        }
    }

    #[cfg(feature = "alloc")]
    pub mod as_btc {
        //! Serialize and deserialize [`Amount`](crate::Amount) as JSON numbers denominated in BTC.
        //! Use with `#[serde(with = "amount::serde::as_btc")]`.

        use serde::{Deserializer, Serializer};

        use super::private;
        use crate::amount::serde::SerdeAmount;

        pub fn serialize<A: SerdeAmount, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error> {
            a.ser_btc(s, private::Token)
        }

        pub fn deserialize<'d, A: SerdeAmount, D: Deserializer<'d>>(d: D) -> Result<A, D::Error> {
            A::des_btc(d, private::Token)
        }

        pub mod opt {
            //! Serialize and deserialize `Option<Amount>` as JSON numbers denominated in BTC.
            //! Use with `#[serde(default, with = "amount::serde::as_btc::opt")]`.

            use core::fmt;
            use core::marker::PhantomData;

            use serde::{de, Deserializer, Serializer};

            use super::private;
            use crate::amount::serde::SerdeAmountForOpt;

            pub fn serialize<A: SerdeAmountForOpt, S: Serializer>(
                a: &Option<A>,
                s: S,
            ) -> Result<S::Ok, S::Error> {
                match *a {
                    Some(a) => a.ser_btc_opt(s, private::Token),
                    None => s.serialize_none(),
                }
            }

            pub fn deserialize<'d, A: SerdeAmountForOpt, D: Deserializer<'d>>(
                d: D,
            ) -> Result<Option<A>, D::Error> {
                struct VisitOptAmt<X>(PhantomData<X>);

                impl<'de, X: SerdeAmountForOpt> de::Visitor<'de> for VisitOptAmt<X> {
                    type Value = Option<X>;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        write!(formatter, "An Option<f64>")
                    }

                    fn visit_none<E>(self) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        Ok(None)
                    }
                    fn visit_some<D>(self, d: D) -> Result<Self::Value, D::Error>
                    where
                        D: Deserializer<'de>,
                    {
                        Ok(Some(X::des_btc(d, private::Token)?))
                    }
                }
                d.deserialize_option(VisitOptAmt::<A>(PhantomData))
            }
        }
    }
}
