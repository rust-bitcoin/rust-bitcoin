// SPDX-License-Identifier: CC0-1.0

//! Bitcoin amounts.
//!
//! This module mainly introduces the [`Amount`] and [`SignedAmount`] types.
//! We refer to the documentation on the types for more information.

pub mod error;
mod result;
#[cfg(feature = "serde")]
pub mod serde;

mod signed;
#[cfg(test)]
mod tests;
mod unsigned;
#[cfg(kani)]
mod verification;

use core::cmp::Ordering;
use core::convert::Infallible;
use core::fmt;
use core::str::FromStr;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

use self::error::{
    InputTooLargeError, InvalidCharacterError, MissingDenominationError, MissingDigitsError,
    MissingDigitsKind, ParseAmountErrorInner, ParseErrorInner, PossiblyConfusingDenominationError,
    TooPreciseError, UnknownDenominationError,
};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    signed::SignedAmount,
    unsigned::Amount,
};
#[doc(no_inline)]
pub use self::error::{OutOfRangeError, ParseAmountError, ParseDenominationError, ParseError};

/// A set of denominations in which amounts can be expressed.
///
/// # Accepted Denominations
///
/// All upper or lower case, excluding SI prefixes c, m and u (or µ) which must be lower case.
/// - Singular: BTC, cBTC, mBTC, uBTC
/// - Plural or singular: sat, satoshi, bit
///
/// # Note
///
/// Due to ambiguity between mega and milli we prohibit usage of leading capital 'M'. It is
/// more important to protect users from incorrectly using a capital M to mean milli than to
/// allow Megabitcoin which is not a realistic denomination, and Megasatoshi which is
/// equivalent to cBTC which is allowed.
///
/// # Examples
///
/// ```
/// # use bitcoin_units::{amount, Amount};
///
/// let equal = [
///     ("1 BTC", 100_000_000),
///     ("1 cBTC", 1_000_000),
///     ("1 mBTC", 100_000),
///     ("1 uBTC", 100),
///     ("1 bit", 100),
///     ("1 sat", 1),
/// ];
/// for (string, sats) in equal {
///     assert_eq!(
///         string.parse::<Amount>().expect("valid bitcoin amount string"),
///         Amount::from_sat(sats)?,
///     )
/// }
/// # Ok::<_, amount::OutOfRangeError>(())
/// ```
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[non_exhaustive]
#[allow(clippy::doc_markdown)]
pub enum Denomination {
    /// BTC (1 BTC = 100,000,000 satoshi).
    Bitcoin,
    /// cBTC (1 cBTC = 1,000,000 satoshi).
    CentiBitcoin,
    /// mBTC (1 mBTC = 100,000 satoshi).
    MilliBitcoin,
    /// µBTC (1 µBTC = 100 satoshi).
    MicroBitcoin,
    /// bits (bits = µBTC).
    Bit,
    /// satoshi (1 BTC = 100,000,000 satoshi).
    Satoshi,
    /// Stops users from casting this enum to an integer.
    // May get removed if one day Rust supports disabling casts natively.
    #[doc(hidden)]
    _DoNotUse(Infallible),
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
            Denomination::_DoNotUse(infallible) => match infallible {},
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
            Denomination::_DoNotUse(infallible) => match infallible {},
        }
    }

    /// The different `str` forms of denominations that are recognized.
    fn forms(s: &str) -> Option<Self> {
        match s {
            "BTC" | "btc" => Some(Denomination::Bitcoin),
            "cBTC" | "cbtc" => Some(Denomination::CentiBitcoin),
            "mBTC" | "mbtc" => Some(Denomination::MilliBitcoin),
            "uBTC" | "ubtc" | "µBTC" | "µbtc" => Some(Denomination::MicroBitcoin),
            "bit" | "bits" | "BIT" | "BITS" => Some(Denomination::Bit),
            "SATOSHI" | "satoshi" | "SATOSHIS" | "satoshis" | "SAT" | "sat" | "SATS" | "sats" =>
                Some(Denomination::Satoshi),
            _ => None,
        }
    }
}

/// These form are ambiguous and could have many meanings.  For example, M could denote Mega or Milli.
/// If any of these forms are used, an error type `PossiblyConfusingDenomination` is returned.
const CONFUSING_FORMS: [&str; 6] = ["CBTC", "Cbtc", "MBTC", "Mbtc", "UBTC", "Ubtc"];

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str(self.as_str()) }
}

impl FromStr for Denomination {
    type Err = ParseDenominationError;

    /// Converts from a `str` to a `Denomination`.
    ///
    /// # Errors
    ///
    /// - [`ParseDenominationError::PossiblyConfusing`]: If the denomination begins with a capital
    ///   letter that could be confused with centi, milli, or micro-bitcoin.
    /// - [`ParseDenominationError::Unknown`]: If an unknown denomination is used.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::ParseDenominationError as E;

        if CONFUSING_FORMS.contains(&s) {
            return Err(E::PossiblyConfusing(PossiblyConfusingDenominationError(s.into())));
        };

        let form = self::Denomination::forms(s);

        form.ok_or_else(|| E::Unknown(UnknownDenominationError(s.into())))
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
///
/// The `bool` is only needed to distinguish -0 from 0.
fn parse_signed_to_satoshi(
    mut s: &str,
    denom: Denomination,
) -> Result<(bool, SignedAmount), InnerParseError> {
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
                    Ok(0) => return Ok((is_negative, SignedAmount::ZERO)),
                    _ =>
                        return Err(InnerParseError::TooPrecise(TooPreciseError {
                            position: position + usize::from(is_negative),
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
    let mut value: i64 = 0; // as satoshis
    for (i, c) in s.char_indices() {
        match c {
            '0'..='9' => {
                // Do `value = 10 * value + digit`, catching overflows.
                match 10_i64.checked_mul(value) {
                    None => return Err(InnerParseError::Overflow { is_negative }),
                    Some(val) => match val.checked_add(i64::from(c as u8 - b'0')) {
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
                            position: i + usize::from(is_negative),
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
                        position: i + usize::from(is_negative),
                    })),
            },
            c =>
                return Err(InnerParseError::InvalidCharacter(InvalidCharacterError {
                    invalid_char: c,
                    position: i + usize::from(is_negative),
                })),
        }
    }

    // Decimally shift left by `max_decimals - decimals`.
    let scale_factor = max_decimals - decimals.unwrap_or(0);
    for _ in 0..scale_factor {
        value = match 10_i64.checked_mul(value) {
            Some(v) => v,
            None => return Err(InnerParseError::Overflow { is_negative }),
        };
    }

    let mut ret =
        SignedAmount::from_sat(value).map_err(|_| InnerParseError::Overflow { is_negative })?;
    if is_negative {
        ret = -ret;
    }
    Ok((is_negative, ret))
}

#[derive(Debug)]
enum InnerParseError {
    Overflow { is_negative: bool },
    TooPrecise(TooPreciseError),
    MissingDigits(MissingDigitsError),
    InputTooLarge(usize),
    InvalidCharacter(InvalidCharacterError),
}

impl From<Infallible> for InnerParseError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl InnerParseError {
    fn convert(self, is_signed: bool) -> ParseAmountError {
        match self {
            Self::Overflow { is_negative } =>
                OutOfRangeError { is_signed, is_greater_than_max: !is_negative }.into(),
            Self::TooPrecise(e) => ParseAmountError(ParseAmountErrorInner::TooPrecise(e)),
            Self::MissingDigits(e) => ParseAmountError(ParseAmountErrorInner::MissingDigits(e)),
            Self::InputTooLarge(len) =>
                ParseAmountError(ParseAmountErrorInner::InputTooLarge(InputTooLargeError { len })),
            Self::InvalidCharacter(e) =>
                ParseAmountError(ParseAmountErrorInner::InvalidCharacter(e)),
        }
    }
}

fn split_amount_and_denomination(s: &str) -> Result<(&str, Denomination), ParseError> {
    let (i, j) = if let Some(i) = s.find(' ') {
        (i, i + 1)
    } else {
        let i = s
            .find(|c: char| c.is_alphabetic())
            .ok_or(ParseError(ParseErrorInner::MissingDenomination(MissingDenominationError)))?;
        (i, i)
    };
    Ok((&s[..i], s[j..].parse()?))
}

/// Options given by `fmt::Formatter`
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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

/// Formats the given satoshi amount in the given denomination.
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
                exp = precision as usize; // Cast ok, checked not negative above.
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
                        10u64.pow(u32::from(precision) - format_precision as u32); // Cast ok, commented above.
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
                    num_after_decimal_point /= 10;
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
            ((width - num_width) / 2, (width - num_width).div_ceil(2)),
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
    #[must_use]
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

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Denomination {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=5)?;
        match choice {
            0 => Ok(Denomination::Bitcoin),
            1 => Ok(Denomination::CentiBitcoin),
            2 => Ok(Denomination::MilliBitcoin),
            3 => Ok(Denomination::MicroBitcoin),
            4 => Ok(Denomination::Bit),
            _ => Ok(Denomination::Satoshi),
        }
    }
}
