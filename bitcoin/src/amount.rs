// SPDX-License-Identifier: CC0-1.0

//! Bitcoin amounts.
//!
//! This module mainly introduces the [Amount] and [SignedAmount] types.
//! We refer to the documentation on the types for more information.
//!

use core::cmp::Ordering;
use core::fmt::{self, Write};
use core::str::FromStr;
use core::{default, ops};

use crate::prelude::*;

/// A set of denominations in which amounts can be expressed.
///
/// # Examples
/// ```
/// # use core::str::FromStr;
/// # use bitcoin::Amount;
///
/// assert_eq!(Amount::from_str("1 BTC").unwrap(), Amount::from_sat(100_000_000));
/// assert_eq!(Amount::from_str("1 cBTC").unwrap(), Amount::from_sat(1_000_000));
/// assert_eq!(Amount::from_str("1 mBTC").unwrap(), Amount::from_sat(100_000));
/// assert_eq!(Amount::from_str("1 uBTC").unwrap(), Amount::from_sat(100));
/// assert_eq!(Amount::from_str("10 nBTC").unwrap(), Amount::from_sat(1));
/// assert_eq!(Amount::from_str("10000 pBTC").unwrap(), Amount::from_sat(1));
/// assert_eq!(Amount::from_str("1 bit").unwrap(), Amount::from_sat(100));
/// assert_eq!(Amount::from_str("1 sat").unwrap(), Amount::from_sat(1));
/// assert_eq!(Amount::from_str("1000 msats").unwrap(), Amount::from_sat(1));
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
    /// nBTC
    NanoBitcoin,
    /// pBTC
    PicoBitcoin,
    /// bits
    Bit,
    /// satoshi
    Satoshi,
    /// msat
    MilliSatoshi,
}

impl Denomination {
    /// The number of decimal places more than a satoshi.
    fn precision(self) -> i8 {
        match self {
            Denomination::Bitcoin => -8,
            Denomination::CentiBitcoin => -6,
            Denomination::MilliBitcoin => -5,
            Denomination::MicroBitcoin => -2,
            Denomination::NanoBitcoin => 1,
            Denomination::PicoBitcoin => 4,
            Denomination::Bit => -2,
            Denomination::Satoshi => 0,
            Denomination::MilliSatoshi => 3,
        }
    }

    /// Returns stringly representation of this
    fn as_str(self) -> &'static str {
        match self {
            Denomination::Bitcoin => "BTC",
            Denomination::CentiBitcoin => "cBTC",
            Denomination::MilliBitcoin => "mBTC",
            Denomination::MicroBitcoin => "uBTC",
            Denomination::NanoBitcoin => "nBTC",
            Denomination::PicoBitcoin => "pBTC",
            Denomination::Bit => "bits",
            Denomination::Satoshi => "satoshi",
            Denomination::MilliSatoshi => "msat",
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str(self.as_str()) }
}

impl FromStr for Denomination {
    type Err = ParseAmountError;

    /// Convert from a str to Denomination.
    ///
    /// Any combination of upper and/or lower case, excluding uppercase of SI(m, u, n, p) is considered valid.
    /// - Singular: BTC, mBTC, uBTC, nBTC, pBTC
    /// - Plural or singular: sat, satoshi, bit, msat
    ///
    /// Due to ambiguity between mega and milli, pico and peta we prohibit usage of leading capital 'M', 'P'.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::Denomination as D;
        use self::ParseAmountError::*;

        let starts_with_uppercase = || s.starts_with(char::is_uppercase);
        match denomination_from_str(s) {
            None => Err(UnknownDenomination(s.to_owned())),
            Some(D::MilliBitcoin) | Some(D::PicoBitcoin) | Some(D::MilliSatoshi)
                if starts_with_uppercase() =>
                Err(PossiblyConfusingDenomination(s.to_owned())),
            Some(D::NanoBitcoin) | Some(D::MicroBitcoin) if starts_with_uppercase() =>
                Err(UnknownDenomination(s.to_owned())),
            Some(d) => Ok(d),
        }
    }
}

fn denomination_from_str(mut s: &str) -> Option<Denomination> {
    if s.eq_ignore_ascii_case("BTC") {
        return Some(Denomination::Bitcoin);
    }

    if s.eq_ignore_ascii_case("cBTC") {
        return Some(Denomination::CentiBitcoin);
    }

    if s.eq_ignore_ascii_case("mBTC") {
        return Some(Denomination::MilliBitcoin);
    }

    if s.eq_ignore_ascii_case("uBTC") {
        return Some(Denomination::MicroBitcoin);
    }

    if s.eq_ignore_ascii_case("nBTC") {
        return Some(Denomination::NanoBitcoin);
    }

    if s.eq_ignore_ascii_case("pBTC") {
        return Some(Denomination::PicoBitcoin);
    }

    if s.ends_with('s') || s.ends_with('S') {
        s = &s[..(s.len() - 1)];
    }

    if s.eq_ignore_ascii_case("bit") {
        return Some(Denomination::Bit);
    }
    if s.eq_ignore_ascii_case("satoshi") {
        return Some(Denomination::Satoshi);
    }
    if s.eq_ignore_ascii_case("sat") {
        return Some(Denomination::Satoshi);
    }

    if s.eq_ignore_ascii_case("msat") {
        return Some(Denomination::MilliSatoshi);
    }

    None
}

/// An error during amount parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseAmountError {
    /// Amount is negative.
    Negative,
    /// Amount is too big to fit inside the type.
    TooBig,
    /// Amount has higher precision than supported by the type.
    TooPrecise,
    /// Invalid number format.
    InvalidFormat,
    /// Input string was too large.
    InputTooLarge,
    /// Invalid character in input.
    InvalidCharacter(char),
    /// The denomination was unknown.
    UnknownDenomination(String),
    /// The denomination has multiple possible interpretations.
    PossiblyConfusingDenomination(String),
}

impl fmt::Display for ParseAmountError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseAmountError::Negative => f.write_str("amount is negative"),
            ParseAmountError::TooBig => f.write_str("amount is too big"),
            ParseAmountError::TooPrecise => f.write_str("amount has a too high precision"),
            ParseAmountError::InvalidFormat => f.write_str("invalid number format"),
            ParseAmountError::InputTooLarge => f.write_str("input string was too large"),
            ParseAmountError::InvalidCharacter(c) => write!(f, "invalid character in input: {}", c),
            ParseAmountError::UnknownDenomination(ref d) =>
                write!(f, "unknown denomination: {}", d),
            ParseAmountError::PossiblyConfusingDenomination(ref d) => {
                let (letter, upper, lower) = match d.chars().next() {
                    Some('M') => ('M', "Mega", "milli"),
                    Some('P') => ('P', "Peta", "pico"),
                    // This panic could be avoided by adding enum ConfusingDenomination { Mega, Peta } but is it worth it?
                    _ => panic!("invalid error information"),
                };
                write!(f, "the '{}' at the beginning of {} should technically mean '{}' but that denomination is uncommon and maybe '{}' was intended", letter, d, upper, lower)
            }
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for ParseAmountError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::ParseAmountError::*;

        match *self {
            Negative
            | TooBig
            | TooPrecise
            | InvalidFormat
            | InputTooLarge
            | InvalidCharacter(_)
            | UnknownDenomination(_)
            | PossiblyConfusingDenomination(_) => None,
        }
    }
}

fn is_too_precise(s: &str, precision: usize) -> bool {
    s.contains('.') || precision >= s.len() || s.chars().rev().take(precision).any(|d| d != '0')
}

/// Parse decimal string in the given denomination into a satoshi value and a
/// bool indicator for a negative amount.
fn parse_signed_to_satoshi(
    mut s: &str,
    denom: Denomination,
) -> Result<(bool, u64), ParseAmountError> {
    if s.is_empty() {
        return Err(ParseAmountError::InvalidFormat);
    }
    if s.len() > 50 {
        return Err(ParseAmountError::InputTooLarge);
    }

    let is_negative = s.starts_with('-');
    if is_negative {
        if s.len() == 1 {
            return Err(ParseAmountError::InvalidFormat);
        }
        s = &s[1..];
    }

    let max_decimals = {
        // The difference in precision between native (satoshi)
        // and desired denomination.
        let precision_diff = -denom.precision();
        if precision_diff < 0 {
            // If precision diff is negative, this means we are parsing
            // into a less precise amount. That is not allowed unless
            // there are no decimals and the last digits are zeroes as
            // many as the difference in precision.
            let last_n = unsigned_abs(precision_diff).into();
            if is_too_precise(s, last_n) {
                match s.parse::<i64>() {
                    Ok(v) if v == 0_i64 => return Ok((is_negative, 0)),
                    _ => return Err(ParseAmountError::TooPrecise),
                }
            }
            s = &s[0..s.len() - last_n];
            0
        } else {
            precision_diff
        }
    };

    let mut decimals = None;
    let mut value: u64 = 0; // as satoshis
    for c in s.chars() {
        match c {
            '0'..='9' => {
                // Do `value = 10 * value + digit`, catching overflows.
                match 10_u64.checked_mul(value) {
                    None => return Err(ParseAmountError::TooBig),
                    Some(val) => match val.checked_add((c as u8 - b'0') as u64) {
                        None => return Err(ParseAmountError::TooBig),
                        Some(val) => value = val,
                    },
                }
                // Increment the decimal digit counter if past decimal.
                decimals = match decimals {
                    None => None,
                    Some(d) if d < max_decimals => Some(d + 1),
                    _ => return Err(ParseAmountError::TooPrecise),
                };
            }
            '.' => match decimals {
                None => decimals = Some(0),
                // Double decimal dot.
                _ => return Err(ParseAmountError::InvalidFormat),
            },
            c => return Err(ParseAmountError::InvalidCharacter(c)),
        }
    }

    // Decimally shift left by `max_decimals - decimals`.
    let scale_factor = max_decimals - decimals.unwrap_or(0);
    for _ in 0..scale_factor {
        value = match 10_u64.checked_mul(value) {
            Some(v) => v,
            None => return Err(ParseAmountError::TooBig),
        };
    }

    Ok((is_negative, value))
}

fn split_amount_and_denomination(s: &str) -> Result<(&str, Denomination), ParseAmountError> {
    let (i, j) = if let Some(i) = s.find(' ') {
        (i, i + 1)
    } else {
        let i = s.find(|c: char| c.is_alphabetic()).ok_or(ParseAmountError::InvalidFormat)?;
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

// NIH due to MSRV, impl copied from `core::i8::unsigned_abs` (introduced in Rust 1.51.1).
fn unsigned_abs(x: i8) -> u8 { x.wrapping_abs() as u8 }

fn repeat_char(f: &mut dyn fmt::Write, c: char, count: usize) -> fmt::Result {
    for _ in 0..count {
        f.write_char(c)?;
    }
    Ok(())
}

/// Format the given satoshi amount in the given denomination.
fn fmt_satoshi_in(
    satoshi: u64,
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
            let precision = unsigned_abs(precision);
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

/// Amount
///
/// The [Amount] type can be used to express Bitcoin amounts that support
/// arithmetic and conversion to various denominations.
///
///
/// Warning!
///
/// This type implements several arithmetic operations from [core::ops].
/// To prevent errors due to overflow or underflow when using these operations,
/// it is advised to instead use the checked arithmetic methods whose names
/// start with `checked_`.  The operations from [core::ops] that [Amount]
/// implements will panic when overflow or underflow occurs.  Also note that
/// since the internal representation of amounts is unsigned, subtracting below
/// zero is considered an underflow and will cause a panic if you're not using
/// the checked arithmetic methods.
///
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(u64);

impl Amount {
    /// The zero amount.
    pub const ZERO: Amount = Amount(0);
    /// Exactly one satoshi.
    pub const ONE_SAT: Amount = Amount(1);
    /// Exactly one bitcoin.
    pub const ONE_BTC: Amount = Amount(100_000_000);
    /// The maximum value allowed as an amount. Useful for sanity checking.
    pub const MAX_MONEY: Amount = Amount(21_000_000 * 100_000_000);

    /// Create an [Amount] with satoshi precision and the given number of satoshis.
    pub const fn from_sat(satoshi: u64) -> Amount { Amount(satoshi) }

    /// Gets the number of satoshis in this [`Amount`].
    pub fn to_sat(self) -> u64 { self.0 }

    /// The maximum value of an [Amount].
    pub const fn max_value() -> Amount { Amount(u64::max_value()) }

    /// The minimum value of an [Amount].
    pub const fn min_value() -> Amount { Amount(u64::min_value()) }

    /// Convert from a value expressing bitcoins to an [Amount].
    pub fn from_btc(btc: f64) -> Result<Amount, ParseAmountError> {
        Amount::from_float_in(btc, Denomination::Bitcoin)
    }

    /// Parse a decimal string as a value in the given denomination.
    ///
    /// Note: This only parses the value string.  If you want to parse a value
    /// with denomination, use [FromStr].
    pub fn from_str_in(s: &str, denom: Denomination) -> Result<Amount, ParseAmountError> {
        let (negative, satoshi) = parse_signed_to_satoshi(s, denom)?;
        if negative {
            return Err(ParseAmountError::Negative);
        }
        if satoshi > i64::max_value() as u64 {
            return Err(ParseAmountError::TooBig);
        }
        Ok(Amount::from_sat(satoshi))
    }

    /// Parses amounts with denomination suffix like they are produced with
    /// [Self::to_string_with_denomination] or with [fmt::Display].
    /// If you want to parse only the amount without the denomination,
    /// use [Self::from_str_in].
    pub fn from_str_with_denomination(s: &str) -> Result<Amount, ParseAmountError> {
        let (amt, denom) = split_amount_and_denomination(s)?;
        Amount::from_str_in(amt, denom)
    }

    /// Express this [Amount] as a floating-point value in the given denomination.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn to_float_in(self, denom: Denomination) -> f64 {
        f64::from_str(&self.to_string_in(denom)).unwrap()
    }

    /// Express this [`Amount`] as a floating-point value in Bitcoin.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    ///
    /// # Examples
    /// ```
    /// # use bitcoin::{Amount, Denomination};
    /// let amount = Amount::from_sat(100_000);
    /// assert_eq!(amount.to_btc(), amount.to_float_in(Denomination::Bitcoin))
    /// ```
    pub fn to_btc(self) -> f64 { self.to_float_in(Denomination::Bitcoin) }

    /// Convert this [Amount] in floating-point notation with a given
    /// denomination.
    /// Can return error if the amount is too big, too precise or negative.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn from_float_in(value: f64, denom: Denomination) -> Result<Amount, ParseAmountError> {
        if value < 0.0 {
            return Err(ParseAmountError::Negative);
        }
        // This is inefficient, but the safest way to deal with this. The parsing logic is safe.
        // Any performance-critical application should not be dealing with floats.
        Amount::from_str_in(&value.to_string(), denom)
    }

    /// Create an object that implements [`fmt::Display`] using specified denomination.
    pub fn display_in(self, denomination: Denomination) -> Display {
        Display {
            sats_abs: self.to_sat(),
            is_negative: false,
            style: DisplayStyle::FixedDenomination { denomination, show_denomination: false },
        }
    }

    /// Create an object that implements [`fmt::Display`] dynamically selecting denomination.
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

    /// Format the value of this [Amount] in the given denomination.
    ///
    /// Does not include the denomination.
    #[rustfmt::skip]
    pub fn fmt_value_in(self, f: &mut dyn fmt::Write, denom: Denomination) -> fmt::Result {
        fmt_satoshi_in(self.to_sat(), false, f, denom, false, FormatOptions::default())
    }

    /// Get a string number of this [Amount] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn to_string_in(self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        buf
    }

    /// Get a formatted string of this [Amount] in the given denomination,
    /// suffixed with the abbreviation for the denomination.
    pub fn to_string_with_denomination(self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        write!(buf, " {}", denom).unwrap();
        buf
    }

    // Some arithmetic that doesn't fit in `core::ops` traits.

    /// Checked addition.
    /// Returns [None] if overflow occurred.
    pub fn checked_add(self, rhs: Amount) -> Option<Amount> {
        self.0.checked_add(rhs.0).map(Amount)
    }

    /// Checked subtraction.
    /// Returns [None] if overflow occurred.
    pub fn checked_sub(self, rhs: Amount) -> Option<Amount> {
        self.0.checked_sub(rhs.0).map(Amount)
    }

    /// Checked multiplication.
    /// Returns [None] if overflow occurred.
    pub fn checked_mul(self, rhs: u64) -> Option<Amount> { self.0.checked_mul(rhs).map(Amount) }

    /// Checked integer division.
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made.
    /// Returns [None] if overflow occurred.
    pub fn checked_div(self, rhs: u64) -> Option<Amount> { self.0.checked_div(rhs).map(Amount) }

    /// Checked remainder.
    /// Returns [None] if overflow occurred.
    pub fn checked_rem(self, rhs: u64) -> Option<Amount> { self.0.checked_rem(rhs).map(Amount) }

    /// Convert to a signed amount.
    pub fn to_signed(self) -> Result<SignedAmount, ParseAmountError> {
        if self.to_sat() > SignedAmount::max_value().to_sat() as u64 {
            Err(ParseAmountError::TooBig)
        } else {
            Ok(SignedAmount::from_sat(self.to_sat() as i64))
        }
    }
}

impl default::Default for Amount {
    fn default() -> Self { Amount::ZERO }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Amount({:.8} BTC)", self.to_btc())
    }
}

// No one should depend on a binding contract for Display for this type.
// Just using Bitcoin denominated string.
impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_value_in(f, Denomination::Bitcoin)?;
        write!(f, " {}", Denomination::Bitcoin)
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
    type Err = ParseAmountError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Amount::from_str_with_denomination(s) }
}

impl core::iter::Sum for Amount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let sats: u64 = iter.map(|amt| amt.0).sum();
        Amount::from_sat(sats)
    }
}

/// A helper/builder that displays amount with specified settings.
///
/// This provides richer interface than `fmt::Formatter`:
///
/// * Ability to select denomination
/// * Show or hide denomination
/// * Dynamically-selected denomination - show in sats if less than 1 BTC.
///
/// However this can still be combined with `fmt::Formatter` options to precisely control zeros,
/// padding, alignment... The formatting works like floats from `core` but note that precision will
/// **never** be lossy - that means no rounding.
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

/// SignedAmount
///
/// The [SignedAmount] type can be used to express Bitcoin amounts that support
/// arithmetic and conversion to various denominations.
///
///
/// Warning!
///
/// This type implements several arithmetic operations from [core::ops].
/// To prevent errors due to overflow or underflow when using these operations,
/// it is advised to instead use the checked arithmetic methods whose names
/// start with `checked_`.  The operations from [core::ops] that [Amount]
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

    /// Create an [SignedAmount] with satoshi precision and the given number of satoshis.
    pub const fn from_sat(satoshi: i64) -> SignedAmount { SignedAmount(satoshi) }

    /// Gets the number of satoshis in this [`SignedAmount`].
    pub fn to_sat(self) -> i64 { self.0 }

    /// The maximum value of an [SignedAmount].
    pub const fn max_value() -> SignedAmount { SignedAmount(i64::max_value()) }

    /// The minimum value of an [SignedAmount].
    pub const fn min_value() -> SignedAmount { SignedAmount(i64::min_value()) }

    /// Convert from a value expressing bitcoins to an [SignedAmount].
    pub fn from_btc(btc: f64) -> Result<SignedAmount, ParseAmountError> {
        SignedAmount::from_float_in(btc, Denomination::Bitcoin)
    }

    /// Parse a decimal string as a value in the given denomination.
    ///
    /// Note: This only parses the value string.  If you want to parse a value
    /// with denomination, use [FromStr].
    pub fn from_str_in(s: &str, denom: Denomination) -> Result<SignedAmount, ParseAmountError> {
        let (negative, satoshi) = parse_signed_to_satoshi(s, denom)?;
        if satoshi > i64::max_value() as u64 {
            return Err(ParseAmountError::TooBig);
        }
        Ok(match negative {
            true => SignedAmount(-(satoshi as i64)),
            false => SignedAmount(satoshi as i64),
        })
    }

    /// Parses amounts with denomination suffix like they are produced with
    /// [Self::to_string_with_denomination] or with [fmt::Display].
    /// If you want to parse only the amount without the denomination,
    /// use [Self::from_str_in].
    pub fn from_str_with_denomination(s: &str) -> Result<SignedAmount, ParseAmountError> {
        let (amt, denom) = split_amount_and_denomination(s)?;
        SignedAmount::from_str_in(amt, denom)
    }

    /// Express this [SignedAmount] as a floating-point value in the given denomination.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn to_float_in(self, denom: Denomination) -> f64 {
        f64::from_str(&self.to_string_in(denom)).unwrap()
    }

    /// Express this [`SignedAmount`] as a floating-point value in Bitcoin.
    ///
    /// Equivalent to `to_float_in(Denomination::Bitcoin)`.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn to_btc(self) -> f64 { self.to_float_in(Denomination::Bitcoin) }

    /// Convert this [SignedAmount] in floating-point notation with a given
    /// denomination.
    /// Can return error if the amount is too big, too precise or negative.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn from_float_in(
        value: f64,
        denom: Denomination,
    ) -> Result<SignedAmount, ParseAmountError> {
        // This is inefficient, but the safest way to deal with this. The parsing logic is safe.
        // Any performance-critical application should not be dealing with floats.
        SignedAmount::from_str_in(&value.to_string(), denom)
    }

    /// Returns the absolute value as satoshis.
    ///
    /// This is the implementation of `unsigned_abs()` copied from `core` to support older MSRV.
    fn to_sat_abs(self) -> u64 { self.to_sat().wrapping_abs() as u64 }

    /// Create an object that implements [`fmt::Display`] using specified denomination.
    pub fn display_in(self, denomination: Denomination) -> Display {
        Display {
            sats_abs: self.to_sat_abs(),
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
            sats_abs: self.to_sat_abs(),
            is_negative: self.is_negative(),
            style: DisplayStyle::DynamicDenomination,
        }
    }

    /// Format the value of this [SignedAmount] in the given denomination.
    ///
    /// Does not include the denomination.
    #[rustfmt::skip]
    pub fn fmt_value_in(self, f: &mut dyn fmt::Write, denom: Denomination) -> fmt::Result {
        fmt_satoshi_in(self.to_sat_abs(), self.is_negative(), f, denom, false, FormatOptions::default())
    }

    /// Get a string number of this [SignedAmount] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn to_string_in(self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        buf
    }

    /// Get a formatted string of this [SignedAmount] in the given denomination,
    /// suffixed with the abbreviation for the denomination.
    pub fn to_string_with_denomination(self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        write!(buf, " {}", denom).unwrap();
        buf
    }

    // Some arithmetic that doesn't fit in `core::ops` traits.

    /// Get the absolute value of this [SignedAmount].
    pub fn abs(self) -> SignedAmount { SignedAmount(self.0.abs()) }

    /// Returns a number representing sign of this [SignedAmount].
    ///
    /// - `0` if the amount is zero
    /// - `1` if the amount is positive
    /// - `-1` if the amount is negative
    pub fn signum(self) -> i64 { self.0.signum() }

    /// Returns `true` if this [SignedAmount] is positive and `false` if
    /// this [SignedAmount] is zero or negative.
    pub fn is_positive(self) -> bool { self.0.is_positive() }

    /// Returns `true` if this [SignedAmount] is negative and `false` if
    /// this [SignedAmount] is zero or positive.
    pub fn is_negative(self) -> bool { self.0.is_negative() }

    /// Get the absolute value of this [SignedAmount].
    /// Returns [None] if overflow occurred. (`self == min_value()`)
    pub fn checked_abs(self) -> Option<SignedAmount> { self.0.checked_abs().map(SignedAmount) }

    /// Checked addition.
    /// Returns [None] if overflow occurred.
    pub fn checked_add(self, rhs: SignedAmount) -> Option<SignedAmount> {
        self.0.checked_add(rhs.0).map(SignedAmount)
    }

    /// Checked subtraction.
    /// Returns [None] if overflow occurred.
    pub fn checked_sub(self, rhs: SignedAmount) -> Option<SignedAmount> {
        self.0.checked_sub(rhs.0).map(SignedAmount)
    }

    /// Checked multiplication.
    /// Returns [None] if overflow occurred.
    pub fn checked_mul(self, rhs: i64) -> Option<SignedAmount> {
        self.0.checked_mul(rhs).map(SignedAmount)
    }

    /// Checked integer division.
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made.
    /// Returns [None] if overflow occurred.
    pub fn checked_div(self, rhs: i64) -> Option<SignedAmount> {
        self.0.checked_div(rhs).map(SignedAmount)
    }

    /// Checked remainder.
    /// Returns [None] if overflow occurred.
    pub fn checked_rem(self, rhs: i64) -> Option<SignedAmount> {
        self.0.checked_rem(rhs).map(SignedAmount)
    }

    /// Subtraction that doesn't allow negative [SignedAmount]s.
    /// Returns [None] if either [self], `rhs` or the result is strictly negative.
    pub fn positive_sub(self, rhs: SignedAmount) -> Option<SignedAmount> {
        if self.is_negative() || rhs.is_negative() || rhs > self {
            None
        } else {
            self.checked_sub(rhs)
        }
    }

    /// Convert to an unsigned amount.
    pub fn to_unsigned(self) -> Result<Amount, ParseAmountError> {
        if self.is_negative() {
            Err(ParseAmountError::Negative)
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
        write!(f, "SignedAmount({:.8} BTC)", self.to_btc())
    }
}

// No one should depend on a binding contract for Display for this type.
// Just using Bitcoin denominated string.
impl fmt::Display for SignedAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_value_in(f, Denomination::Bitcoin)?;
        write!(f, " {}", Denomination::Bitcoin)
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

impl FromStr for SignedAmount {
    type Err = ParseAmountError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { SignedAmount::from_str_with_denomination(s) }
}

impl core::iter::Sum for SignedAmount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let sats: i64 = iter.map(|amt| amt.0).sum();
        SignedAmount::from_sat(sats)
    }
}

/// Calculate the sum over the iterator using checked arithmetic.
pub trait CheckedSum<R>: private::SumSeal<R> {
    /// Calculate the sum over the iterator using checked arithmetic. If an over or underflow would
    /// happen it returns `None`.
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
    use crate::{Amount, SignedAmount};

    /// Used to seal the `CheckedSum` trait
    pub trait SumSeal<A> {}

    impl<T> SumSeal<Amount> for T where T: Iterator<Item = Amount> {}
    impl<T> SumSeal<SignedAmount> for T where T: Iterator<Item = SignedAmount> {}
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub mod serde {
    // methods are implementation of a standardized serde-specific signature
    #![allow(missing_docs)]

    //! This module adds serde serialization and deserialization support for Amounts.
    //! Since there is not a default way to serialize and deserialize Amounts, multiple
    //! ways are supported and it's up to the user to decide which serialiation to use.
    //! The provided modules can be used as follows:
    //!
    //! ```rust,ignore
    //! use serde::{Serialize, Deserialize};
    //! use bitcoin::Amount;
    //!
    //! #[derive(Serialize, Deserialize)]
    //! # #[serde(crate = "actual_serde")]
    //! pub struct HasAmount {
    //!     #[serde(with = "bitcoin::amount::serde::as_btc")]
    //!     pub amount: Amount,
    //! }
    //! ```

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::amount::{Amount, Denomination, SignedAmount};

    /// This trait is used only to avoid code duplication and naming collisions
    /// of the different serde serialization crates.
    pub trait SerdeAmount: Copy + Sized + private::Sealed {
        fn ser_sat<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error>;
        fn des_sat<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error>;
        fn ser_btc<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error>;
        fn des_btc<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error>;
    }

    mod private {
        /// add this as a trait bound to traits which consumers of this library
        /// should not be able to implement.
        pub trait Sealed {}
        impl Sealed for super::Amount {}
        impl Sealed for super::SignedAmount {}
    }

    /// This trait is only for internal Amount type serialization/deserialization
    pub trait SerdeAmountForOpt: Copy + Sized + SerdeAmount + private::Sealed {
        fn type_prefix() -> &'static str;
        fn ser_sat_opt<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error>;
        fn ser_btc_opt<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error>;
    }

    impl SerdeAmount for Amount {
        fn ser_sat<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            u64::serialize(&self.to_sat(), s)
        }
        fn des_sat<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            Ok(Amount::from_sat(u64::deserialize(d)?))
        }
        fn ser_btc<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            f64::serialize(&self.to_float_in(Denomination::Bitcoin), s)
        }
        fn des_btc<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            use serde::de::Error;
            Amount::from_btc(f64::deserialize(d)?).map_err(D::Error::custom)
        }
    }

    impl SerdeAmountForOpt for Amount {
        fn type_prefix() -> &'static str { "u" }
        fn ser_sat_opt<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_some(&self.to_sat())
        }
        fn ser_btc_opt<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_some(&self.to_btc())
        }
    }

    impl SerdeAmount for SignedAmount {
        fn ser_sat<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            i64::serialize(&self.to_sat(), s)
        }
        fn des_sat<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            Ok(SignedAmount::from_sat(i64::deserialize(d)?))
        }
        fn ser_btc<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            f64::serialize(&self.to_float_in(Denomination::Bitcoin), s)
        }
        fn des_btc<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            use serde::de::Error;
            SignedAmount::from_btc(f64::deserialize(d)?).map_err(D::Error::custom)
        }
    }

    impl SerdeAmountForOpt for SignedAmount {
        fn type_prefix() -> &'static str { "i" }
        fn ser_sat_opt<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_some(&self.to_sat())
        }
        fn ser_btc_opt<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_some(&self.to_btc())
        }
    }

    pub mod as_sat {
        //! Serialize and deserialize [`Amount`](crate::Amount) as real numbers denominated in satoshi.
        //! Use with `#[serde(with = "amount::serde::as_sat")]`.

        use serde::{Deserializer, Serializer};

        use crate::amount::serde::SerdeAmount;

        pub fn serialize<A: SerdeAmount, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error> {
            a.ser_sat(s)
        }

        pub fn deserialize<'d, A: SerdeAmount, D: Deserializer<'d>>(d: D) -> Result<A, D::Error> {
            A::des_sat(d)
        }

        pub mod opt {
            //! Serialize and deserialize [`Option<Amount>`](crate::Amount) as real numbers denominated in satoshi.
            //! Use with `#[serde(default, with = "amount::serde::as_sat::opt")]`.

            use core::fmt;
            use core::marker::PhantomData;

            use serde::{de, Deserializer, Serializer};

            use crate::amount::serde::SerdeAmountForOpt;

            pub fn serialize<A: SerdeAmountForOpt, S: Serializer>(
                a: &Option<A>,
                s: S,
            ) -> Result<S::Ok, S::Error> {
                match *a {
                    Some(a) => a.ser_sat_opt(s),
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
                        write!(formatter, "An Option<{}64>", X::type_prefix())
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
                        Ok(Some(X::des_sat(d)?))
                    }
                }
                d.deserialize_option(VisitOptAmt::<A>(PhantomData))
            }
        }
    }

    pub mod as_btc {
        //! Serialize and deserialize [`Amount`](crate::Amount) as JSON numbers denominated in BTC.
        //! Use with `#[serde(with = "amount::serde::as_btc")]`.

        use serde::{Deserializer, Serializer};

        use crate::amount::serde::SerdeAmount;

        pub fn serialize<A: SerdeAmount, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error> {
            a.ser_btc(s)
        }

        pub fn deserialize<'d, A: SerdeAmount, D: Deserializer<'d>>(d: D) -> Result<A, D::Error> {
            A::des_btc(d)
        }

        pub mod opt {
            //! Serialize and deserialize `Option<Amount>` as JSON numbers denominated in BTC.
            //! Use with `#[serde(default, with = "amount::serde::as_btc::opt")]`.

            use core::fmt;
            use core::marker::PhantomData;

            use serde::{de, Deserializer, Serializer};

            use crate::amount::serde::SerdeAmountForOpt;

            pub fn serialize<A: SerdeAmountForOpt, S: Serializer>(
                a: &Option<A>,
                s: S,
            ) -> Result<S::Ok, S::Error> {
                match *a {
                    Some(a) => a.ser_btc_opt(s),
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
                        Ok(Some(X::des_btc(d)?))
                    }
                }
                d.deserialize_option(VisitOptAmt::<A>(PhantomData))
            }
        }
    }
}

#[cfg(kani)]
mod verification {
    use std::cmp;
    use std::convert::TryInto;

    use super::*;

    // Note regarding the `unwind` parameter: this defines how many iterations
    // of loops kani will unwind before handing off to the SMT solver. Basically
    // it should be set as low as possible such that Kani still succeeds (doesn't
    // return "undecidable").
    //
    // There is more info here: https://model-checking.github.io/kani/tutorial-loop-unwinding.html
    //
    // Unfortunately what it means to "loop" is pretty opaque ... in this case
    // there appear to be loops in memcmp, which I guess comes from assert_eq!,
    // though I didn't see any failures until I added the to_signed() test.
    // Further confusing the issue, a value of 2 works fine on my system, but on
    // CI it fails, so we need to set it higher.
    #[kani::unwind(4)]
    #[kani::proof]
    fn u_amount_add_homomorphic() {
        let n1 = kani::any::<u64>();
        let n2 = kani::any::<u64>();
        kani::assume(n1.checked_add(n2).is_some()); // assume we don't overflow in the actual test
        assert_eq!(Amount::from_sat(n1) + Amount::from_sat(n2), Amount::from_sat(n1 + n2));

        let mut amt = Amount::from_sat(n1);
        amt += Amount::from_sat(n2);
        assert_eq!(amt, Amount::from_sat(n1 + n2));

        let max = cmp::max(n1, n2);
        let min = cmp::min(n1, n2);
        assert_eq!(Amount::from_sat(max) - Amount::from_sat(min), Amount::from_sat(max - min));

        let mut amt = Amount::from_sat(max);
        amt -= Amount::from_sat(min);
        assert_eq!(amt, Amount::from_sat(max - min));

        assert_eq!(
            Amount::from_sat(n1).to_signed(),
            if n1 <= i64::MAX as u64 {
                Ok(SignedAmount::from_sat(n1.try_into().unwrap()))
            } else {
                Err(ParseAmountError::TooBig)
            },
        );
    }

    #[kani::unwind(4)]
    #[kani::proof]
    fn u_amount_add_homomorphic_checked() {
        let n1 = kani::any::<u64>();
        let n2 = kani::any::<u64>();
        assert_eq!(
            Amount::from_sat(n1).checked_add(Amount::from_sat(n2)),
            n1.checked_add(n2).map(Amount::from_sat),
        );
        assert_eq!(
            Amount::from_sat(n1).checked_sub(Amount::from_sat(n2)),
            n1.checked_sub(n2).map(Amount::from_sat),
        );
    }

    #[kani::unwind(4)]
    #[kani::proof]
    fn s_amount_add_homomorphic() {
        let n1 = kani::any::<i64>();
        let n2 = kani::any::<i64>();
        kani::assume(n1.checked_add(n2).is_some()); // assume we don't overflow in the actual test
        kani::assume(n1.checked_sub(n2).is_some()); // assume we don't overflow in the actual test
        assert_eq!(
            SignedAmount::from_sat(n1) + SignedAmount::from_sat(n2),
            SignedAmount::from_sat(n1 + n2)
        );
        assert_eq!(
            SignedAmount::from_sat(n1) - SignedAmount::from_sat(n2),
            SignedAmount::from_sat(n1 - n2)
        );

        let mut amt = SignedAmount::from_sat(n1);
        amt += SignedAmount::from_sat(n2);
        assert_eq!(amt, SignedAmount::from_sat(n1 + n2));
        let mut amt = SignedAmount::from_sat(n1);
        amt -= SignedAmount::from_sat(n2);
        assert_eq!(amt, SignedAmount::from_sat(n1 - n2));

        assert_eq!(
            SignedAmount::from_sat(n1).to_unsigned(),
            if n1 >= 0 {
                Ok(Amount::from_sat(n1.try_into().unwrap()))
            } else {
                Err(ParseAmountError::Negative)
            },
        );
    }

    #[kani::unwind(4)]
    #[kani::proof]
    fn s_amount_add_homomorphic_checked() {
        let n1 = kani::any::<i64>();
        let n2 = kani::any::<i64>();
        assert_eq!(
            SignedAmount::from_sat(n1).checked_add(SignedAmount::from_sat(n2)),
            n1.checked_add(n2).map(SignedAmount::from_sat),
        );
        assert_eq!(
            SignedAmount::from_sat(n1).checked_sub(SignedAmount::from_sat(n2)),
            n1.checked_sub(n2).map(SignedAmount::from_sat),
        );

        assert_eq!(
            SignedAmount::from_sat(n1).positive_sub(SignedAmount::from_sat(n2)),
            if n1 >= 0 && n2 >= 0 && n1 >= n2 {
                Some(SignedAmount::from_sat(n1 - n2))
            } else {
                None
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;
    #[cfg(feature = "std")]
    use std::panic;

    #[cfg(feature = "serde")]
    use serde_test;

    use super::*;

    #[test]
    fn from_str_zero() {
        let denoms = vec!["BTC", "mBTC", "uBTC", "nBTC", "pBTC", "bits", "sats", "msats"];
        for denom in denoms {
            for v in &["0", "000"] {
                let s = format!("{} {}", v, denom);
                match Amount::from_str(&s) {
                    Err(e) => panic!("Failed to crate amount from {}: {:?}", s, e),
                    Ok(amount) => assert_eq!(amount, Amount::from_sat(0)),
                }
            }

            let s = format!("-0 {}", denom);
            match Amount::from_str(&s) {
                Err(e) => assert_eq!(e, ParseAmountError::Negative),
                Ok(_) => panic!("Unsigned amount from {}", s),
            }
            match SignedAmount::from_str(&s) {
                Err(e) => panic!("Failed to crate amount from {}: {:?}", s, e),
                Ok(amount) => assert_eq!(amount, SignedAmount::from_sat(0)),
            }
        }
    }

    #[test]
    fn mul_div() {
        let sat = Amount::from_sat;
        let ssat = SignedAmount::from_sat;

        assert_eq!(sat(14) * 3, sat(42));
        assert_eq!(sat(14) / 2, sat(7));
        assert_eq!(sat(14) % 3, sat(2));
        assert_eq!(ssat(-14) * 3, ssat(-42));
        assert_eq!(ssat(-14) / 2, ssat(-7));
        assert_eq!(ssat(-14) % 3, ssat(-2));

        let mut b = ssat(30);
        b /= 3;
        assert_eq!(b, ssat(10));
        b %= 3;
        assert_eq!(b, ssat(1));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_overflows() {
        // panic on overflow
        let result = panic::catch_unwind(|| Amount::max_value() + Amount::from_sat(1));
        assert!(result.is_err());
        let result = panic::catch_unwind(|| Amount::from_sat(8446744073709551615) * 3);
        assert!(result.is_err());
    }

    #[test]
    fn checked_arithmetic() {
        let sat = Amount::from_sat;
        let ssat = SignedAmount::from_sat;

        assert_eq!(SignedAmount::max_value().checked_add(ssat(1)), None);
        assert_eq!(SignedAmount::min_value().checked_sub(ssat(1)), None);
        assert_eq!(Amount::max_value().checked_add(sat(1)), None);
        assert_eq!(Amount::min_value().checked_sub(sat(1)), None);

        assert_eq!(sat(5).checked_div(2), Some(sat(2))); // integer division
        assert_eq!(ssat(-6).checked_div(2), Some(ssat(-3)));
    }

    #[test]
    fn floating_point() {
        use super::Denomination as D;
        let f = Amount::from_float_in;
        let sf = SignedAmount::from_float_in;
        let sat = Amount::from_sat;
        let ssat = SignedAmount::from_sat;

        assert_eq!(f(11.22, D::Bitcoin), Ok(sat(1122000000)));
        assert_eq!(sf(-11.22, D::MilliBitcoin), Ok(ssat(-1122000)));
        assert_eq!(f(11.22, D::Bit), Ok(sat(1122)));
        assert_eq!(sf(-1000.0, D::MilliSatoshi), Ok(ssat(-1)));
        assert_eq!(f(0.0001234, D::Bitcoin), Ok(sat(12340)));
        assert_eq!(sf(-0.00012345, D::Bitcoin), Ok(ssat(-12345)));

        assert_eq!(f(-100.0, D::MilliSatoshi), Err(ParseAmountError::Negative));
        assert_eq!(f(11.22, D::Satoshi), Err(ParseAmountError::TooPrecise));
        assert_eq!(sf(-100.0, D::MilliSatoshi), Err(ParseAmountError::TooPrecise));
        assert_eq!(sf(-100.0, D::MilliSatoshi), Err(ParseAmountError::TooPrecise));
        assert_eq!(f(42.123456781, D::Bitcoin), Err(ParseAmountError::TooPrecise));
        assert_eq!(sf(-184467440738.0, D::Bitcoin), Err(ParseAmountError::TooBig));
        assert_eq!(f(18446744073709551617.0, D::Satoshi), Err(ParseAmountError::TooBig));
        assert_eq!(
            f(SignedAmount::max_value().to_float_in(D::Satoshi) + 1.0, D::Satoshi),
            Err(ParseAmountError::TooBig)
        );
        assert_eq!(
            f(Amount::max_value().to_float_in(D::Satoshi) + 1.0, D::Satoshi),
            Err(ParseAmountError::TooBig)
        );

        let btc = move |f| SignedAmount::from_btc(f).unwrap();
        assert_eq!(btc(2.5).to_float_in(D::Bitcoin), 2.5);
        assert_eq!(btc(-2.5).to_float_in(D::MilliBitcoin), -2500.0);
        assert_eq!(btc(2.5).to_float_in(D::Satoshi), 250000000.0);
        assert_eq!(btc(-2.5).to_float_in(D::MilliSatoshi), -250000000000.0);

        let btc = move |f| Amount::from_btc(f).unwrap();
        assert_eq!(&btc(0.0012).to_float_in(D::Bitcoin).to_string(), "0.0012")
    }

    #[test]
    #[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
    fn parsing() {
        use super::ParseAmountError as E;
        let btc = Denomination::Bitcoin;
        let sat = Denomination::Satoshi;
        let p = Amount::from_str_in;
        let sp = SignedAmount::from_str_in;

        assert_eq!(p("x", btc), Err(E::InvalidCharacter('x')));
        assert_eq!(p("-", btc), Err(E::InvalidFormat));
        assert_eq!(sp("-", btc), Err(E::InvalidFormat));
        assert_eq!(p("-1.0x", btc), Err(E::InvalidCharacter('x')));
        assert_eq!(p("0.0 ", btc), Err(ParseAmountError::InvalidCharacter(' ')));
        assert_eq!(p("0.000.000", btc), Err(E::InvalidFormat));
        let more_than_max = format!("1{}", Amount::max_value());
        assert_eq!(p(&more_than_max, btc), Err(E::TooBig));
        assert_eq!(p("0.000000042", btc), Err(E::TooPrecise));

        assert_eq!(p("1", btc), Ok(Amount::from_sat(1_000_000_00)));
        assert_eq!(sp("-.5", btc), Ok(SignedAmount::from_sat(-500_000_00)));
        assert_eq!(p("1.1", btc), Ok(Amount::from_sat(1_100_000_00)));
        assert_eq!(p("100", sat), Ok(Amount::from_sat(100)));
        assert_eq!(p("55", sat), Ok(Amount::from_sat(55)));
        assert_eq!(p("5500000000000000000", sat), Ok(Amount::from_sat(55_000_000_000_000_000_00)));
        // Should this even pass?
        assert_eq!(p("5500000000000000000.", sat), Ok(Amount::from_sat(55_000_000_000_000_000_00)));
        assert_eq!(
            p("12345678901.12345678", btc),
            Ok(Amount::from_sat(12_345_678_901__123_456_78))
        );

        // make sure satoshi > i64::max_value() is checked.
        let amount = Amount::from_sat(i64::max_value() as u64);
        assert_eq!(Amount::from_str_in(&amount.to_string_in(sat), sat), Ok(amount));
        assert_eq!(
            Amount::from_str_in(&(amount + Amount(1)).to_string_in(sat), sat),
            Err(E::TooBig)
        );

        assert_eq!(p("12.000", Denomination::MilliSatoshi), Err(E::TooPrecise));
        // exactly 50 chars.
        assert_eq!(
            p("100000000000000.0000000000000000000000000000000000", Denomination::Bitcoin),
            Err(E::TooBig)
        );
        // more than 50 chars.
        assert_eq!(
            p("100000000000000.00000000000000000000000000000000000", Denomination::Bitcoin),
            Err(E::InputTooLarge)
        );
    }

    #[test]
    fn to_string() {
        use super::Denomination as D;

        assert_eq!(Amount::ONE_BTC.to_string_in(D::Bitcoin), "1");
        assert_eq!(format!("{:.8}", Amount::ONE_BTC.display_in(D::Bitcoin)), "1.00000000");
        assert_eq!(Amount::ONE_BTC.to_string_in(D::Satoshi), "100000000");
        assert_eq!(Amount::ONE_SAT.to_string_in(D::Bitcoin), "0.00000001");
        assert_eq!(SignedAmount::from_sat(-42).to_string_in(D::Bitcoin), "-0.00000042");

        assert_eq!(Amount::ONE_BTC.to_string_with_denomination(D::Bitcoin), "1 BTC");
        assert_eq!(Amount::ONE_SAT.to_string_with_denomination(D::MilliSatoshi), "1000 msat");
        assert_eq!(
            SignedAmount::ONE_BTC.to_string_with_denomination(D::Satoshi),
            "100000000 satoshi"
        );
        assert_eq!(Amount::ONE_SAT.to_string_with_denomination(D::Bitcoin), "0.00000001 BTC");
        assert_eq!(
            SignedAmount::from_sat(-42).to_string_with_denomination(D::Bitcoin),
            "-0.00000042 BTC"
        );
    }

    // May help identify a problem sooner
    #[test]
    fn test_repeat_char() {
        let mut buf = String::new();
        repeat_char(&mut buf, '0', 0).unwrap();
        assert_eq!(buf.len(), 0);
        repeat_char(&mut buf, '0', 42).unwrap();
        assert_eq!(buf.len(), 42);
        assert!(buf.chars().all(|c| c == '0'));
    }

    // Creates individual test functions to make it easier to find which check failed.
    macro_rules! check_format_non_negative {
        ($denom:ident; $($test_name:ident, $val:literal, $format_string:literal, $expected:literal);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    assert_eq!(format!($format_string, Amount::from_sat($val).display_in(Denomination::$denom)), $expected);
                    assert_eq!(format!($format_string, SignedAmount::from_sat($val as i64).display_in(Denomination::$denom)), $expected);
                }
            )*
        }
    }

    macro_rules! check_format_non_negative_show_denom {
        ($denom:ident, $denom_suffix:literal; $($test_name:ident, $val:literal, $format_string:literal, $expected:literal);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    assert_eq!(format!($format_string, Amount::from_sat($val).display_in(Denomination::$denom).show_denomination()), concat!($expected, $denom_suffix));
                    assert_eq!(format!($format_string, SignedAmount::from_sat($val as i64).display_in(Denomination::$denom).show_denomination()), concat!($expected, $denom_suffix));
                }
            )*
        }
    }

    check_format_non_negative! {
        Satoshi;
        sat_check_fmt_non_negative_0, 0, "{}", "0";
        sat_check_fmt_non_negative_1, 0, "{:2}", " 0";
        sat_check_fmt_non_negative_2, 0, "{:02}", "00";
        sat_check_fmt_non_negative_3, 0, "{:.1}", "0.0";
        sat_check_fmt_non_negative_4, 0, "{:4.1}", " 0.0";
        sat_check_fmt_non_negative_5, 0, "{:04.1}", "00.0";
        sat_check_fmt_non_negative_6, 1, "{}", "1";
        sat_check_fmt_non_negative_7, 1, "{:2}", " 1";
        sat_check_fmt_non_negative_8, 1, "{:02}", "01";
        sat_check_fmt_non_negative_9, 1, "{:.1}", "1.0";
        sat_check_fmt_non_negative_10, 1, "{:4.1}", " 1.0";
        sat_check_fmt_non_negative_11, 1, "{:04.1}", "01.0";
        sat_check_fmt_non_negative_12, 10, "{}", "10";
        sat_check_fmt_non_negative_13, 10, "{:2}", "10";
        sat_check_fmt_non_negative_14, 10, "{:02}", "10";
        sat_check_fmt_non_negative_15, 10, "{:3}", " 10";
        sat_check_fmt_non_negative_16, 10, "{:03}", "010";
        sat_check_fmt_non_negative_17, 10, "{:.1}", "10.0";
        sat_check_fmt_non_negative_18, 10, "{:5.1}", " 10.0";
        sat_check_fmt_non_negative_19, 10, "{:05.1}", "010.0";
        sat_check_fmt_non_negative_20, 1, "{:<2}", "1 ";
        sat_check_fmt_non_negative_21, 1, "{:<02}", "01";
        sat_check_fmt_non_negative_22, 1, "{:<3.1}", "1.0";
        sat_check_fmt_non_negative_23, 1, "{:<4.1}", "1.0 ";
    }

    check_format_non_negative_show_denom! {
        Satoshi, " satoshi";
        sat_check_fmt_non_negative_show_denom_0, 0, "{}", "0";
        sat_check_fmt_non_negative_show_denom_1, 0, "{:2}", "0";
        sat_check_fmt_non_negative_show_denom_2, 0, "{:02}", "0";
        sat_check_fmt_non_negative_show_denom_3, 0, "{:9}", "0";
        sat_check_fmt_non_negative_show_denom_4, 0, "{:09}", "0";
        sat_check_fmt_non_negative_show_denom_5, 0, "{:10}", " 0";
        sat_check_fmt_non_negative_show_denom_6, 0, "{:010}", "00";
        sat_check_fmt_non_negative_show_denom_7, 0, "{:.1}", "0.0";
        sat_check_fmt_non_negative_show_denom_8, 0, "{:11.1}", "0.0";
        sat_check_fmt_non_negative_show_denom_9, 0, "{:011.1}", "0.0";
        sat_check_fmt_non_negative_show_denom_10, 0, "{:12.1}", " 0.0";
        sat_check_fmt_non_negative_show_denom_11, 0, "{:012.1}", "00.0";
        sat_check_fmt_non_negative_show_denom_12, 1, "{}", "1";
        sat_check_fmt_non_negative_show_denom_13, 1, "{:10}", " 1";
        sat_check_fmt_non_negative_show_denom_14, 1, "{:010}", "01";
        sat_check_fmt_non_negative_show_denom_15, 1, "{:.1}", "1.0";
        sat_check_fmt_non_negative_show_denom_16, 1, "{:12.1}", " 1.0";
        sat_check_fmt_non_negative_show_denom_17, 1, "{:012.1}", "01.0";
        sat_check_fmt_non_negative_show_denom_18, 10, "{}", "10";
        sat_check_fmt_non_negative_show_denom_19, 10, "{:10}", "10";
        sat_check_fmt_non_negative_show_denom_20, 10, "{:010}", "10";
        sat_check_fmt_non_negative_show_denom_21, 10, "{:11}", " 10";
        sat_check_fmt_non_negative_show_denom_22, 10, "{:011}", "010";
    }

    check_format_non_negative! {
        Bitcoin;
        btc_check_fmt_non_negative_0, 0, "{}", "0";
        btc_check_fmt_non_negative_1, 0, "{:2}", " 0";
        btc_check_fmt_non_negative_2, 0, "{:02}", "00";
        btc_check_fmt_non_negative_3, 0, "{:.1}", "0.0";
        btc_check_fmt_non_negative_4, 0, "{:4.1}", " 0.0";
        btc_check_fmt_non_negative_5, 0, "{:04.1}", "00.0";
        btc_check_fmt_non_negative_6, 1, "{}", "0.00000001";
        btc_check_fmt_non_negative_7, 1, "{:2}", "0.00000001";
        btc_check_fmt_non_negative_8, 1, "{:02}", "0.00000001";
        btc_check_fmt_non_negative_9, 1, "{:.1}", "0.00000001";
        btc_check_fmt_non_negative_10, 1, "{:11}", " 0.00000001";
        btc_check_fmt_non_negative_11, 1, "{:11.1}", " 0.00000001";
        btc_check_fmt_non_negative_12, 1, "{:011.1}", "00.00000001";
        btc_check_fmt_non_negative_13, 1, "{:.9}", "0.000000010";
        btc_check_fmt_non_negative_14, 1, "{:11.9}", "0.000000010";
        btc_check_fmt_non_negative_15, 1, "{:011.9}", "0.000000010";
        btc_check_fmt_non_negative_16, 1, "{:12.9}", " 0.000000010";
        btc_check_fmt_non_negative_17, 1, "{:012.9}", "00.000000010";
        btc_check_fmt_non_negative_18, 100_000_000, "{}", "1";
        btc_check_fmt_non_negative_19, 100_000_000, "{:2}", " 1";
        btc_check_fmt_non_negative_20, 100_000_000, "{:02}", "01";
        btc_check_fmt_non_negative_21, 100_000_000, "{:.1}", "1.0";
        btc_check_fmt_non_negative_22, 100_000_000, "{:4.1}", " 1.0";
        btc_check_fmt_non_negative_23, 100_000_000, "{:04.1}", "01.0";
        btc_check_fmt_non_negative_24, 110_000_000, "{}", "1.1";
        btc_check_fmt_non_negative_25, 100_000_001, "{}", "1.00000001";
        btc_check_fmt_non_negative_26, 100_000_001, "{:1}", "1.00000001";
        btc_check_fmt_non_negative_27, 100_000_001, "{:.1}", "1.00000001";
        btc_check_fmt_non_negative_28, 100_000_001, "{:10}", "1.00000001";
        btc_check_fmt_non_negative_29, 100_000_001, "{:11}", " 1.00000001";
        btc_check_fmt_non_negative_30, 100_000_001, "{:011}", "01.00000001";
        btc_check_fmt_non_negative_31, 100_000_001, "{:.8}", "1.00000001";
        btc_check_fmt_non_negative_32, 100_000_001, "{:.9}", "1.000000010";
        btc_check_fmt_non_negative_33, 100_000_001, "{:11.9}", "1.000000010";
        btc_check_fmt_non_negative_34, 100_000_001, "{:12.9}", " 1.000000010";
        btc_check_fmt_non_negative_35, 100_000_001, "{:012.9}", "01.000000010";
        btc_check_fmt_non_negative_36, 100_000_001, "{:+011.8}", "+1.00000001";
        btc_check_fmt_non_negative_37, 100_000_001, "{:+12.8}", " +1.00000001";
        btc_check_fmt_non_negative_38, 100_000_001, "{:+012.8}", "+01.00000001";
        btc_check_fmt_non_negative_39, 100_000_001, "{:+12.9}", "+1.000000010";
        btc_check_fmt_non_negative_40, 100_000_001, "{:+012.9}", "+1.000000010";
        btc_check_fmt_non_negative_41, 100_000_001, "{:+13.9}", " +1.000000010";
        btc_check_fmt_non_negative_42, 100_000_001, "{:+013.9}", "+01.000000010";
        btc_check_fmt_non_negative_43, 100_000_001, "{:<10}", "1.00000001";
        btc_check_fmt_non_negative_44, 100_000_001, "{:<11}", "1.00000001 ";
        btc_check_fmt_non_negative_45, 100_000_001, "{:<011}", "01.00000001";
        btc_check_fmt_non_negative_46, 100_000_001, "{:<11.9}", "1.000000010";
        btc_check_fmt_non_negative_47, 100_000_001, "{:<12.9}", "1.000000010 ";
        btc_check_fmt_non_negative_48, 100_000_001, "{:<12}", "1.00000001  ";
        btc_check_fmt_non_negative_49, 100_000_001, "{:^11}", "1.00000001 ";
        btc_check_fmt_non_negative_50, 100_000_001, "{:^11.9}", "1.000000010";
        btc_check_fmt_non_negative_51, 100_000_001, "{:^12.9}", "1.000000010 ";
        btc_check_fmt_non_negative_52, 100_000_001, "{:^12}", " 1.00000001 ";
        btc_check_fmt_non_negative_53, 100_000_001, "{:^12.9}", "1.000000010 ";
        btc_check_fmt_non_negative_54, 100_000_001, "{:^13.9}", " 1.000000010 ";
    }

    check_format_non_negative_show_denom! {
        Bitcoin, " BTC";
        btc_check_fmt_non_negative_show_denom_0, 1, "{:14.1}", "0.00000001";
        btc_check_fmt_non_negative_show_denom_1, 1, "{:14.8}", "0.00000001";
        btc_check_fmt_non_negative_show_denom_2, 1, "{:15}", " 0.00000001";
        btc_check_fmt_non_negative_show_denom_3, 1, "{:015}", "00.00000001";
        btc_check_fmt_non_negative_show_denom_4, 1, "{:.9}", "0.000000010";
        btc_check_fmt_non_negative_show_denom_5, 1, "{:15.9}", "0.000000010";
        btc_check_fmt_non_negative_show_denom_6, 1, "{:16.9}", " 0.000000010";
        btc_check_fmt_non_negative_show_denom_7, 1, "{:016.9}", "00.000000010";
    }

    check_format_non_negative_show_denom! {
        Bitcoin, " BTC ";
        btc_check_fmt_non_negative_show_denom_align_0, 1, "{:<15}", "0.00000001";
        btc_check_fmt_non_negative_show_denom_align_1, 1, "{:^15}", "0.00000001";
        btc_check_fmt_non_negative_show_denom_align_2, 1, "{:^16}", " 0.00000001";
    }

    check_format_non_negative! {
        MilliSatoshi;
        msat_check_fmt_non_negative_0, 0, "{}", "0";
        msat_check_fmt_non_negative_1, 1, "{}", "1000";
        msat_check_fmt_non_negative_2, 1, "{:5}", " 1000";
        msat_check_fmt_non_negative_3, 1, "{:05}", "01000";
        msat_check_fmt_non_negative_4, 1, "{:.1}", "1000.0";
        msat_check_fmt_non_negative_5, 1, "{:6.1}", "1000.0";
        msat_check_fmt_non_negative_6, 1, "{:06.1}", "1000.0";
        msat_check_fmt_non_negative_7, 1, "{:7.1}", " 1000.0";
        msat_check_fmt_non_negative_8, 1, "{:07.1}", "01000.0";
    }

    #[test]
    fn test_unsigned_signed_conversion() {
        use super::ParseAmountError as E;
        let sa = SignedAmount::from_sat;
        let ua = Amount::from_sat;

        assert_eq!(Amount::max_value().to_signed(), Err(E::TooBig));
        assert_eq!(ua(i64::max_value() as u64).to_signed(), Ok(sa(i64::max_value())));
        assert_eq!(ua(i64::max_value() as u64 + 1).to_signed(), Err(E::TooBig));

        assert_eq!(sa(i64::max_value()).to_unsigned(), Ok(ua(i64::max_value() as u64)));

        assert_eq!(
            sa(i64::max_value()).to_unsigned().unwrap().to_signed(),
            Ok(sa(i64::max_value()))
        );
    }

    #[test]
    #[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
    fn from_str() {
        use super::ParseAmountError as E;

        assert_eq!(Amount::from_str("x BTC"), Err(E::InvalidCharacter('x')));
        assert_eq!(Amount::from_str("xBTC"), Err(E::UnknownDenomination("xBTC".into())));
        assert_eq!(Amount::from_str("5 BTC BTC"), Err(E::UnknownDenomination("BTC BTC".into())));
        assert_eq!(Amount::from_str("5BTC BTC"), Err(E::InvalidCharacter('B')));
        assert_eq!(Amount::from_str("5 5 BTC"), Err(E::UnknownDenomination("5 BTC".into())));

        #[cfg_attr(rust_v_1_46, track_caller)]
        fn case(s: &str, expected: Result<Amount, ParseAmountError>) {
            assert_eq!(Amount::from_str(s), expected);
            assert_eq!(Amount::from_str(&s.replace(' ', "")), expected);
        }

        #[cfg_attr(rust_v_1_46, track_caller)]
        fn scase(s: &str, expected: Result<SignedAmount, ParseAmountError>) {
            assert_eq!(SignedAmount::from_str(s), expected);
            assert_eq!(SignedAmount::from_str(&s.replace(' ', "")), expected);
        }

        case("5 BCH", Err(E::UnknownDenomination("BCH".to_owned())));

        case("-1 BTC", Err(E::Negative));
        case("-0.0 BTC", Err(E::Negative));
        case("0.123456789 BTC", Err(E::TooPrecise));
        scase("-0.1 satoshi", Err(E::TooPrecise));
        case("0.123456 mBTC", Err(E::TooPrecise));
        scase("-1.001 bits", Err(E::TooPrecise));
        scase("-200000000000 BTC", Err(E::TooBig));
        case("18446744073709551616 sat", Err(E::TooBig));

        case(".5 bits", Ok(Amount::from_sat(50)));
        scase("-.5 bits", Ok(SignedAmount::from_sat(-50)));
        case("0.00253583 BTC", Ok(Amount::from_sat(253583)));
        scase("-5 satoshi", Ok(SignedAmount::from_sat(-5)));
        case("0.10000000 BTC", Ok(Amount::from_sat(100_000_00)));
        scase("-100 bits", Ok(SignedAmount::from_sat(-10_000)));
    }

    #[test]
    #[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
    fn to_from_string_in() {
        use super::Denomination as D;
        let ua_str = Amount::from_str_in;
        let ua_sat = Amount::from_sat;
        let sa_str = SignedAmount::from_str_in;
        let sa_sat = SignedAmount::from_sat;

        assert_eq!("0.5", Amount::from_sat(50).to_string_in(D::Bit));
        assert_eq!("-0.5", SignedAmount::from_sat(-50).to_string_in(D::Bit));
        assert_eq!("0.00253583", Amount::from_sat(253583).to_string_in(D::Bitcoin));
        assert_eq!("-5", SignedAmount::from_sat(-5).to_string_in(D::Satoshi));
        assert_eq!("0.1", Amount::from_sat(100_000_00).to_string_in(D::Bitcoin));
        assert_eq!("-100", SignedAmount::from_sat(-10_000).to_string_in(D::Bit));
        assert_eq!("2535830", Amount::from_sat(253583).to_string_in(D::NanoBitcoin));
        assert_eq!("-100000", SignedAmount::from_sat(-10_000).to_string_in(D::NanoBitcoin));
        assert_eq!("2535830000", Amount::from_sat(253583).to_string_in(D::PicoBitcoin));
        assert_eq!("-100000000", SignedAmount::from_sat(-10_000).to_string_in(D::PicoBitcoin));

        assert_eq!("0.50", format!("{:.2}", Amount::from_sat(50).display_in(D::Bit)));
        assert_eq!("-0.50", format!("{:.2}", SignedAmount::from_sat(-50).display_in(D::Bit)));
        assert_eq!(
            "0.10000000",
            format!("{:.8}", Amount::from_sat(100_000_00).display_in(D::Bitcoin))
        );
        assert_eq!("-100.00", format!("{:.2}", SignedAmount::from_sat(-10_000).display_in(D::Bit)));

        assert_eq!(ua_str(&ua_sat(0).to_string_in(D::Satoshi), D::Satoshi), Ok(ua_sat(0)));
        assert_eq!(ua_str(&ua_sat(500).to_string_in(D::Bitcoin), D::Bitcoin), Ok(ua_sat(500)));
        assert_eq!(
            ua_str(&ua_sat(21_000_000).to_string_in(D::Bit), D::Bit),
            Ok(ua_sat(21_000_000))
        );
        assert_eq!(
            ua_str(&ua_sat(1).to_string_in(D::MicroBitcoin), D::MicroBitcoin),
            Ok(ua_sat(1))
        );
        assert_eq!(
            ua_str(&ua_sat(1_000_000_000_000).to_string_in(D::MilliBitcoin), D::MilliBitcoin),
            Ok(ua_sat(1_000_000_000_000))
        );
        assert_eq!(
            ua_str(&ua_sat(u64::max_value()).to_string_in(D::MilliBitcoin), D::MilliBitcoin),
            Err(ParseAmountError::TooBig)
        );

        assert_eq!(
            sa_str(&sa_sat(-1).to_string_in(D::MicroBitcoin), D::MicroBitcoin),
            Ok(sa_sat(-1))
        );

        assert_eq!(
            sa_str(&sa_sat(i64::max_value()).to_string_in(D::Satoshi), D::MicroBitcoin),
            Err(ParseAmountError::TooBig)
        );
        // Test an overflow bug in `abs()`
        assert_eq!(
            sa_str(&sa_sat(i64::min_value()).to_string_in(D::Satoshi), D::MicroBitcoin),
            Err(ParseAmountError::TooBig)
        );

        assert_eq!(
            sa_str(&sa_sat(-1).to_string_in(D::NanoBitcoin), D::NanoBitcoin),
            Ok(sa_sat(-1))
        );
        assert_eq!(
            sa_str(&sa_sat(i64::max_value()).to_string_in(D::Satoshi), D::NanoBitcoin),
            Err(ParseAmountError::TooPrecise)
        );
        assert_eq!(
            sa_str(&sa_sat(i64::min_value()).to_string_in(D::Satoshi), D::NanoBitcoin),
            Err(ParseAmountError::TooPrecise)
        );

        assert_eq!(
            sa_str(&sa_sat(-1).to_string_in(D::PicoBitcoin), D::PicoBitcoin),
            Ok(sa_sat(-1))
        );
        assert_eq!(
            sa_str(&sa_sat(i64::max_value()).to_string_in(D::Satoshi), D::PicoBitcoin),
            Err(ParseAmountError::TooPrecise)
        );
        assert_eq!(
            sa_str(&sa_sat(i64::min_value()).to_string_in(D::Satoshi), D::PicoBitcoin),
            Err(ParseAmountError::TooPrecise)
        );
    }

    #[test]
    fn to_string_with_denomination_from_str_roundtrip() {
        use super::Denomination as D;
        let amt = Amount::from_sat(42);
        let denom = Amount::to_string_with_denomination;
        assert_eq!(Amount::from_str(&denom(amt, D::Bitcoin)), Ok(amt));
        assert_eq!(Amount::from_str(&denom(amt, D::MilliBitcoin)), Ok(amt));
        assert_eq!(Amount::from_str(&denom(amt, D::MicroBitcoin)), Ok(amt));
        assert_eq!(Amount::from_str(&denom(amt, D::Bit)), Ok(amt));
        assert_eq!(Amount::from_str(&denom(amt, D::Satoshi)), Ok(amt));
        assert_eq!(Amount::from_str(&denom(amt, D::NanoBitcoin)), Ok(amt));
        assert_eq!(Amount::from_str(&denom(amt, D::MilliSatoshi)), Ok(amt));
        assert_eq!(Amount::from_str(&denom(amt, D::PicoBitcoin)), Ok(amt));

        assert_eq!(
            Amount::from_str("42 satoshi BTC"),
            Err(ParseAmountError::UnknownDenomination("satoshi BTC".into())),
        );
        assert_eq!(
            SignedAmount::from_str("-42 satoshi BTC"),
            Err(ParseAmountError::UnknownDenomination("satoshi BTC".into())),
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_sat() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        #[serde(crate = "actual_serde")]
        struct T {
            #[serde(with = "crate::amount::serde::as_sat")]
            pub amt: Amount,
            #[serde(with = "crate::amount::serde::as_sat")]
            pub samt: SignedAmount,
        }

        serde_test::assert_tokens(
            &T { amt: Amount::from_sat(123456789), samt: SignedAmount::from_sat(-123456789) },
            &[
                serde_test::Token::Struct { name: "T", len: 2 },
                serde_test::Token::Str("amt"),
                serde_test::Token::U64(123456789),
                serde_test::Token::Str("samt"),
                serde_test::Token::I64(-123456789),
                serde_test::Token::StructEnd,
            ],
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    #[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
    fn serde_as_btc() {
        use serde_json;

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        #[serde(crate = "actual_serde")]
        struct T {
            #[serde(with = "crate::amount::serde::as_btc")]
            pub amt: Amount,
            #[serde(with = "crate::amount::serde::as_btc")]
            pub samt: SignedAmount,
        }

        let orig = T {
            amt: Amount::from_sat(21_000_000__000_000_01),
            samt: SignedAmount::from_sat(-21_000_000__000_000_01),
        };

        let json = "{\"amt\": 21000000.00000001, \
                    \"samt\": -21000000.00000001}";
        let t: T = serde_json::from_str(json).unwrap();
        assert_eq!(t, orig);

        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(t, serde_json::from_value(value).unwrap());

        // errors
        let t: Result<T, serde_json::Error> =
            serde_json::from_str("{\"amt\": 1000000.000000001, \"samt\": 1}");
        assert!(t.unwrap_err().to_string().contains(&ParseAmountError::TooPrecise.to_string()));
        let t: Result<T, serde_json::Error> = serde_json::from_str("{\"amt\": -1, \"samt\": 1}");
        assert!(t.unwrap_err().to_string().contains(&ParseAmountError::Negative.to_string()));
    }

    #[cfg(feature = "serde")]
    #[test]
    #[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
    fn serde_as_btc_opt() {
        use serde_json;

        #[derive(Serialize, Deserialize, PartialEq, Debug, Eq)]
        #[serde(crate = "actual_serde")]
        struct T {
            #[serde(default, with = "crate::amount::serde::as_btc::opt")]
            pub amt: Option<Amount>,
            #[serde(default, with = "crate::amount::serde::as_btc::opt")]
            pub samt: Option<SignedAmount>,
        }

        let with = T {
            amt: Some(Amount::from_sat(2_500_000_00)),
            samt: Some(SignedAmount::from_sat(-2_500_000_00)),
        };
        let without = T { amt: None, samt: None };

        // Test Roundtripping
        for s in [&with, &without].iter() {
            let v = serde_json::to_string(s).unwrap();
            let w: T = serde_json::from_str(&v).unwrap();
            assert_eq!(w, **s);
        }

        let t: T = serde_json::from_str("{\"amt\": 2.5, \"samt\": -2.5}").unwrap();
        assert_eq!(t, with);

        let t: T = serde_json::from_str("{}").unwrap();
        assert_eq!(t, without);

        let value_with: serde_json::Value =
            serde_json::from_str("{\"amt\": 2.5, \"samt\": -2.5}").unwrap();
        assert_eq!(with, serde_json::from_value(value_with).unwrap());

        let value_without: serde_json::Value = serde_json::from_str("{}").unwrap();
        assert_eq!(without, serde_json::from_value(value_without).unwrap());
    }

    #[cfg(feature = "serde")]
    #[test]
    #[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
    fn serde_as_sat_opt() {
        use serde_json;

        #[derive(Serialize, Deserialize, PartialEq, Debug, Eq)]
        #[serde(crate = "actual_serde")]
        struct T {
            #[serde(default, with = "crate::amount::serde::as_sat::opt")]
            pub amt: Option<Amount>,
            #[serde(default, with = "crate::amount::serde::as_sat::opt")]
            pub samt: Option<SignedAmount>,
        }

        let with = T {
            amt: Some(Amount::from_sat(2_500_000_00)),
            samt: Some(SignedAmount::from_sat(-2_500_000_00)),
        };
        let without = T { amt: None, samt: None };

        // Test Roundtripping
        for s in [&with, &without].iter() {
            let v = serde_json::to_string(s).unwrap();
            let w: T = serde_json::from_str(&v).unwrap();
            assert_eq!(w, **s);
        }

        let t: T = serde_json::from_str("{\"amt\": 250000000, \"samt\": -250000000}").unwrap();
        assert_eq!(t, with);

        let t: T = serde_json::from_str("{}").unwrap();
        assert_eq!(t, without);

        let value_with: serde_json::Value =
            serde_json::from_str("{\"amt\": 250000000, \"samt\": -250000000}").unwrap();
        assert_eq!(with, serde_json::from_value(value_with).unwrap());

        let value_without: serde_json::Value = serde_json::from_str("{}").unwrap();
        assert_eq!(without, serde_json::from_value(value_without).unwrap());
    }

    #[test]
    fn sum_amounts() {
        assert_eq!(Amount::from_sat(0), vec![].into_iter().sum::<Amount>());
        assert_eq!(SignedAmount::from_sat(0), vec![].into_iter().sum::<SignedAmount>());

        let amounts = vec![Amount::from_sat(42), Amount::from_sat(1337), Amount::from_sat(21)];
        let sum = amounts.into_iter().sum::<Amount>();
        assert_eq!(Amount::from_sat(1400), sum);

        let amounts = vec![
            SignedAmount::from_sat(-42),
            SignedAmount::from_sat(1337),
            SignedAmount::from_sat(21),
        ];
        let sum = amounts.into_iter().sum::<SignedAmount>();
        assert_eq!(SignedAmount::from_sat(1316), sum);
    }

    #[test]
    fn checked_sum_amounts() {
        assert_eq!(Some(Amount::from_sat(0)), vec![].into_iter().checked_sum());
        assert_eq!(Some(SignedAmount::from_sat(0)), vec![].into_iter().checked_sum());

        let amounts = vec![Amount::from_sat(42), Amount::from_sat(1337), Amount::from_sat(21)];
        let sum = amounts.into_iter().checked_sum();
        assert_eq!(Some(Amount::from_sat(1400)), sum);

        let amounts =
            vec![Amount::from_sat(u64::max_value()), Amount::from_sat(1337), Amount::from_sat(21)];
        let sum = amounts.into_iter().checked_sum();
        assert_eq!(None, sum);

        let amounts = vec![
            SignedAmount::from_sat(i64::min_value()),
            SignedAmount::from_sat(-1),
            SignedAmount::from_sat(21),
        ];
        let sum = amounts.into_iter().checked_sum();
        assert_eq!(None, sum);

        let amounts = vec![
            SignedAmount::from_sat(i64::max_value()),
            SignedAmount::from_sat(1),
            SignedAmount::from_sat(21),
        ];
        let sum = amounts.into_iter().checked_sum();
        assert_eq!(None, sum);

        let amounts = vec![
            SignedAmount::from_sat(42),
            SignedAmount::from_sat(3301),
            SignedAmount::from_sat(21),
        ];
        let sum = amounts.into_iter().checked_sum();
        assert_eq!(Some(SignedAmount::from_sat(3364)), sum);
    }

    #[test]
    fn denomination_string_acceptable_forms() {
        // Non-exhaustive list of valid forms.
        let valid = vec![
            "BTC", "btc", "mBTC", "mbtc", "uBTC", "ubtc", "SATOSHI", "Satoshi", "Satoshis",
            "satoshis", "SAT", "Sat", "sats", "bit", "bits", "nBTC", "pBTC",
        ];
        for denom in valid.iter() {
            assert!(Denomination::from_str(denom).is_ok());
        }
    }

    #[test]
    fn disallow_confusing_forms() {
        // Non-exhaustive list of confusing forms.
        let confusing =
            vec!["Msat", "Msats", "MSAT", "MSATS", "MSat", "MSats", "MBTC", "Mbtc", "PBTC"];
        for denom in confusing.iter() {
            match Denomination::from_str(denom) {
                Ok(_) => panic!("from_str should error for {}", denom),
                Err(ParseAmountError::PossiblyConfusingDenomination(_)) => {}
                Err(e) => panic!("unexpected error: {}", e),
            }
        }
    }

    #[test]
    fn disallow_unknown_denomination() {
        // Non-exhaustive list of unknown forms.
        let unknown = vec!["NBTC", "UBTC", "ABC", "abc"];
        for denom in unknown.iter() {
            match Denomination::from_str(denom) {
                Ok(_) => panic!("from_str should error for {}", denom),
                Err(ParseAmountError::UnknownDenomination(_)) => {}
                Err(e) => panic!("unexpected error: {}", e),
            }
        }
    }
}
