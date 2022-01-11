// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Bitcoin amounts.
//!
//! This module mainly introduces the [Amount] and [SignedAmount] types.
//! We refer to the documentation on the types for more information.
//!

use prelude::*;

use core::{ops, default, str::FromStr, cmp::Ordering};
use core::fmt::{self, Write};

/// A set of denominations in which amounts can be expressed.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Denomination {
    /// BTC
    Bitcoin,
    /// mBTC
    MilliBitcoin,
    /// uBTC
    MicroBitcoin,
    /// bits
    Bit,
    /// satoshi
    Satoshi,
    /// msat
    MilliSatoshi,
}

impl Denomination {
    /// The number of decimal places more than a satoshi.
    fn precision(self) -> i32 {
        match self {
            Denomination::Bitcoin => -8,
            Denomination::MilliBitcoin => -5,
            Denomination::MicroBitcoin => -2,
            Denomination::Bit => -2,
            Denomination::Satoshi => 0,
            Denomination::MilliSatoshi => 3,
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            Denomination::Bitcoin => "BTC",
            Denomination::MilliBitcoin => "mBTC",
            Denomination::MicroBitcoin => "uBTC",
            Denomination::Bit => "bits",
            Denomination::Satoshi => "satoshi",
            Denomination::MilliSatoshi => "msat",
        })
    }
}

impl FromStr for Denomination {
    type Err = ParseAmountError;

    /// Convert from a str to Denomination.
    ///
    /// Any combination of upper and/or lower case, excluding uppercase 'M' is considered valid.
    /// - Singular: BTC, mBTC, uBTC
    /// - Plural or singular: sat, satoshi, bit, msat
    ///
    /// Due to ambiguity between mega and milli we prohibit usage of leading capital 'M'.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::ParseAmountError::*;

        if s.starts_with('M') {
            return Err(denomination_from_str(s).map_or_else(
                || UnknownDenomination(s.to_owned()),
                |_| PossiblyConfusingDenomination(s.to_owned())
            ));
        }

        denomination_from_str(s).ok_or_else(|| UnknownDenomination(s.to_owned()))
    }
}

fn denomination_from_str(mut s: &str) -> Option<Denomination> {
    if s.eq_ignore_ascii_case("BTC") {
        return Some(Denomination::Bitcoin);
    }

    if s.eq_ignore_ascii_case("mBTC") {
        return Some(Denomination::MilliBitcoin);
    }

    if s.eq_ignore_ascii_case("uBTC") {
        return Some(Denomination::MicroBitcoin);
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
    PossiblyConfusingDenomination(String)
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
            ParseAmountError::UnknownDenomination(ref d) => write!(f, "unknown denomination: {}", d),
            ParseAmountError::PossiblyConfusingDenomination(ref d) => {
                write!(f, "the 'M' at the beginning of {} should technically mean 'Mega' but that denomination is uncommon and maybe 'milli' was intended", d)
            }
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl ::std::error::Error for ParseAmountError {}

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
            let last_n = precision_diff.abs() as usize;
            if is_too_precise(s, last_n) {
                return Err(ParseAmountError::TooPrecise);
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

/// Format the given satoshi amount in the given denomination.
///
/// Does not include the denomination.
fn fmt_satoshi_in(
    satoshi: u64,
    negative: bool,
    f: &mut dyn fmt::Write,
    denom: Denomination,
) -> fmt::Result {
    if negative {
        f.write_str("-")?;
    }

    let precision = denom.precision();
    match precision.cmp(&0) {
        Ordering::Greater => {
            // add zeroes in the end
            let width = precision as usize;
            write!(f, "{}{:0width$}", satoshi, 0, width = width)?;
        }
        Ordering::Less => {
            // need to inject a comma in the number
            let nb_decimals = precision.abs() as usize;
            let real = format!("{:0width$}", satoshi, width = nb_decimals);
            if real.len() == nb_decimals {
                write!(f, "0.{}", &real[real.len() - nb_decimals..])?;
            } else {
                write!(
                    f,
                    "{}.{}",
                    &real[0..(real.len() - nb_decimals)],
                    &real[real.len() - nb_decimals..]
                )?;
            }
        }
        Ordering::Equal => write!(f, "{}", satoshi)?,
    }
    Ok(())
}

/// Amount
///
/// The [Amount] type can be used to express Bitcoin amounts that supports
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
    pub fn from_sat(satoshi: u64) -> Amount {
        Amount(satoshi)
    }

    /// Get the number of satoshis in this [Amount].
    pub fn as_sat(self) -> u64 {
        self.0
    }

    /// The maximum value of an [Amount].
    pub fn max_value() -> Amount {
        Amount(u64::max_value())
    }

    /// The minimum value of an [Amount].
    pub fn min_value() -> Amount {
        Amount(u64::min_value())
    }

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
        let mut split = s.splitn(3, ' ');
        let amt_str = split.next().unwrap();
        let denom_str = split.next().ok_or(ParseAmountError::InvalidFormat)?;
        if split.next().is_some() {
            return Err(ParseAmountError::InvalidFormat);
        }

        Amount::from_str_in(amt_str, denom_str.parse()?)
    }

    /// Express this [Amount] as a floating-point value in the given denomination.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn to_float_in(self, denom: Denomination) -> f64 {
        f64::from_str(&self.to_string_in(denom)).unwrap()
    }

    /// Express this [Amount] as a floating-point value in Bitcoin.
    ///
    /// Equivalent to `to_float_in(Denomination::Bitcoin)`.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn as_btc(self) -> f64 {
        self.to_float_in(Denomination::Bitcoin)
    }

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

    /// Format the value of this [Amount] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn fmt_value_in(self, f: &mut dyn fmt::Write, denom: Denomination) -> fmt::Result {
        fmt_satoshi_in(self.as_sat(), false, f, denom)
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
    pub fn checked_mul(self, rhs: u64) -> Option<Amount> {
        self.0.checked_mul(rhs).map(Amount)
    }

    /// Checked integer division.
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made.
    /// Returns [None] if overflow occurred.
    pub fn checked_div(self, rhs: u64) -> Option<Amount> {
        self.0.checked_div(rhs).map(Amount)
    }

    /// Checked remainder.
    /// Returns [None] if overflow occurred.
    pub fn checked_rem(self, rhs: u64) -> Option<Amount> {
        self.0.checked_rem(rhs).map(Amount)
    }

    /// Convert to a signed amount.
    pub fn to_signed(self) -> Result<SignedAmount, ParseAmountError> {
        if self.as_sat() > SignedAmount::max_value().as_sat() as u64 {
            Err(ParseAmountError::TooBig)
        } else {
            Ok(SignedAmount::from_sat(self.as_sat() as i64))
        }
    }
}

impl default::Default for Amount {
    fn default() -> Self {
        Amount::ZERO
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Amount({:.8} BTC)", self.as_btc())
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
    fn add_assign(&mut self, other: Amount) {
        *self = *self + other
    }
}

impl ops::Sub for Amount {
    type Output = Amount;

    fn sub(self, rhs: Amount) -> Self::Output {
        self.checked_sub(rhs).expect("Amount subtraction error")
    }
}

impl ops::SubAssign for Amount {
    fn sub_assign(&mut self, other: Amount) {
        *self = *self - other
    }
}

impl ops::Rem<u64> for Amount {
    type Output = Amount;

    fn rem(self, modulus: u64) -> Self {
        self.checked_rem(modulus).expect("Amount remainder error")
    }
}

impl ops::RemAssign<u64> for Amount {
    fn rem_assign(&mut self, modulus: u64) {
        *self = *self % modulus
    }
}

impl ops::Mul<u64> for Amount {
    type Output = Amount;

    fn mul(self, rhs: u64) -> Self::Output {
        self.checked_mul(rhs).expect("Amount multiplication error")
    }
}

impl ops::MulAssign<u64> for Amount {
    fn mul_assign(&mut self, rhs: u64) {
        *self = *self * rhs
    }
}

impl ops::Div<u64> for Amount {
    type Output = Amount;

    fn div(self, rhs: u64) -> Self::Output {
        self.checked_div(rhs).expect("Amount division error")
    }
}

impl ops::DivAssign<u64> for Amount {
    fn div_assign(&mut self, rhs: u64) {
        *self = *self / rhs
    }
}

impl FromStr for Amount {
    type Err = ParseAmountError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Amount::from_str_with_denomination(s)
    }
}

impl ::core::iter::Sum for Amount {
    fn sum<I: Iterator<Item=Self>>(iter: I) -> Self {
        let sats: u64 = iter.map(|amt| amt.0).sum();
        Amount::from_sat(sats)
    }
}

/// SignedAmount
///
/// The [SignedAmount] type can be used to express Bitcoin amounts that supports
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
    pub fn from_sat(satoshi: i64) -> SignedAmount {
        SignedAmount(satoshi)
    }

    /// Get the number of satoshis in this [SignedAmount].
    pub fn as_sat(self) -> i64 {
        self.0
    }

    /// The maximum value of an [SignedAmount].
    pub fn max_value() -> SignedAmount {
        SignedAmount(i64::max_value())
    }

    /// The minimum value of an [SignedAmount].
    pub fn min_value() -> SignedAmount {
        SignedAmount(i64::min_value())
    }

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
        let mut split = s.splitn(3, ' ');
        let amt_str = split.next().unwrap();
        let denom_str = split.next().ok_or(ParseAmountError::InvalidFormat)?;
        if split.next().is_some() {
            return Err(ParseAmountError::InvalidFormat);
        }

        SignedAmount::from_str_in(amt_str, denom_str.parse()?)
    }

    /// Express this [SignedAmount] as a floating-point value in the given denomination.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn to_float_in(self, denom: Denomination) -> f64 {
        f64::from_str(&self.to_string_in(denom)).unwrap()
    }

    /// Express this [SignedAmount] as a floating-point value in Bitcoin.
    ///
    /// Equivalent to `to_float_in(Denomination::Bitcoin)`.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn as_btc(self) -> f64 {
        self.to_float_in(Denomination::Bitcoin)
    }

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

    /// Format the value of this [SignedAmount] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn fmt_value_in(self, f: &mut dyn fmt::Write, denom: Denomination) -> fmt::Result {
        let sats = self.as_sat().checked_abs().map(|a: i64| a as u64).unwrap_or_else(|| {
            // We could also hard code this into `9223372036854775808`
            u64::max_value() - self.as_sat() as u64 +1
        });
        fmt_satoshi_in(sats, self.is_negative(), f, denom)
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
    pub fn abs(self) -> SignedAmount {
        SignedAmount(self.0.abs())
    }

    /// Returns a number representing sign of this [SignedAmount].
    ///
    /// - `0` if the amount is zero
    /// - `1` if the amount is positive
    /// - `-1` if the amount is negative
    pub fn signum(self) -> i64 {
        self.0.signum()
    }

    /// Returns `true` if this [SignedAmount] is positive and `false` if
    /// this [SignedAmount] is zero or negative.
    pub fn is_positive(self) -> bool {
        self.0.is_positive()
    }

    /// Returns `true` if this [SignedAmount] is negative and `false` if
    /// this [SignedAmount] is zero or positive.
    pub fn is_negative(self) -> bool {
        self.0.is_negative()
    }


    /// Get the absolute value of this [SignedAmount].
    /// Returns [None] if overflow occurred. (`self == min_value()`)
    pub fn checked_abs(self) -> Option<SignedAmount> {
        self.0.checked_abs().map(SignedAmount)
    }

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
            Ok(Amount::from_sat(self.as_sat() as u64))
        }
    }
}

impl default::Default for SignedAmount {
    fn default() -> Self {
        SignedAmount::ZERO
    }
}

impl fmt::Debug for SignedAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SignedAmount({:.8} BTC)", self.as_btc())
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
    fn add_assign(&mut self, other: SignedAmount) {
        *self = *self + other
    }
}

impl ops::Sub for SignedAmount {
    type Output = SignedAmount;

    fn sub(self, rhs: SignedAmount) -> Self::Output {
        self.checked_sub(rhs).expect("SignedAmount subtraction error")
    }
}

impl ops::SubAssign for SignedAmount {
    fn sub_assign(&mut self, other: SignedAmount) {
        *self = *self - other
    }
}

impl ops::Rem<i64> for SignedAmount {
    type Output = SignedAmount;

    fn rem(self, modulus: i64) -> Self {
        self.checked_rem(modulus).expect("SignedAmount remainder error")
    }
}

impl ops::RemAssign<i64> for SignedAmount {
    fn rem_assign(&mut self, modulus: i64) {
        *self = *self % modulus
    }
}

impl ops::Mul<i64> for SignedAmount {
    type Output = SignedAmount;

    fn mul(self, rhs: i64) -> Self::Output {
        self.checked_mul(rhs).expect("SignedAmount multiplication error")
    }
}

impl ops::MulAssign<i64> for SignedAmount {
    fn mul_assign(&mut self, rhs: i64) {
        *self = *self * rhs
    }
}

impl ops::Div<i64> for SignedAmount {
    type Output = SignedAmount;

    fn div(self, rhs: i64) -> Self::Output {
        self.checked_div(rhs).expect("SignedAmount division error")
    }
}

impl ops::DivAssign<i64> for SignedAmount {
    fn div_assign(&mut self, rhs: i64) {
        *self = *self / rhs
    }
}

impl FromStr for SignedAmount {
    type Err = ParseAmountError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SignedAmount::from_str_with_denomination(s)
    }
}

impl ::core::iter::Sum for SignedAmount {
    fn sum<I: Iterator<Item=Self>>(iter: I) -> Self {
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

impl<T> CheckedSum<Amount> for T where T: Iterator<Item = Amount> {
    fn checked_sum(mut self) -> Option<Amount> {
        let first = Some(self.next().unwrap_or_default());

        self.fold(
            first,
            |acc, item| acc.and_then(|acc| acc.checked_add(item))
        )
    }
}

impl<T> CheckedSum<SignedAmount> for T where T: Iterator<Item = SignedAmount> {
    fn checked_sum(mut self) -> Option<SignedAmount> {
        let first = Some(self.next().unwrap_or_default());

        self.fold(
            first,
            |acc, item| acc.and_then(|acc| acc.checked_add(item))
        )
    }
}

mod private {
    use ::{Amount, SignedAmount};

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
    //! pub struct HasAmount {
    //!     #[serde(with = "bitcoin::util::amount::serde::as_btc")]
    //!     pub amount: Amount,
    //! }
    //! ```

    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use util::amount::{Amount, Denomination, SignedAmount};

    /// This trait is used only to avoid code duplication and naming collisions
    /// of the different serde serialization crates.
    ///
    /// TODO: Add the private::Sealed bound in next breaking release
    pub trait SerdeAmount: Copy + Sized {
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
            u64::serialize(&self.as_sat(), s)
        }
        fn des_sat<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            Ok(Amount::from_sat(u64::deserialize(d)?))
        }
        fn ser_btc<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            f64::serialize(&self.to_float_in(Denomination::Bitcoin), s)
        }
        fn des_btc<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            use serde::de::Error;
            Ok(Amount::from_btc(f64::deserialize(d)?).map_err(D::Error::custom)?)
        }
    }

    impl SerdeAmountForOpt for Amount {
        fn type_prefix() -> &'static str {
            "u"
        }
        fn ser_sat_opt<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_some(&self.as_sat())
        }
        fn ser_btc_opt<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_some(&self.as_btc())
        }
    }

    impl SerdeAmount for SignedAmount {
        fn ser_sat<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            i64::serialize(&self.as_sat(), s)
        }
        fn des_sat<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            Ok(SignedAmount::from_sat(i64::deserialize(d)?))
        }
        fn ser_btc<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            f64::serialize(&self.to_float_in(Denomination::Bitcoin), s)
        }
        fn des_btc<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            use serde::de::Error;
            Ok(SignedAmount::from_btc(f64::deserialize(d)?).map_err(D::Error::custom)?)
        }
    }

    impl SerdeAmountForOpt for SignedAmount {
        fn type_prefix() -> &'static str {
            "i"
        }
        fn ser_sat_opt<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_some(&self.as_sat())
        }
        fn ser_btc_opt<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_some(&self.as_btc())
        }
    }

    pub mod as_sat {
        //! Serialize and deserialize [`Amount`](crate::Amount) as real numbers denominated in satoshi.
        //! Use with `#[serde(with = "amount::serde::as_sat")]`.

        use serde::{Deserializer, Serializer};
        use util::amount::serde::SerdeAmount;

        pub fn serialize<A: SerdeAmount, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error> {
            a.ser_sat(s)
        }

        pub fn deserialize<'d, A: SerdeAmount, D: Deserializer<'d>>(d: D) -> Result<A, D::Error> {
            A::des_sat(d)
        }

        pub mod opt {
            //! Serialize and deserialize [`Option<Amount>`](crate::Amount) as real numbers denominated in satoshi.
            //! Use with `#[serde(default, with = "amount::serde::as_sat::opt")]`.

            use serde::{Deserializer, Serializer, de};
            use util::amount::serde::SerdeAmountForOpt;
            use core::fmt;
            use core::marker::PhantomData;

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
                        E: de::Error {
                        Ok(None)
                    }
                    fn visit_some<D>(self, d: D) -> Result<Self::Value, D::Error>
                    where
                        D: Deserializer<'de>
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
        use util::amount::serde::SerdeAmount;

        pub fn serialize<A: SerdeAmount, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error> {
            a.ser_btc(s)
        }

        pub fn deserialize<'d, A: SerdeAmount, D: Deserializer<'d>>(d: D) -> Result<A, D::Error> {
            A::des_btc(d)
        }

        pub mod opt {
            //! Serialize and deserialize [Option<Amount>] as JSON numbers denominated in BTC.
            //! Use with `#[serde(default, with = "amount::serde::as_btc::opt")]`.

            use serde::{Deserializer, Serializer, de};
            use util::amount::serde::SerdeAmountForOpt;
            use core::fmt;
            use core::marker::PhantomData;

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

                impl<'de, X :SerdeAmountForOpt> de::Visitor<'de> for VisitOptAmt<X> {
                    type Value = Option<X>;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        write!(formatter, "An Option<f64>")
                    }

                    fn visit_none<E>(self) -> Result<Self::Value, E>
                    where
                        E: de::Error {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "std")]
    use std::panic;
    use core::str::FromStr;

    #[cfg(feature = "serde")]
    use serde_test;

    #[test]
    fn add_sub_mul_div() {
        let sat = Amount::from_sat;
        let ssat = SignedAmount::from_sat;

        assert_eq!(sat(15) + sat(15), sat(30));
        assert_eq!(sat(15) - sat(15), sat(0));
        assert_eq!(sat(14) * 3, sat(42));
        assert_eq!(sat(14) / 2, sat(7));
        assert_eq!(sat(14) % 3, sat(2));
        assert_eq!(ssat(15) - ssat(20), ssat(-5));
        assert_eq!(ssat(-14) * 3, ssat(-42));
        assert_eq!(ssat(-14) / 2, ssat(-7));
        assert_eq!(ssat(-14) % 3, ssat(-2));

        let mut b = ssat(-5);
        b += ssat(13);
        assert_eq!(b, ssat(8));
        b -= ssat(3);
        assert_eq!(b, ssat(5));
        b *= 6;
        assert_eq!(b, ssat(30));
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

        assert_eq!(sat(42).checked_add(sat(1)), Some(sat(43)));
        assert_eq!(SignedAmount::max_value().checked_add(ssat(1)), None);
        assert_eq!(SignedAmount::min_value().checked_sub(ssat(1)), None);
        assert_eq!(Amount::max_value().checked_add(sat(1)), None);
        assert_eq!(Amount::min_value().checked_sub(sat(1)), None);

        assert_eq!(sat(5).checked_sub(sat(3)), Some(sat(2)));
        assert_eq!(sat(5).checked_sub(sat(6)), None);
        assert_eq!(ssat(5).checked_sub(ssat(6)), Some(ssat(-1)));
        assert_eq!(sat(5).checked_rem(2), Some(sat(1)));

        assert_eq!(sat(5).checked_div(2), Some(sat(2))); // integer division
        assert_eq!(ssat(-6).checked_div(2), Some(ssat(-3)));

        assert_eq!(ssat(-5).positive_sub(ssat(3)), None);
        assert_eq!(ssat(5).positive_sub(ssat(-3)), None);
        assert_eq!(ssat(3).positive_sub(ssat(5)), None);
        assert_eq!(ssat(3).positive_sub(ssat(3)), Some(ssat(0)));
        assert_eq!(ssat(5).positive_sub(ssat(3)), Some(ssat(2)));
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
        assert_eq!(p("5500000000000000000", sat), Ok(Amount::from_sat(5_500_000_000_000_000_000)));
        // Should this even pass?
        assert_eq!(p("5500000000000000000.", sat), Ok(Amount::from_sat(5_500_000_000_000_000_000)));
        assert_eq!(
            p("12345678901.12345678", btc),
            Ok(Amount::from_sat(12_345_678_901__123_456_78))
        );

        // make sure satoshi > i64::max_value() is checked.
        let amount = Amount::from_sat(i64::max_value() as u64);
        assert_eq!(Amount::from_str_in(&amount.to_string_in(sat), sat), Ok(amount));
        assert_eq!(Amount::from_str_in(&(amount+Amount(1)).to_string_in(sat), sat), Err(E::TooBig));

        assert_eq!(p("12.000", Denomination::MilliSatoshi), Err(E::TooPrecise));
        // exactly 50 chars.
        assert_eq!(p("100000000000000.0000000000000000000000000000000000", Denomination::Bitcoin), Err(E::TooBig));
        // more than 50 chars.
        assert_eq!(p("100000000000000.00000000000000000000000000000000000", Denomination::Bitcoin), Err(E::InputTooLarge));
    }

    #[test]
    fn to_string() {
        use super::Denomination as D;

        assert_eq!(Amount::ONE_BTC.to_string_in(D::Bitcoin), "1.00000000");
        assert_eq!(Amount::ONE_BTC.to_string_in(D::Satoshi), "100000000");
        assert_eq!(Amount::ONE_SAT.to_string_in(D::Bitcoin), "0.00000001");
        assert_eq!(SignedAmount::from_sat(-42).to_string_in(D::Bitcoin), "-0.00000042");

        assert_eq!(Amount::ONE_BTC.to_string_with_denomination(D::Bitcoin), "1.00000000 BTC");
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

    #[test]
    fn test_unsigned_signed_conversion() {
        use super::ParseAmountError as E;
        let sa = SignedAmount::from_sat;
        let ua = Amount::from_sat;

        assert_eq!(Amount::max_value().to_signed(),  Err(E::TooBig));
        assert_eq!(ua(i64::max_value() as u64).to_signed(),  Ok(sa(i64::max_value())));
        assert_eq!(ua(0).to_signed(),  Ok(sa(0)));
        assert_eq!(ua(1).to_signed(), Ok( sa(1)));
        assert_eq!(ua(1).to_signed(),  Ok(sa(1)));
        assert_eq!(ua(i64::max_value() as u64 + 1).to_signed(),  Err(E::TooBig));

        assert_eq!(sa(-1).to_unsigned(), Err(E::Negative));
        assert_eq!(sa(i64::max_value()).to_unsigned(), Ok(ua(i64::max_value() as u64)));

        assert_eq!(sa(0).to_unsigned().unwrap().to_signed(), Ok(sa(0)));
        assert_eq!(sa(1).to_unsigned().unwrap().to_signed(), Ok(sa(1)));
        assert_eq!(sa(i64::max_value()).to_unsigned().unwrap().to_signed(), Ok(sa(i64::max_value())));
    }

    #[test]
    fn from_str() {
        use super::ParseAmountError as E;
        let p = Amount::from_str;
        let sp = SignedAmount::from_str;

        assert_eq!(p("x BTC"), Err(E::InvalidCharacter('x')));
        assert_eq!(p("5 BTC BTC"), Err(E::InvalidFormat));
        assert_eq!(p("5 5 BTC"), Err(E::InvalidFormat));

        assert_eq!(p("5 BCH"), Err(E::UnknownDenomination("BCH".to_owned())));

        assert_eq!(p("-1 BTC"), Err(E::Negative));
        assert_eq!(p("-0.0 BTC"), Err(E::Negative));
        assert_eq!(p("0.123456789 BTC"), Err(E::TooPrecise));
        assert_eq!(sp("-0.1 satoshi"), Err(E::TooPrecise));
        assert_eq!(p("0.123456 mBTC"), Err(E::TooPrecise));
        assert_eq!(sp("-1.001 bits"), Err(E::TooPrecise));
        assert_eq!(sp("-200000000000 BTC"), Err(E::TooBig));
        assert_eq!(p("18446744073709551616 sat"), Err(E::TooBig));

        assert_eq!(sp("0 msat"), Err(E::TooPrecise));
        assert_eq!(sp("-0 msat"), Err(E::TooPrecise));
        assert_eq!(sp("000 msat"), Err(E::TooPrecise));
        assert_eq!(sp("-000 msat"), Err(E::TooPrecise));
        assert_eq!(p("0 msat"), Err(E::TooPrecise));
        assert_eq!(p("-0 msat"), Err(E::TooPrecise));
        assert_eq!(p("000 msat"), Err(E::TooPrecise));
        assert_eq!(p("-000 msat"), Err(E::TooPrecise));

        assert_eq!(p(".5 bits"), Ok(Amount::from_sat(50)));
        assert_eq!(sp("-.5 bits"), Ok(SignedAmount::from_sat(-50)));
        assert_eq!(p("0.00253583 BTC"), Ok(Amount::from_sat(253583)));
        assert_eq!(sp("-5 satoshi"), Ok(SignedAmount::from_sat(-5)));
        assert_eq!(p("0.10000000 BTC"), Ok(Amount::from_sat(100_000_00)));
        assert_eq!(sp("-100 bits"), Ok(SignedAmount::from_sat(-10_000)));
    }

    #[test]
    fn to_from_string_in() {
        use super::Denomination as D;
        let ua_str = Amount::from_str_in;
        let ua_sat = Amount::from_sat;
        let sa_str = SignedAmount::from_str_in;
        let sa_sat = SignedAmount::from_sat;

        assert_eq!("0.50", Amount::from_sat(50).to_string_in(D::Bit));
        assert_eq!("-0.50", SignedAmount::from_sat(-50).to_string_in(D::Bit));
        assert_eq!("0.00253583", Amount::from_sat(253583).to_string_in(D::Bitcoin));
        assert_eq!("-5", SignedAmount::from_sat(-5).to_string_in(D::Satoshi));
        assert_eq!("0.10000000", Amount::from_sat(100_000_00).to_string_in(D::Bitcoin));
        assert_eq!("-100.00", SignedAmount::from_sat(-10_000).to_string_in(D::Bit));

        assert_eq!(ua_str(&ua_sat(0).to_string_in(D::Satoshi), D::Satoshi), Ok(ua_sat(0)));
        assert_eq!(ua_str(&ua_sat(500).to_string_in(D::Bitcoin), D::Bitcoin), Ok(ua_sat(500)));
        assert_eq!(ua_str(&ua_sat(21_000_000).to_string_in(D::Bit), D::Bit), Ok(ua_sat(21_000_000)));
        assert_eq!(ua_str(&ua_sat(1).to_string_in(D::MicroBitcoin), D::MicroBitcoin), Ok(ua_sat(1)));
        assert_eq!(ua_str(&ua_sat(1_000_000_000_000).to_string_in(D::MilliBitcoin), D::MilliBitcoin), Ok(ua_sat(1_000_000_000_000)));
        assert_eq!(ua_str(&ua_sat(u64::max_value()).to_string_in(D::MilliBitcoin), D::MilliBitcoin),  Err(ParseAmountError::TooBig));

        assert_eq!(sa_str(&sa_sat(-1).to_string_in(D::MicroBitcoin), D::MicroBitcoin), Ok(sa_sat(-1)));

        assert_eq!(sa_str(&sa_sat(i64::max_value()).to_string_in(D::Satoshi), D::MicroBitcoin), Err(ParseAmountError::TooBig));
        // Test an overflow bug in `abs()`
        assert_eq!(sa_str(&sa_sat(i64::min_value()).to_string_in(D::Satoshi), D::MicroBitcoin), Err(ParseAmountError::TooBig));

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
        assert_eq!(Amount::from_str(&denom(amt, D::MilliSatoshi)), Ok(amt));

        assert_eq!(Amount::from_str("42 satoshi BTC"), Err(ParseAmountError::InvalidFormat));
        assert_eq!(SignedAmount::from_str("-42 satoshi BTC"), Err(ParseAmountError::InvalidFormat));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_sat() {

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(with = "::util::amount::serde::as_sat")]
            pub amt: Amount,
            #[serde(with = "::util::amount::serde::as_sat")]
            pub samt: SignedAmount,
        }

        serde_test::assert_tokens(
            &T {
                amt: Amount::from_sat(123456789),
                samt: SignedAmount::from_sat(-123456789),
            },
            &[
                serde_test::Token::Struct {
                    name: "T",
                    len: 2,
                },
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
    fn serde_as_btc() {
        use serde_json;

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(with = "::util::amount::serde::as_btc")]
            pub amt: Amount,
            #[serde(with = "::util::amount::serde::as_btc")]
            pub samt: SignedAmount,
        }

        let orig = T {
            amt: Amount::from_sat(21_000_000__000_000_01),
            samt: SignedAmount::from_sat(-21_000_000__000_000_01),
        };

        let json = "{\"amt\": 21000000.00000001, \
                    \"samt\": -21000000.00000001}";
        let t: T = serde_json::from_str(&json).unwrap();
        assert_eq!(t, orig);

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
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
    fn serde_as_btc_opt() {
        use serde_json;

        #[derive(Serialize, Deserialize, PartialEq, Debug, Eq)]
        struct T {
            #[serde(default, with = "::util::amount::serde::as_btc::opt")]
            pub amt: Option<Amount>,
            #[serde(default, with = "::util::amount::serde::as_btc::opt")]
            pub samt: Option<SignedAmount>,
        }

        let with = T {
            amt: Some(Amount::from_sat(2__500_000_00)),
            samt: Some(SignedAmount::from_sat(-2__500_000_00)),
        };
        let without = T {
            amt: None,
            samt: None,
        };

        // Test Roundtripping
        for s in [&with, &without].iter() {
            let v = serde_json::to_string(s).unwrap();
            let w : T = serde_json::from_str(&v).unwrap();
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
    fn serde_as_sat_opt() {
        use serde_json;

        #[derive(Serialize, Deserialize, PartialEq, Debug, Eq)]
        struct T {
            #[serde(default, with = "::util::amount::serde::as_sat::opt")]
            pub amt: Option<Amount>,
            #[serde(default, with = "::util::amount::serde::as_sat::opt")]
            pub samt: Option<SignedAmount>,
        }

        let with = T {
            amt: Some(Amount::from_sat(2__500_000_00)),
            samt: Some(SignedAmount::from_sat(-2__500_000_00)),
        };
        let without = T {
            amt: None,
            samt: None,
        };

        // Test Roundtripping
        for s in [&with, &without].iter() {
            let v = serde_json::to_string(s).unwrap();
            let w : T = serde_json::from_str(&v).unwrap();
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

        let amounts = vec![
            Amount::from_sat(42),
            Amount::from_sat(1337),
            Amount::from_sat(21)
        ];
        let sum = amounts.into_iter().sum::<Amount>();
        assert_eq!(Amount::from_sat(1400), sum);

        let amounts = vec![
            SignedAmount::from_sat(-42),
            SignedAmount::from_sat(1337),
            SignedAmount::from_sat(21)
        ];
        let sum = amounts.into_iter().sum::<SignedAmount>();
        assert_eq!(SignedAmount::from_sat(1316), sum);
    }

    #[test]
    fn checked_sum_amounts() {
        assert_eq!(Some(Amount::from_sat(0)), vec![].into_iter().checked_sum());
        assert_eq!(Some(SignedAmount::from_sat(0)), vec![].into_iter().checked_sum());

        let amounts = vec![
            Amount::from_sat(42),
            Amount::from_sat(1337),
            Amount::from_sat(21)
        ];
        let sum = amounts.into_iter().checked_sum();
        assert_eq!(Some(Amount::from_sat(1400)), sum);

        let amounts = vec![
            Amount::from_sat(u64::max_value()),
            Amount::from_sat(1337),
            Amount::from_sat(21)
        ];
        let sum = amounts.into_iter().checked_sum();
        assert_eq!(None, sum);

        let amounts = vec![
            SignedAmount::from_sat(i64::min_value()),
            SignedAmount::from_sat(-1),
            SignedAmount::from_sat(21)
        ];
        let sum = amounts.into_iter().checked_sum();
        assert_eq!(None, sum);

        let amounts = vec![
            SignedAmount::from_sat(i64::max_value()),
            SignedAmount::from_sat(1),
            SignedAmount::from_sat(21)
        ];
        let sum = amounts.into_iter().checked_sum();
        assert_eq!(None, sum);

        let amounts = vec![
            SignedAmount::from_sat(42),
            SignedAmount::from_sat(3301),
            SignedAmount::from_sat(21)
        ];
        let sum = amounts.into_iter().checked_sum();
        assert_eq!(Some(SignedAmount::from_sat(3364)), sum);
    }

    #[test]
    fn denomination_string_acceptable_forms() {
        // Non-exhaustive list of valid forms.
        let valid = vec!["BTC", "btc", "mBTC", "mbtc", "uBTC", "ubtc", "SATOSHI","Satoshi", "Satoshis", "satoshis", "SAT", "Sat", "sats", "bit", "bits"];
        for denom in valid.iter() {
            assert!(Denomination::from_str(denom).is_ok());
        }
    }

    #[test]
    fn disallow_confusing_forms() {
        // Non-exhaustive list of confusing forms.
        let confusing = vec!["Msat", "Msats", "MSAT", "MSATS", "MSat", "MSats", "MBTC", "Mbtc"];
        for denom in confusing.iter() {
            match  Denomination::from_str(denom) {
                Ok(_) => panic!("from_str should error for {}", denom),
                Err(ParseAmountError::PossiblyConfusingDenomination(_)) => {},
                Err(e) => panic!("unexpected error: {}", e),
            }
        }
    }
}

