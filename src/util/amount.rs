// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Amounts
//!
//! This module mainly introduces the [Amount] type.  We refer to the
//! documentation on the type for more information.
//!

use std::default;
use std::error;
use std::fmt::{self, Write};
use std::ops;
use std::str::FromStr;

/// A set of denominations in which an Amount can be expressed.
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

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "BTC" => Ok(Denomination::Bitcoin),
            "mBTC" => Ok(Denomination::MilliBitcoin),
            "uBTC" => Ok(Denomination::MicroBitcoin),
            "bits" => Ok(Denomination::Bit),
            "satoshi" => Ok(Denomination::Satoshi),
            "sat" => Ok(Denomination::Satoshi),
            "msat" => Ok(Denomination::MilliSatoshi),
            d => Err(ParseAmountError::UnknownDenomination(d.to_owned())),
        }
    }
}

/// An error during [Amount] parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseAmountError {
    /// Amount is too big to fit in an [Amount].
    TooBig,
    /// Amount has higher precision than supported by [Amount].
    TooPrecise,
    /// Invalid number format.
    InvalidFormat,
    /// Input string was too large.
    InputTooLarge,
    /// Invalid character in input.
    InvalidCharacter(char),
    /// The denomination was unknown.
    UnknownDenomination(String),
}

impl fmt::Display for ParseAmountError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let desc = ::std::error::Error::description(self);
        match *self {
            ParseAmountError::InvalidCharacter(c) => write!(f, "{}: {}", desc, c),
            ParseAmountError::UnknownDenomination(ref d) => write!(f, "{}: {}", desc, d),
            _ => f.write_str(desc),
        }
    }
}

impl error::Error for ParseAmountError {
    fn cause(&self) -> Option<&error::Error> {
        None
    }

    fn description(&self) -> &'static str {
        match *self {
            ParseAmountError::TooBig => "amount is too big",
            ParseAmountError::TooPrecise => "amount has a too high precision",
            ParseAmountError::InvalidFormat => "invalid number format",
            ParseAmountError::InputTooLarge => "input string was too large",
            ParseAmountError::InvalidCharacter(_) => "invalid character in input",
            ParseAmountError::UnknownDenomination(_) => "unknown denomination",
        }
    }
}

// The inner type used to represent amounts.
// This is done to more easily change the underlying type in case this is
// desired in the future.
type Inner = i64;

/// Amount
///
/// The [Amount] type can be used to express Bitcoin amounts that supports
/// arithmetic and convertion to various denominations.
///
///
/// Warning!
///
/// This type implements several arithmetic operations from [std::ops].
/// To prevent errors due to overflow or underflow when using these operations,
/// it is advised to instead use the checked arithmetic methods whose names
/// start with `checked_`.  The operations from [std::ops] that [Amount]
/// implements will panic when overflow or underflow occurs.  Also note that
/// since the internal representation of amounts is unsigned, subtracting below
/// zero is considered an underflow and will cause a panic if you're not using
/// the checked arithmetic methods.
///
#[derive(Copy, Clone, Hash)]
pub struct Amount(Inner);
// The Inner amount represents the number of satoshis.

impl Amount {
    /// The zero amount.
    pub const ZERO: Amount = Amount(0);
    /// Exactly one satoshi.
    pub const ONE_SAT: Amount = Amount(1);
    /// Exactly one bitcoin.
    pub const ONE_BTC: Amount = Amount(100_000_000);

    /// Create a new [Amount] using [amount] as the Inner type.
    fn from_inner(amount: Inner) -> Amount {
        Amount(amount)
    }

    /// Create an [Amount] with satoshi precision and the given number of satoshis.
    pub fn from_sat(satoshi: i64) -> Amount {
        Amount::from_inner(satoshi)
    }

    /// Get the number of satoshis in this [Amount].
    pub fn as_sat(self) -> i64 {
        self.0
    }

    /// The maximum value of an [Amount].
    pub fn max_value() -> Amount {
        Amount::from_inner(Inner::max_value())
    }

    /// The minimum value of an [Amount].
    pub fn min_value() -> Amount {
        Amount::from_inner(Inner::min_value())
    }

    // Don't use the Inner type in the methods below.
    // Always use [Amount::from_sat] and [Amount::as_sat] instead.

    /// Convert from a value expressing bitcoins to an [Amount].
    pub fn from_btc(btc: f64) -> Result<Amount, ParseAmountError> {
        Amount::from_float_in(btc, Denomination::Bitcoin)
    }

    /// Parse a decimal string as a value in the given denomination.
    ///
    /// Note: This only parses the value string.  If you want to parse a value
    /// with denomination, use [FromStr].
    pub fn from_str_in(mut s: &str, denom: Denomination) -> Result<Amount, ParseAmountError> {
        if s.len() == 0 {
            return Err(ParseAmountError::InvalidFormat);
        }
        if s.len() > 50 {
            return Err(ParseAmountError::InputTooLarge);
        }

        let negative = s.chars().next().unwrap() == '-';
        if negative {
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
                // many as the diffence in precision.
                let last_n = precision_diff.abs() as usize;
                if s.contains(".") || s.chars().rev().take(last_n).any(|d| d != '0') {
                    return Err(ParseAmountError::TooPrecise);
                }
                s = &s[0..s.len() - last_n];
                0
            } else {
                precision_diff
            }
        };

        let mut decimals = None;
        let mut value: i64 = 0; // as satoshis
        for c in s.chars() {
            match c {
                '0'...'9' => {
                    // Do `value = 10 * value + digit`, catching overflows.
                    match 10_i64.checked_mul(value) {
                        None => return Err(ParseAmountError::TooBig),
                        Some(val) => match val.checked_add((c as u8 - b'0') as i64) {
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
            value = match 10_i64.checked_mul(value) {
                Some(v) => v,
                None => return Err(ParseAmountError::TooBig),
            };
        }

        if negative {
            value *= -1;
        }
        Ok(Amount::from_sat(value))
    }

    /// Parses amounts with denomination suffix like they are produced with
    /// [to_string_with_denomination] or with [fmt::Display].
    /// If you want to parse only the amount without the denomination,
    /// use [from_str_in].
    pub fn from_str_with_denomination(s: &str) -> Result<Amount, ParseAmountError> {
        let mut split = s.splitn(3, " ");
        let amt_str = split.next().unwrap();
        let denom_str = split.next().ok_or(ParseAmountError::InvalidFormat)?;
        if split.next().is_some() {
            return Err(ParseAmountError::InvalidFormat);
        }

        Ok(Amount::from_str_in(amt_str, denom_str.parse()?)?)
    }

    /// Express this [Amount] as a floating-point value in the given denomination.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn to_float_in(&self, denom: Denomination) -> f64 {
        (self.as_sat() as f64) * 10_f64.powi(denom.precision())
    }

    /// Express this [Amount] as a floating-point value in Bitcoin.
    ///
    /// Equivalent to `to_float_in(Denomination::Bitcoin)`.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn as_btc(&self) -> f64 {
        self.to_float_in(Denomination::Bitcoin)
    }

    /// Convert this [Amount] in floating-point notation with a given
    /// denomination.
    /// Can return error if the amount is too big, too precise or negative.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn from_float_in(value: f64, denom: Denomination) -> Result<Amount, ParseAmountError> {
        // This is inefficient, but the safest way to deal with this. The parsing logic is safe.
        // Any performance-critical application should not be dealing with floats.
        Amount::from_str_in(&value.to_string(), denom)
    }

    /// Format the value of this [Amount] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn fmt_value_in(&self, f: &mut fmt::Write, denom: Denomination) -> fmt::Result {
        if denom.precision() > 0 {
            // add zeroes in the end
            let width = denom.precision() as usize;
            write!(f, "{}{:0width$}", self.as_sat(), 0, width = width)?;
        } else if denom.precision() < 0 {
            // need to inject a comma in the number

            let sign = match self.is_negative() {
                true => "-",
                false => "",
            };
            let nb_decimals = denom.precision().abs() as usize;
            let real = format!("{:0width$}", self.as_sat().abs(), width = nb_decimals);
            if real.len() == nb_decimals {
                write!(f, "{}0.{}", sign, &real[real.len() - nb_decimals..])?;
            } else {
                write!(
                    f,
                    "{}{}.{}",
                    sign,
                    &real[0..(real.len() - nb_decimals)],
                    &real[real.len() - nb_decimals..]
                )?;
            }
        } else {
            // denom.precision() == 0
            write!(f, "{}", self.as_sat())?;
        }
        Ok(())
    }

    /// Get a string number of this [Amount] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn to_string_in(&self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        buf
    }

    /// Get a formatted string of this [Amount] in the given denomination,
    /// suffixed with the abbreviation for the denomination.
    pub fn to_string_with_denomination(&self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        write!(buf, " {}", denom).unwrap();
        buf
    }

    // Some arithmethic that doesn't fit in `std::ops` traits.

    /// Get the absolute value of this [Amount].
    pub fn abs(self) -> Amount {
        Amount::from_inner(self.0.abs())
    }

    /// Returns a number representing sign of this [Amount].
    ///
    /// - `0` if the Amount is zero
    /// - `1` if the Amount is positive
    /// - `-1` if the Amount is negative
    pub fn signum(self) -> i64 {
        self.0.signum()
    }

    /// Returns `true` if this [Amount] is positive and `false` if
    /// this [Amount] is zero or negative.
    pub fn is_positive(self) -> bool {
        self.0.is_positive()
    }

    /// Returns `true` if this [Amount] is negative and `false` if
    /// this [Amount] is zero or positive.
    pub fn is_negative(self) -> bool {
        self.0.is_negative()
    }

    /// Checked addition.
    /// Returns [None] if overflow occurred.
    pub fn checked_add(self, rhs: Amount) -> Option<Amount> {
        self.0.checked_add(rhs.0).map(Amount::from_inner)
    }

    /// Checked subtraction.
    /// Returns [None] if overflow occurred.
    pub fn checked_sub(self, rhs: Amount) -> Option<Amount> {
        self.0.checked_sub(rhs.0).map(Amount::from_inner)
    }

    /// Checked multiplication.
    /// Returns [None] if overflow occurred.
    pub fn checked_mul(self, rhs: i64) -> Option<Amount> {
        self.0.checked_mul(rhs).map(Amount::from_inner)
    }

    /// Checked integer division.
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made.
    /// Returns [None] if overflow occurred.
    pub fn checked_div(self, rhs: i64) -> Option<Amount> {
        self.0.checked_div(rhs).map(Amount::from_inner)
    }

    /// Checked remainder.
    /// Returns [None] if overflow occurred.
    pub fn checked_rem(self, rhs: i64) -> Option<Amount> {
        self.0.checked_rem(rhs).map(Amount::from_inner)
    }

    /// Subtraction that doesn't allow negative [Amount]s.
    /// Returns [None] if either [self], [rhs] or the result is strictly negative.
    pub fn positive_sub(self, rhs: Amount) -> Option<Amount> {
        if self.is_negative() || rhs.is_negative() || rhs > self {
            None
        } else {
            self.checked_sub(rhs)
        }
    }
}

impl default::Default for Amount {
    fn default() -> Self {
        Amount::ZERO
    }
}

impl PartialEq for Amount {
    fn eq(&self, other: &Amount) -> bool {
        PartialEq::eq(&self.0, &other.0)
    }
}
impl Eq for Amount {}

impl PartialOrd for Amount {
    fn partial_cmp(&self, other: &Amount) -> Option<::std::cmp::Ordering> {
        PartialOrd::partial_cmp(&self.0, &other.0)
    }
}

impl Ord for Amount {
    fn cmp(&self, other: &Amount) -> ::std::cmp::Ordering {
        Ord::cmp(&self.0, &other.0)
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Amount({} satoshi)", self.as_sat())
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

impl ops::Rem<i64> for Amount {
    type Output = Amount;

    fn rem(self, modulus: i64) -> Self {
        self.checked_rem(modulus).expect("Amount remainder error")
    }
}

impl ops::RemAssign<i64> for Amount {
    fn rem_assign(&mut self, modulus: i64) {
        *self = *self % modulus
    }
}

impl ops::Mul<i64> for Amount {
    type Output = Amount;

    fn mul(self, rhs: i64) -> Self::Output {
        self.checked_mul(rhs).expect("Amount multiplication error")
    }
}

impl ops::MulAssign<i64> for Amount {
    fn mul_assign(&mut self, rhs: i64) {
        *self = *self * rhs
    }
}

impl ops::Div<i64> for Amount {
    type Output = Amount;

    fn div(self, rhs: i64) -> Self::Output {
        self.checked_div(rhs).expect("Amount division error")
    }
}

impl ops::DivAssign<i64> for Amount {
    fn div_assign(&mut self, rhs: i64) {
        *self = *self / rhs
    }
}

impl FromStr for Amount {
    type Err = ParseAmountError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Amount::from_str_with_denomination(s)
    }
}

#[cfg(feature = "serde")]
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

    pub mod as_sat {
        //! Serialize and deserialize [Amount] as real numbers denominated in satoshi.
        //! Use with `#[serde(with = "amount::serde::as_sat")]`.

        use serde::{Deserialize, Deserializer, Serialize, Serializer};
        use util::amount::Amount;

        pub fn serialize<S: Serializer>(a: &Amount, s: S) -> Result<S::Ok, S::Error> {
            i64::serialize(&a.as_sat(), s)
        }

        pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Amount, D::Error> {
            Ok(Amount::from_sat(i64::deserialize(d)?))
        }

        pub mod opt {
            //! Serialize and deserialize [Optoin<Amount>] as real numbers denominated in satoshi.
            //! Use with `#[serde(default, with = "amount::serde::as_sat::opt")]`.

            use serde::{Deserialize, Deserializer, Serializer};
            use util::amount::Amount;

            pub fn serialize<S: Serializer>(a: &Option<Amount>, s: S) -> Result<S::Ok, S::Error> {
                match *a {
                    Some(a) => s.serialize_some(&a.as_sat()),
                    None => s.serialize_none(),
                }
            }

            pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Option<Amount>, D::Error> {
                Ok(Some(Amount::from_sat(i64::deserialize(d)?)))
            }
        }
    }

    pub mod as_btc {
        //! Serialize and deserialize [Amount] as JSON numbers denominated in BTC.
        //! Use with `#[serde(with = "amount::serde::as_btc")]`.

        use serde::{Deserialize, Deserializer, Serialize, Serializer};
        use util::amount::{Amount, Denomination};

        pub fn serialize<S: Serializer>(a: &Amount, s: S) -> Result<S::Ok, S::Error> {
            f64::serialize(&a.to_float_in(Denomination::Bitcoin), s)
        }

        pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Amount, D::Error> {
            use serde::de::Error;
            Ok(Amount::from_btc(f64::deserialize(d)?).map_err(D::Error::custom)?)
        }

        pub mod opt {
            //! Serialize and deserialize [Option<Amount>] as JSON numbers denominated in BTC.
            //! Use with `#[serde(default, with = "amount::serde::as_btc::opt")]`.

            use serde::{Deserialize, Deserializer, Serializer};
            use util::amount::{Amount, Denomination};

            pub fn serialize<S: Serializer>(a: &Option<Amount>, s: S) -> Result<S::Ok, S::Error> {
                match *a {
                    Some(a) => s.serialize_some(&a.to_float_in(Denomination::Bitcoin)),
                    None => s.serialize_none(),
                }
            }

            pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Option<Amount>, D::Error> {
                use serde::de::Error;
                Ok(Some(Amount::from_btc(f64::deserialize(d)?).map_err(D::Error::custom)?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[cfg(feature = "serde")]
    use serde_test;

    #[test]
    fn add_sub_mul_div() {
        use std::panic;
        let sat = Amount::from_sat;

        assert_eq!(sat(15) + sat(15), sat(30));
        assert_eq!(sat(15) - sat(15), sat(0));
        assert_eq!(sat(14) * 3, sat(42));
        assert_eq!(sat(14) / 2, sat(7));
        assert_eq!(sat(14) % 3, sat(2));
        assert_eq!(sat(15) - sat(20), sat(-5));
        assert_eq!(sat(-14) * 3, sat(-42));
        assert_eq!(sat(-14) / 2, sat(-7));
        assert_eq!(sat(-14) % 3, sat(-2));

        let mut b = sat(-5);
        b += sat(13);
        assert_eq!(b, sat(8));
        b -= sat(3);
        assert_eq!(b, sat(5));
        b *= 6;
        assert_eq!(b, sat(30));
        b /= 3;
        assert_eq!(b, sat(10));
        b %= 3;
        assert_eq!(b, sat(1));

        // panic on overflow
        let result = panic::catch_unwind(|| Amount::max_value() + Amount::from_sat(1));
        assert!(result.is_err());
        let result = panic::catch_unwind(|| Amount::from_sat(8446744073709551615) * 3);
        assert!(result.is_err());
    }

    #[test]
    fn checked_arithmetic() {
        let sat = Amount::from_sat;

        assert_eq!(sat(42).checked_add(sat(1)), Some(sat(43)));
        assert_eq!(Amount::max_value().checked_add(sat(1)), None);
        assert_eq!(Amount::min_value().checked_sub(sat(1)), None);

        assert_eq!(sat(5).checked_sub(sat(3)), Some(sat(2)));
        assert_eq!(sat(5).checked_sub(sat(6)), Some(sat(-1)));
        assert_eq!(sat(5).checked_rem(2), Some(sat(1)));

        assert_eq!(sat(5).checked_div(2), Some(sat(2))); // integer division
        assert_eq!(sat(-6).checked_div(2), Some(sat(-3)));

        assert_eq!(sat(-5).positive_sub(sat(3)), None);
        assert_eq!(sat(5).positive_sub(sat(-3)), None);
        assert_eq!(sat(3).positive_sub(sat(5)), None);
        assert_eq!(sat(3).positive_sub(sat(3)), Some(sat(0)));
        assert_eq!(sat(5).positive_sub(sat(3)), Some(sat(2)));
    }

    #[test]
    fn floating_point() {
        use super::Denomination as D;
        let f = Amount::from_float_in;
        let sat = Amount::from_sat;

        assert_eq!(f(11.22, D::Bitcoin), Ok(sat(1122000000)));
        assert_eq!(f(-11.22, D::MilliBitcoin), Ok(sat(-1122000)));
        assert_eq!(f(11.22, D::Bit), Ok(sat(1122)));
        assert_eq!(f(-1000.0, D::MilliSatoshi), Ok(sat(-1)));
        assert_eq!(f(0.0001234, D::Bitcoin), Ok(sat(12340)));
        assert_eq!(f(-0.00012345, D::Bitcoin), Ok(sat(-12345)));

        assert_eq!(f(11.22, D::Satoshi), Err(ParseAmountError::TooPrecise));
        assert_eq!(f(-100.0, D::MilliSatoshi), Err(ParseAmountError::TooPrecise));
        assert_eq!(f(42.123456781, D::Bitcoin), Err(ParseAmountError::TooPrecise));
        assert_eq!(f(-184467440738.0, D::Bitcoin), Err(ParseAmountError::TooBig));
        assert_eq!(f(18446744073709551617.0, D::Satoshi), Err(ParseAmountError::TooBig));
        assert_eq!(
            f(Amount::max_value().to_float_in(D::Satoshi) + 1.0, D::Satoshi),
            Err(ParseAmountError::TooBig)
        );

        let btc = move |f| Amount::from_btc(f).unwrap();
        assert_eq!(btc(2.5).to_float_in(D::Bitcoin), 2.5);
        assert_eq!(btc(-2.5).to_float_in(D::MilliBitcoin), -2500.0);
        assert_eq!(btc(2.5).to_float_in(D::Satoshi), 250000000.0);
        assert_eq!(btc(-2.5).to_float_in(D::MilliSatoshi), -250000000000.0);
    }

    #[test]
    fn parsing() {
        use super::ParseAmountError as E;
        let btc = Denomination::Bitcoin;
        let p = Amount::from_str_in;

        assert_eq!(p("x", btc), Err(E::InvalidCharacter('x')));
        assert_eq!(p("-", btc), Err(E::InvalidFormat));
        assert_eq!(p("-1.0x", btc), Err(E::InvalidCharacter('x')));
        assert_eq!(p("0.0 ", btc), Err(ParseAmountError::InvalidCharacter(' ')));
        assert_eq!(p("0.000.000", btc), Err(E::InvalidFormat));
        let more_than_max = format!("1{}", Amount::max_value());
        assert_eq!(p(&more_than_max, btc), Err(E::TooBig));
        assert_eq!(p("0.000000042", btc), Err(E::TooPrecise));

        assert_eq!(p("1", btc), Ok(Amount::from_sat(1_000_000_00)));
        assert_eq!(p("-.5", btc), Ok(Amount::from_sat(-500_000_00)));
        assert_eq!(p("1.1", btc), Ok(Amount::from_sat(1_100_000_00)));
        assert_eq!(
            p("12345678901.12345678", btc),
            Ok(Amount::from_sat(12_345_678_901__123_456_78))
        );
        assert_eq!(p("12.000", Denomination::MilliSatoshi), Err(E::TooPrecise));
    }

    #[test]
    fn to_string() {
        use super::Denomination as D;

        assert_eq!(Amount::ONE_BTC.to_string_in(D::Bitcoin), "1.00000000");
        assert_eq!(Amount::ONE_BTC.to_string_in(D::Satoshi), "100000000");
        assert_eq!(Amount::ONE_SAT.to_string_in(D::Bitcoin), "0.00000001");
        assert_eq!(Amount::from_sat(-42).to_string_in(D::Bitcoin), "-0.00000042");

        assert_eq!(Amount::ONE_BTC.to_string_with_denomination(D::Bitcoin), "1.00000000 BTC");
        assert_eq!(Amount::ONE_SAT.to_string_with_denomination(D::MilliSatoshi), "1000 msat");
        assert_eq!(Amount::ONE_BTC.to_string_with_denomination(D::Satoshi), "100000000 satoshi");
        assert_eq!(Amount::ONE_SAT.to_string_with_denomination(D::Bitcoin), "0.00000001 BTC");
        assert_eq!(Amount::from_sat(-42).to_string_with_denomination(D::Bitcoin), "-0.00000042 BTC");
    }

    #[test]
    fn from_str() {
        use super::ParseAmountError as E;
        let p = Amount::from_str;

        assert_eq!(p("x BTC"), Err(E::InvalidCharacter('x')));
        assert_eq!(p("5 BTC BTC"), Err(E::InvalidFormat));
        assert_eq!(p("5 5 BTC"), Err(E::InvalidFormat));

        assert_eq!(p("5 BCH"), Err(E::UnknownDenomination("BCH".to_owned())));

        assert_eq!(p("0.123456789 BTC"), Err(E::TooPrecise));
        assert_eq!(p("-0.1 satoshi"), Err(E::TooPrecise));
        assert_eq!(p("0.123456 mBTC"), Err(E::TooPrecise));
        assert_eq!(p("-1.001 bits"), Err(E::TooPrecise));
        assert_eq!(p("-200000000000 BTC"), Err(E::TooBig));
        assert_eq!(p("18446744073709551616 sat"), Err(E::TooBig));

        assert_eq!(p("0.00253583 BTC"), Ok(Amount::from_sat(253583)));
        assert_eq!(p("-5 satoshi"), Ok(Amount::from_sat(-5)));
        assert_eq!(p("0.10000000 BTC"), Ok(Amount::from_sat(100_000_00)));
        assert_eq!(p("-100 bits"), Ok(Amount::from_sat(-10_000)));
    }

    #[test]
    fn to_string_with_denomination_from_str_roundtrip() {
        use super::Denomination as D;

        let amt = Amount::from_sat(42);
        assert_eq!(Amount::from_str(&amt.to_string_with_denomination(D::Bitcoin)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_with_denomination(D::MilliBitcoin)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_with_denomination(D::MicroBitcoin)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_with_denomination(D::Bit)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_with_denomination(D::Satoshi)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_with_denomination(D::MilliSatoshi)), Ok(amt));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_sat() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(with = "::util::amount::serde::as_sat")]
            pub amt: Amount,
        }

        serde_test::assert_tokens(
            &T {
                amt: Amount::from_sat(123456789),
            },
            &[
                serde_test::Token::Struct {
                    name: "T",
                    len: 1,
                },
                serde_test::Token::Str("amt"),
                serde_test::Token::I64(123456789),
                serde_test::Token::StructEnd,
            ],
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_btc() {
        use serde::{Deserialize, Serialize};
        use serde_json;

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(with = "::util::amount::serde::as_btc")]
            pub amt: Amount,
        }

        let orig = T {
            amt: Amount::from_sat(21_000_000__000_000_01),
        };

        let t: T = serde_json::from_str("{\"amt\": 21000000.00000001}").unwrap();
        assert_eq!(t, orig);

        let value: serde_json::Value =
            serde_json::from_str("{\"amt\": 21000000.00000001}").unwrap();
        assert_eq!(t, serde_json::from_value(value).unwrap());

        // errors
        let t: Result<T, serde_json::Error> = serde_json::from_str("{\"amt\": -42.0.0}");
        assert!(t
            .unwrap_err()
            .to_string()
            .contains(&ParseAmountError::InvalidCharacter('.').to_string()));
        let t: Result<T, serde_json::Error> = serde_json::from_str("{\"amt\": 1000000.000000001}");
        assert!(t.unwrap_err().to_string().contains(&ParseAmountError::TooPrecise.to_string()));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_btc_opt() {
        use serde::{Deserialize, Serialize};
        use serde_json;

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(default, with = "::util::amount::serde::as_btc::opt")]
            pub amt: Option<Amount>,
        }

        let with = T {
            amt: Some(Amount::from_sat(2__500_000_00)),
        };
        let without = T {
            amt: None,
        };

        let t: T = serde_json::from_str("{\"amt\":2.5}").unwrap();
        assert_eq!(t, with);

        let t: T = serde_json::from_str("{}").unwrap();
        assert_eq!(t, without);

        let value_with: serde_json::Value = serde_json::from_str("{\"amt\": 2.5}").unwrap();
        assert_eq!(with, serde_json::from_value(value_with).unwrap());

        let value_without: serde_json::Value = serde_json::from_str("{}").unwrap();
        assert_eq!(without, serde_json::from_value(value_without).unwrap());
    }
}
