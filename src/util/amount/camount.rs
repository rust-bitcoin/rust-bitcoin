// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//
use std::default;
use std::fmt::{self, Write};
use std::ops;
use std::str::FromStr;
use super::*;
/// Amount
///
/// The [Amount] type can be used to express Bitcoin amounts that supports
/// arithmetic and conversion to various denominations.
///
///
/// Warning!
///
/// This type implements several arithmetic operations from [std::ops].
/// To prevent errors due to overflow or underflow when using these operations,
/// it is advised to instead use the checked arithmetic methods whose names
/// start with `checked_`.  The operations from [std::ops] that [Amount]
/// implements will panic when overflow or underflow occurs.
///
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(i64);

impl Amount {
    /// The zero amount.
    pub const ZERO: Amount = Amount(0);
    /// Exactly one satoshi.
    pub const ONE_SAT: Amount = Amount(1);
    /// Exactly one bitcoin.
    pub const ONE_BTC: Amount = Amount(100_000_000);

    /// Create an [Amount] with satoshi precision and the given number of satoshis.
    pub fn from_sat(satoshi: i64) -> Amount {
        Amount(satoshi)
    }

    /// Get the number of satoshis in this [Amount].
    pub fn as_sat(self) -> i64 {
        self.0
    }

    /// The maximum value of an [Amount].
    pub fn max_value() -> Amount {
        Amount(i64::max_value())
    }

    /// The minimum value of an [Amount].
    pub fn min_value() -> Amount {
        Amount(i64::min_value())
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
        if satoshi > i64::max_value() as u64 {
            return Err(ParseAmountError::TooBig);
        }
        Ok(match negative {
            true => Amount(-(satoshi as i64)),
            false => Amount(satoshi as i64),
        })
    }

    /// Parses amounts with denomination suffix like they are produced with
    /// [to_string_with_denomination] or with [fmt::Display].
    /// If you want to parse only the amount without the denomination,
    /// use [from_str_in].
    pub fn from_str_with_denomination(s: &str) -> Result<Amount, ParseAmountError> {
        let mut split = s.splitn(3, ' ');
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
    pub fn from_float_in(
        value: f64,
        denom: Denomination,
    ) -> Result<Amount, ParseAmountError> {
        // This is inefficient, but the safest way to deal with this. The parsing logic is safe.
        // Any performance-critical application should not be dealing with floats.
        Amount::from_str_in(&value.to_string(), denom)
    }

    /// Format the value of this [Amount] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn fmt_value_in(self, f: &mut dyn fmt::Write, denom: Denomination) -> fmt::Result {
        let sats = self.as_sat().checked_abs().map(|a: i64| a as u64).unwrap_or_else(|| {
            // We could also hard code this into `9223372036854775808`
            u64::max_value() - self.as_sat() as u64 +1
        });
        fmt_satoshi_in(sats, self.is_negative(), f, denom)
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

    // Some arithmetic that doesn't fit in `std::ops` traits.

    /// Get the absolute value of this [Amount].
    pub fn abs(self) -> Amount {
        Amount(self.0.abs())
    }

    /// Returns a number representing sign of this [Amount].
    ///
    /// - `0` if the amount is zero
    /// - `1` if the amount is positive
    /// - `-1` if the amount is negative
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


    /// Get the absolute value of this [Amount].
    /// Returns [None] if overflow occurred. (`self == min_value()`)
    pub fn checked_abs(self) -> Option<Amount> {
        self.0.checked_abs().map(Amount)
    }

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
    pub fn checked_mul(self, rhs: i64) -> Option<Amount> {
        self.0.checked_mul(rhs).map(Amount)
    }

    /// Checked integer division.
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made.
    /// Returns [None] if overflow occurred.
    pub fn checked_div(self, rhs: i64) -> Option<Amount> {
        self.0.checked_div(rhs).map(Amount)
    }

    /// Checked remainder.
    /// Returns [None] if overflow occurred.
    pub fn checked_rem(self, rhs: i64) -> Option<Amount> {
        self.0.checked_rem(rhs).map(Amount)
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

    /// Convert to an unsigned amount.
    pub fn to_unsigned(self) -> Result<UnsignedAmount, ParseAmountError> {
        if self.is_negative() {
            Err(ParseAmountError::Negative)
        } else {
            Ok(UnsignedAmount::from_sat(self.as_sat() as u64))
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
const _: () = {
    use serde::{Deserializer, Serializer, Deserialize, Serialize, de::Error};
    use std::convert::TryFrom;
    impl Serialize for Amount {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            ApiAmount::from(self.clone()).serialize(serializer)
        }
    }
    impl<'de> Deserialize<'de> for Amount {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let a = ApiAmount::deserialize(deserializer)?;
            Amount::try_from(a).map_err(Error::custom)
        }
    }
};

#[cfg(feature="schemars")]
const _: () = {
    use schemars::{JsonSchema, gen, schema::Schema};
    impl JsonSchema for Amount {
        fn json_schema(gen: &mut gen::SchemaGenerator) -> Schema {
            ApiAmount::json_schema(gen)
        }
        fn schema_name() -> String {
            "Amount".into()
        }
    }
};

