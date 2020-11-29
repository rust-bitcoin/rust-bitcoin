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
/// UnsignedAmount
///
/// The [UnsignedAmount] type can be used to express Bitcoin amounts that supports
/// arithmetic and conversion to various denominations.
///
///
/// Warning!
///
/// This type implements several arithmetic operations from [std::ops].
/// To prevent errors due to overflow or underflow when using these operations,
/// it is advised to instead use the checked arithmetic methods whose names
/// start with `checked_`.  The operations from [std::ops] that [UnsignedAmount]
/// implements will panic when overflow or underflow occurs.  Also note that
/// since the internal representation of amounts is unsigned, subtracting below
/// zero is considered an underflow and will cause a panic if you're not using
/// the checked arithmetic methods.
///
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnsignedAmount(u64);

impl UnsignedAmount {
    /// The zero amount.
    pub const ZERO: UnsignedAmount = UnsignedAmount(0);
    /// Exactly one satoshi.
    pub const ONE_SAT: UnsignedAmount = UnsignedAmount(1);
    /// Exactly one bitcoin.
    pub const ONE_BTC: UnsignedAmount = UnsignedAmount(100_000_000);

    /// Create an [UnsignedAmount] with satoshi precision and the given number of satoshis.
    pub fn from_sat(satoshi: u64) -> UnsignedAmount {
        UnsignedAmount(satoshi)
    }

    /// Get the number of satoshis in this [UnsignedAmount].
    pub fn as_sat(self) -> u64 {
        self.0
    }

    /// The maximum value of an [UnsignedAmount].
    pub fn max_value() -> UnsignedAmount {
        UnsignedAmount(u64::max_value())
    }

    /// The minimum value of an [UnsignedAmount].
    pub fn min_value() -> UnsignedAmount {
        UnsignedAmount(u64::min_value())
    }

    /// Convert from a value expressing bitcoins to an [UnsignedAmount].
    pub fn from_btc(btc: f64) -> Result<UnsignedAmount, ParseAmountError> {
        UnsignedAmount::from_float_in(btc, Denomination::Bitcoin)
    }

    /// Parse a decimal string as a value in the given denomination.
    ///
    /// Note: This only parses the value string.  If you want to parse a value
    /// with denomination, use [FromStr].
    pub fn from_str_in(s: &str, denom: Denomination) -> Result<UnsignedAmount, ParseAmountError> {
        let (negative, satoshi) = parse_signed_to_satoshi(s, denom)?;
        if negative {
            return Err(ParseAmountError::Negative);
        }
        if satoshi > i64::max_value() as u64 {
            return Err(ParseAmountError::TooBig);
        }
        Ok(UnsignedAmount::from_sat(satoshi))
    }

    /// Parses amounts with denomination suffix like they are produced with
    /// [to_string_with_denomination] or with [fmt::Display].
    /// If you want to parse only the amount without the denomination,
    /// use [from_str_in].
    pub fn from_str_with_denomination(s: &str) -> Result<UnsignedAmount, ParseAmountError> {
        let mut split = s.splitn(3, ' ');
        let amt_str = split.next().unwrap();
        let denom_str = split.next().ok_or(ParseAmountError::InvalidFormat)?;
        if split.next().is_some() {
            return Err(ParseAmountError::InvalidFormat);
        }

        Ok(UnsignedAmount::from_str_in(amt_str, denom_str.parse()?)?)
    }

    /// Express this [UnsignedAmount] as a floating-point value in the given denomination.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn to_float_in(self, denom: Denomination) -> f64 {
        f64::from_str(&self.to_string_in(denom)).unwrap()
    }

    /// Express this [UnsignedAmount] as a floating-point value in Bitcoin.
    ///
    /// Equivalent to `to_float_in(Denomination::Bitcoin)`.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn as_btc(self) -> f64 {
        self.to_float_in(Denomination::Bitcoin)
    }

    /// Convert this [UnsignedAmount] in floating-point notation with a given
    /// denomination.
    /// Can return error if the amount is too big, too precise or negative.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn from_float_in(value: f64, denom: Denomination) -> Result<UnsignedAmount, ParseAmountError> {
        if value < 0.0 {
            return Err(ParseAmountError::Negative);
        }
        // This is inefficient, but the safest way to deal with this. The parsing logic is safe.
        // Any performance-critical application should not be dealing with floats.
        UnsignedAmount::from_str_in(&value.to_string(), denom)
    }

    /// Format the value of this [UnsignedAmount] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn fmt_value_in(self, f: &mut dyn fmt::Write, denom: Denomination) -> fmt::Result {
        fmt_satoshi_in(self.as_sat(), false, f, denom)
    }

    /// Get a string number of this [UnsignedAmount] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn to_string_in(self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        buf
    }

    /// Get a formatted string of this [UnsignedAmount] in the given denomination,
    /// suffixed with the abbreviation for the denomination.
    pub fn to_string_with_denomination(self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        write!(buf, " {}", denom).unwrap();
        buf
    }

    // Some arithmetic that doesn't fit in `std::ops` traits.

    /// Checked addition.
    /// Returns [None] if overflow occurred.
    pub fn checked_add(self, rhs: UnsignedAmount) -> Option<UnsignedAmount> {
        self.0.checked_add(rhs.0).map(UnsignedAmount)
    }

    /// Checked subtraction.
    /// Returns [None] if overflow occurred.
    pub fn checked_sub(self, rhs: UnsignedAmount) -> Option<UnsignedAmount> {
        self.0.checked_sub(rhs.0).map(UnsignedAmount)
    }

    /// Checked multiplication.
    /// Returns [None] if overflow occurred.
    pub fn checked_mul(self, rhs: u64) -> Option<UnsignedAmount> {
        self.0.checked_mul(rhs).map(UnsignedAmount)
    }

    /// Checked integer division.
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made.
    /// Returns [None] if overflow occurred.
    pub fn checked_div(self, rhs: u64) -> Option<UnsignedAmount> {
        self.0.checked_div(rhs).map(UnsignedAmount)
    }

    /// Checked remainder.
    /// Returns [None] if overflow occurred.
    pub fn checked_rem(self, rhs: u64) -> Option<UnsignedAmount> {
        self.0.checked_rem(rhs).map(UnsignedAmount)
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

impl default::Default for UnsignedAmount {
    fn default() -> Self {
        UnsignedAmount::ZERO
    }
}

impl fmt::Debug for UnsignedAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UnsignedAmount({} satoshi)", self.as_sat())
    }
}

// No one should depend on a binding contract for Display for this type.
// Just using Bitcoin denominated string.
impl fmt::Display for UnsignedAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_value_in(f, Denomination::Bitcoin)?;
        write!(f, " {}", Denomination::Bitcoin)
    }
}

impl ops::Add for UnsignedAmount {
    type Output = UnsignedAmount;

    fn add(self, rhs: UnsignedAmount) -> Self::Output {
        self.checked_add(rhs).expect("UnsignedAmount addition error")
    }
}

impl ops::AddAssign for UnsignedAmount {
    fn add_assign(&mut self, other: UnsignedAmount) {
        *self = *self + other
    }
}

impl ops::Sub for UnsignedAmount {
    type Output = UnsignedAmount;

    fn sub(self, rhs: UnsignedAmount) -> Self::Output {
        self.checked_sub(rhs).expect("UnsignedAmount subtraction error")
    }
}

impl ops::SubAssign for UnsignedAmount {
    fn sub_assign(&mut self, other: UnsignedAmount) {
        *self = *self - other
    }
}

impl ops::Rem<u64> for UnsignedAmount {
    type Output = UnsignedAmount;

    fn rem(self, modulus: u64) -> Self {
        self.checked_rem(modulus).expect("UnsignedAmount remainder error")
    }
}

impl ops::RemAssign<u64> for UnsignedAmount {
    fn rem_assign(&mut self, modulus: u64) {
        *self = *self % modulus
    }
}

impl ops::Mul<u64> for UnsignedAmount {
    type Output = UnsignedAmount;

    fn mul(self, rhs: u64) -> Self::Output {
        self.checked_mul(rhs).expect("UnsignedAmount multiplication error")
    }
}

impl ops::MulAssign<u64> for UnsignedAmount {
    fn mul_assign(&mut self, rhs: u64) {
        *self = *self * rhs
    }
}

impl ops::Div<u64> for UnsignedAmount {
    type Output = UnsignedAmount;

    fn div(self, rhs: u64) -> Self::Output {
        self.checked_div(rhs).expect("UnsignedAmount division error")
    }
}

impl ops::DivAssign<u64> for UnsignedAmount {
    fn div_assign(&mut self, rhs: u64) {
        *self = *self / rhs
    }
}

impl FromStr for UnsignedAmount {
    type Err = ParseAmountError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        UnsignedAmount::from_str_with_denomination(s)
    }
}

#[cfg(feature = "serde")]
const _: () = {
    use serde::{Deserializer, Serializer, Deserialize, Serialize, de::Error};
    use std::convert::TryFrom;
    impl Serialize for UnsignedAmount {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            ApiAmount::from(self.clone()).serialize(serializer)
        }
    }
    impl<'de> Deserialize<'de> for UnsignedAmount {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let a = ApiAmount::deserialize(deserializer)?;
            UnsignedAmount::try_from(a).map_err(Error::custom)
        }
    }
};

#[cfg(feature="schemars")]
const _: () = {
    use schemars::{JsonSchema, gen, schema::Schema};
    impl JsonSchema for UnsignedAmount {
        fn json_schema(gen: &mut gen::SchemaGenerator) -> Schema {
            ApiAmount::json_schema(gen)
        }
        fn schema_name() -> String {
            "Amount".into()
        }
    }
};
