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
//! Defines a type `Amount` that can be used to express Bitcoin amounts in
//! different precisions and supports arithmetic and convertion to various
//! denominations.
//!
//!
//! Warning!
//!
//! In a few functions, this module supports convertion to and from floating-point numbers.
//! Please be aware of the risks of using floating-point numbers for financial applications.
//! These types of numbers do not give any guarantee to retain the precision
//! of the original amount when converting, or when doing arithmetic operations.
//!

use std::error;
use std::fmt::{self, Write};
use std::marker::PhantomData;
use std::ops;
use std::str::FromStr;

#[cfg(feature = "serde_json")]
use serde_json;

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
    fn precision(&self) -> i32 {
        match *self {
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
            "msat" => Ok(Denomination::MilliSatoshi),
            d => Err(ParseAmountError::UnknownDenomination(d.to_owned())),
        }
    }
}

/// An error during `Amount` parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseAmountError {
    /// Amount is too big to fit in the data type.
    TooBig,
    /// Amount has higher precision than supported by the type.
    TooPrecise,
    /// Invalid number format.
    InvalidFormat,
    /// The denomination was unknown.
    UnknownDenomination(String),
}

impl fmt::Display for ParseAmountError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseAmountError::TooBig => write!(f, "amount is too big"),
            ParseAmountError::TooPrecise => write!(f, "amount has a too high precision"),
            ParseAmountError::InvalidFormat => write!(f, "invalid number format"),
            ParseAmountError::UnknownDenomination(ref d) => {
                write!(f, "unknown denomination: {}", d)
            }
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
            ParseAmountError::UnknownDenomination(_) => "unknown denomination",
        }
    }
}

/// Type to indicate the precision of an Amount.
pub trait Precision: Copy + Clone + std::hash::Hash {
    /// The number of decimal places more than a satoshi.
    fn precision() -> i32;
}

/// Default precision for Bitcoin amounts: 1 satoshi.
#[derive(Copy, Clone, Hash)]
pub struct Satoshi;
impl Precision for Satoshi {
    fn precision() -> i32 {
        0
    }
}

/// Precision that allows a minimum amount of 0.001 satoshi.
#[derive(Copy, Clone, Hash)]
pub struct MilliSatoshi;
impl Precision for MilliSatoshi {
    fn precision() -> i32 {
        3
    }
}

/// The inner type used to represent amounts.
type Inner = i64;

/// Used to do math with Inner types.
const INNER_TEN: Inner = 10;

/// Rescale an inner value by a number of orders of magnitudes (powers of 10).
#[inline]
fn rescale_inner(inner: Inner, exp: i32) -> Inner {
    if exp == 0 {
        inner
    } else if exp < 0 {
        inner.checked_div((INNER_TEN).pow(-exp as u32)).unwrap()
    } else {
        inner.checked_mul((INNER_TEN).pow(exp as u32)).unwrap()
    }
}

/// First rescale the float value by the given number of orders of magnitude;
/// and then convert it to the Inner type.
#[inline]
fn pow_round_and_to_inner(v: f64, exp: i32) -> Inner {
    let amt = v * 10f64.powi(exp);
    if v < 0.0 {
        (amt - 0.5) as Inner
    } else {
        (amt + 0.5) as Inner
    }
}

/// Type to represent Bitcoin amounts.
///
/// The default precision is satoshi.
#[derive(Copy, Clone, Hash)]
pub struct Amount<P: Precision = Satoshi>(Inner, PhantomData<P>);

impl Amount<Satoshi> {
    /// Create an Amount with satoshi precision and the given number of satoshis.
    pub fn sat(satoshi: Inner) -> Amount<Satoshi> {
        Amount(satoshi, PhantomData)
    }
}

impl Amount<MilliSatoshi> {
    /// Create an Amount with msat precision and the given number of millisatoshis.
    pub fn msat(msat: Inner) -> Amount<MilliSatoshi> {
        Amount(msat, PhantomData)
    }


}

impl<P: Precision> Amount<P> {
    /// Create a new Amount using `amount` as the Inner type.
    ///
    /// Use this method with care, consider using `from_sat` instead.
    fn from_inner(amount: Inner) -> Amount<P> {
        Amount(amount, PhantomData)
    }

    /// The zero value of this amount.
    pub fn zero() -> Amount<P> {
        Amount::from_inner(0)
    }

    /// The one value of this amount.
    ///
    /// For one satoshi, use `from_sat(1)` instead.
    pub fn one() -> Amount<P> {
        Amount::from_inner(1)
    }

    /// Create an Amount with given amount of satoshis.
    pub fn from_sat(satoshis: i64) -> Amount<P> {
        Amount::from_inner(rescale_inner(satoshis.into(), P::precision()))
    }

    /// Convert from a value expressing bitcoins to an Amount.
    pub fn from_btc<T: IntoBtc<P>>(btc: T) -> Amount<P> {
        btc.into_btc()
    }

    /// Get the number of satoshis in this amount.
    pub fn as_sat(self) -> i64 {
        rescale_inner(self.0, -P::precision()).into()
    }

    /// Get the number of millisatoshis in this amount.
    pub fn as_msat(self) -> i64 {
        rescale_inner(self.0, 3-P::precision()).into()
    }

    /// Parse a decimal string as a value in the given denomination.
    ///
    /// Note: This only parses the value string.  If you want to parse a value with denomination,
    /// use `FromStr`.
    pub fn parse_denom(mut s: &str, denom: Denomination) -> Result<Amount<P>, ParseAmountError> {
        if s.len() == 0 {
            return Err(ParseAmountError::InvalidFormat);
        }

        let negative = s.chars().nth(0).unwrap() == '-';
        if negative {
            if s.len() == 1 {
                return Err(ParseAmountError::InvalidFormat);
            }
            s = &s[1..];
        }

        let max_decimals = {
            let precision_diff = P::precision() - denom.precision();
            if precision_diff < 0 {
                // If precision diff is negative, this means we are parsing into a less 
                // precise amount.  That is not allowed unless the last digits are zeroes 
                // as many as the diffence in precision.
                let last_n = (-precision_diff) as usize;
                if !s.chars().skip(s.len()-last_n).all(|d| d == '0') {
                    return Err(ParseAmountError::TooPrecise);
                }
                s = &s[0..s.len()-last_n];
                0
            } else {
                precision_diff
            }
        };

        let mut decimals = None;
        let mut value: Inner = 0;
        for c in s.as_bytes() {
            match *c {
                b'0'...b'9' => {
                    // Do `value = 10 * value + digit`, catching overflows.
                    match INNER_TEN.checked_mul(value) {
                        None => return Err(ParseAmountError::TooBig),
                        Some(n) => match n.checked_add((c - b'0').into()) {
                            None => return Err(ParseAmountError::TooBig),
                            Some(n) => value = n,
                        },
                    }
                    // Increment the decimal digit counter if past decimal.
                    decimals = match decimals {
                        None => None,
                        Some(d) if d == max_decimals => return Err(ParseAmountError::TooPrecise),
                        Some(d) => Some(d + 1),
                    }
                }
                b'.' => match decimals {
                    None => decimals = Some(0),
                    Some(_) => return Err(ParseAmountError::InvalidFormat),
                },
                _ => return Err(ParseAmountError::InvalidFormat),
            }
        }

        // Decimally shift left by `max_decimals - decimals`.
        let scalefactor = max_decimals - decimals.or_else(|| Some(0)).unwrap();
        for _ in 0..scalefactor {
            value = match INNER_TEN.checked_mul(value) {
                Some(v) => v,
                None => return Err(ParseAmountError::TooBig),
            };
        }

        if negative {
            value *= -1;
        }

        Ok(Amount::from_inner(value))
    }

    /// Express this Amount as a floating-point value in the given denomination.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn float_denomination(&self, denom: Denomination) -> f64 {
        let exp = denom.precision() - P::precision();
        if exp >= 0 {
            (self.0 as f64) * 10f64.powi(exp)
        } else {
            (self.0 as f64) / 10f64.powi(exp)
        }
    }

    /// Format the value of this Amount in the given denomination.
    pub fn fmt_value_in(&self, f: &mut fmt::Write, denom: Denomination) -> fmt::Result {
        if denom.precision() == P::precision() {
            write!(f, "{}", self.0)?;
        } else if denom.precision() > P::precision() {
            // add decimal point and zeroes
            let width = (denom.precision() - P::precision()) as usize;
            write!(f, "{}.{:0width$}", self.0, 0, width = width)?;
        } else {
            // need to inject a comma in the numbered
            let nb_decimals = (P::precision() - denom.precision()) as usize;
            let real = format!("{:0width$}", self.0, width = nb_decimals);
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
        Ok(())
    }

    /// Get a formatted string of this Amount in the given denomination,
    /// followed by the shorthand of the denomination.
    pub fn to_string_in(&self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        write!(buf, " {}", denom).unwrap();
        buf
    }

    /// The maximum value of an Amount.
    pub fn max_value() -> Amount<P> {
        Amount::from_inner(Inner::max_value())
    }

    /// The minimum value of an amount.
    pub fn min_value() -> Amount<P> {
        Amount::from_inner(Inner::min_value())
    }

    /// Convert to a new Amount by rescaling this one to a new precision.
    /// Note that some decimals will get lost if the new precision is lower.
    pub fn rescale<O: Precision>(self) -> Amount<O> {
        let amt = rescale_inner(self.0, O::precision() - P::precision());
        Amount::from_inner(amt)
    }
}

impl<P: Precision> fmt::Debug for Amount<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match P::precision() {
            0 => write!(f, "Amount({} sat)", self.0),
            3 => write!(f, "Amount({} msat)", self.0),
            p => write!(f, "Amount({} precision={})", self.0, p),
        }
    }
}

impl<P: Precision> fmt::Display for Amount<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_value_in(f, Denomination::Bitcoin)?;
        write!(f, " {}", Denomination::Bitcoin)
    }
}

impl<P: Precision> ops::Add for Amount<P> {
    type Output = Amount<P>;

    fn add(self, rhs: Amount<P>) -> Self::Output {
        Amount::from_inner(self.0 + rhs.0)
    }
}

impl<P: Precision> ops::Sub for Amount<P> {
    type Output = Amount<P>;

    fn sub(self, rhs: Amount<P>) -> Self::Output {
        Amount::from_inner(self.0 - rhs.0)
    }
}

impl<P: Precision> ops::Mul<i64> for Amount<P> {
    type Output = Amount<P>;

    fn mul(self, rhs: i64) -> Self::Output {
        let rhs_inner: Inner = rhs.into();
        Amount::from_inner(self.0 * rhs_inner)
    }
}

impl<P: Precision> ops::Div for Amount<P> {
    type Output = f64;

    fn div(self, rhs: Amount<P>) -> Self::Output {
        self.0 as f64 / rhs.0 as f64
    }
}

impl<P: Precision> ops::Div<f64> for Amount<P> {
    type Output = Amount<P>;

    fn div(self, rhs: f64) -> Self::Output {
        Amount::from_inner((self.0 as f64 / rhs) as Inner)
    }
}

impl<P: Precision> PartialEq for Amount<P> {
    fn eq(&self, other: &Amount<P>) -> bool {
        PartialEq::eq(&self.0, &other.0)
    }
}
impl<P: Precision> Eq for Amount<P> {}

impl<P: Precision> PartialOrd for Amount<P> {
    fn partial_cmp(&self, other: &Amount<P>) -> Option<::std::cmp::Ordering> {
        PartialOrd::partial_cmp(&self.0, &other.0)
    }
}

impl<P: Precision> Ord for Amount<P> {
    fn cmp(&self, other: &Amount<P>) -> ::std::cmp::Ordering {
        Ord::cmp(&self.0, &other.0)
    }
}

impl<P: Precision> FromStr for Amount<P> {
    type Err = ParseAmountError;

    /// Parses amounts with denomination suffix like they are produced with
    /// `to_string_in()`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.splitn(3, " ");
        let amt_str = split.next().unwrap();
        let denom_str = split.next().ok_or(ParseAmountError::InvalidFormat)?;
        if split.next().is_some() {
            return Err(ParseAmountError::InvalidFormat);
        }

        Ok(Amount::parse_denom(amt_str, denom_str.parse()?)?)
    }
}

/// A trait used to convert BTC-denominated value types into Amounts
pub trait IntoBtc<P: Precision> {
    /// Convert the given BTC-denominated value into an Amount.
    fn into_btc(self) -> Amount<P>;
}

impl<P: Precision> IntoBtc<P> for f64 {
    fn into_btc(self) -> Amount<P> {
        Amount::from_inner(pow_round_and_to_inner(self, P::precision() + 8))
    }
}

impl<'a, P: Precision> IntoBtc<P> for &'a f64 {
    fn into_btc(self) -> Amount<P> {
        Amount::from_inner(pow_round_and_to_inner(*self, P::precision() + 8))
    }
}

#[cfg(feature = "serde_json")]
impl<P: Precision> IntoBtc<P> for serde_json::value::Number {
    fn into_btc(self) -> Amount<P> {
        Amount::parse_denom(self.to_string(), Denomination::Bitcoin).unwrap()
    }
}

#[cfg(feature = "serde_json")]
impl<'a, P: Precision> IntoBtc<P> for &'a serde_json::value::Number {
    fn into_btc(self) -> Amount<P> {
        Amount::parse_denom(self.to_string(), Denomination::Bitcoin).unwrap()
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
    //! #[macro_use]
    //! use serde_derive;
    //! use bitcoin::util::amount::Amount;
    //!
    //! #[derive(Serialize, Deserialize)]
    //! pub struct HasAmount {
    //!     #[serde(with = "bitcoin::util::amount::serde::as_btc")]
    //!     pub amount: Amount,
    //! }
    //! ```

    pub mod as_satoshi {
        //! Serialize and deserialize Amounts as real numbers denominated in satoshi.

        use serde::{self, Deserialize, Serialize};
        use util::amount::{Amount, Precision};

        pub fn serialize<P: Precision, S>(amt: &Amount<P>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::ser::Serializer,
        {
            i64::serialize(&amt.as_sat(), serializer)
        }

        pub fn deserialize<'de, P: Precision, D>(deserializer: D) -> Result<Amount<P>, D::Error>
        where
            D: serde::de::Deserializer<'de>,
        {
            Ok(Amount::from_sat(i64::deserialize(deserializer)?))
        }
    }

    pub mod as_btc {
        //! Serialize and deserialize Amounts as floating point JSON numbers denominated in BTC.

        use serde::{self, Deserialize, Serialize};
        use util::amount::{Amount, Denomination, Precision};

        pub fn serialize<P: Precision, S>(amt: &Amount<P>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::ser::Serializer,
        {
            f64::serialize(&amt.float_denomination(Denomination::Bitcoin), serializer)
        }

        pub fn deserialize<'de, P: Precision, D>(deserializer: D) -> Result<Amount<P>, D::Error>
        where
            D: serde::de::Deserializer<'de>,
        {
            Ok(Amount::from_btc(f64::deserialize(deserializer)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;
    use std::str::FromStr;

    #[cfg(feature = "serde")]
    use serde_test;

    use super::*;
    #[cfg(feature = "serde")]
    use util::amount; // for serde derive

    type Amt = Amount<Satoshi>;
    static ONE_BTC: Amt = Amount(100_000_000, PhantomData);
    static ONE_SAT: Amt = Amount(1, PhantomData);
    static ONE_MSAT: Amount<MilliSatoshi> = Amount(1, PhantomData);

    #[test]
    fn rescaling() {
        assert_eq!(ONE_SAT.as_rescaled::<Satoshi>().into_inner(), 1);
        assert_eq!(ONE_MSAT.as_rescaled::<MilliSatoshi>().into_inner(), 1);

        assert_eq!(ONE_BTC.as_rescaled::<Satoshi>().into_inner(), 100_000_000);
        assert_eq!(ONE_SAT.as_rescaled::<MilliSatoshi>().into_inner(), 1_000);

        assert_eq!(ONE_MSAT.as_rescaled::<Satoshi>().into_inner(), 0);
    }

    #[test]
    fn add_sub_mul_div() {
        assert_eq!(Amount::from_btc(0.15) + Amount::from_btc(0.015), Amount::sat(16_500_000));
        assert_eq!(Amount::from_btc(0.15) - Amount::from_btc(0.015), Amount::sat(13_500_000));

        assert_eq!(Amount::from_btc(0.014) * 3, Amount::sat(4_200_000));
        assert_eq!(Amount::from_btc(0.014) * -3, Amount::sat(-4_200_000));

        assert_eq!((Amount::from_btc(0.225) / Amount::sat(7_500_000)) as usize, 3)
    }

    #[test]
    fn into_btc() {
        let amt: Amount = 0.25.into_btc(); // type annotaion needed
        assert_eq!(amt.into_inner(), 25_000_000);
        let amt: Amount = Amount::from_btc(0.25);
        assert_eq!(amt.into_inner(), 25_000_000);
    }

    #[test]
    fn parsing() {
        use super::ParseAmountError as E;
        let btc = Denomination::Bitcoin;
        let p = Amt::parse_denom;

        assert_eq!(p("x", btc), Err(E::InvalidFormat));
        assert_eq!(p("-", btc), Err(E::InvalidFormat));
        assert_eq!(p("-0.0-", btc), Err(E::InvalidFormat));
        assert_eq!(p("-0.0 ", btc), Err(E::InvalidFormat));
        assert_eq!(p("0.000.000", btc), Err(E::InvalidFormat));
        let more_than_max = format!("1{}", Amt::max_value());
        assert_eq!(p(&more_than_max, btc), Err(E::TooBig));
        assert_eq!(p("0.000000042", btc), Err(E::TooPrecise));

        assert_eq!(p("1", btc), Ok(Amt::sat(1_000_000_00)));
        assert_eq!(p("-1", btc), Ok(Amt::sat(-1_000_000_00)));
        assert_eq!(p("1.1", btc), Ok(Amt::sat(1_100_000_00)));
        assert_eq!(p("-12345678.12345678", btc), Ok(Amt::sat(-12_345_678__123_456_78)));
        assert_eq!(p("12345678901.12345678", btc), Ok(Amt::sat(12_345_678_901__123_456_78)));
    }

    #[test]
    fn to_string_in() {
        assert_eq!(ONE_BTC.to_string_in(Denomination::Bitcoin), "1.00000000 BTC");
        assert_eq!(ONE_BTC.to_string_in(Denomination::Satoshi), "100000000 satoshi");
        assert_eq!(ONE_SAT.to_string_in(Denomination::Bitcoin), "0.00000001 BTC");
        assert_eq!(Amount::sat(42).to_string_in(Denomination::Bitcoin), "0.00000042 BTC");
    }

    #[test]
    fn from_str() {
        use super::ParseAmountError as E;
        assert_eq!(Amt::from_str("x BTC"), Err(E::InvalidFormat));
        assert_eq!(Amt::from_str("5 BTC BTC"), Err(E::InvalidFormat));
        assert_eq!(Amt::from_str("5 5 BTC"), Err(E::InvalidFormat));

        assert_eq!(Amt::from_str("5 BCH"), Err(E::UnknownDenomination("BCH".to_owned())));

        assert_eq!(Amt::from_str("0.123456789 BTC"), Err(E::TooPrecise));
        assert_eq!(Amt::from_str("0.1 satoshi"), Err(E::TooPrecise));
        assert_eq!(Amt::from_str("0.123456 mBTC"), Err(E::TooPrecise));
        assert_eq!(Amt::from_str("1.001 bits"), Err(E::TooPrecise));
        assert_eq!(Amt::from_str("100000000000 BTC"), Err(E::TooBig));

        assert_eq!(Amt::from_str("0.00253583 BTC"), Ok(Amount::sat(253583)));
        assert_eq!(Amt::from_str("5 satoshi"), Ok(Amount::sat(5)));
        assert_eq!(Amt::from_str("0.10000000 BTC"), Ok(Amount::sat(100_000_00)));
        assert_eq!(Amt::from_str("100 bits"), Ok(Amount::sat(10_000)));
    }

    #[test]
    fn to_string_in_from_str_roundtrip() {
        use super::Denomination as D;

        let amt = Amount::sat(42);
        assert_eq!(Amount::from_str(&amt.to_string_in(D::Bitcoin)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_in(D::MilliBitcoin)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_in(D::MicroBitcoin)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_in(D::Bit)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_in(D::Satoshi)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_in(D::MilliSatoshi)), Ok(amt));

        let amt = Amount::msat(42);
        assert_eq!(Amount::from_str(&amt.to_string_in(D::Bitcoin)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_in(D::MilliBitcoin)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_in(D::MicroBitcoin)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_in(D::Bit)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_in(D::Satoshi)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_in(D::MilliSatoshi)), Ok(amt));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_satoshi() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(with = "amount::serde::as_satoshi")]
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

        serde_test::assert_tokens(
            &T {
                amt: Amount::from_sat(-12345678),
            },
            &[
                serde_test::Token::Struct {
                    name: "T",
                    len: 1,
                },
                serde_test::Token::Str("amt"),
                serde_test::Token::I64(-12345678),
                serde_test::Token::StructEnd,
            ],
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_btc() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(with = "amount::serde::as_btc")]
            pub amt: Amount,
        }

        serde_test::assert_tokens(
            &T {
                amt: Amount::from_sat(2__500_000_00),
            },
            &[
                serde_test::Token::Struct {
                    name: "T",
                    len: 1,
                },
                serde_test::Token::Str("amt"),
                serde_test::Token::F64(2.5),
                serde_test::Token::StructEnd,
            ],
        );

        serde_test::assert_tokens(
            &T {
                amt: Amount::from_sat(-12345678_90000000),
            },
            &[
                serde_test::Token::Struct {
                    name: "T",
                    len: 1,
                },
                serde_test::Token::Str("amt"),
                serde_test::Token::F64(-12345678.9),
                serde_test::Token::StructEnd,
            ],
        );
    }
}
