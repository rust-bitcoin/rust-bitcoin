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
//! This module mainly introduces the [UnsignedAmount] and [SignedAmount] types.
//! We refer to the documentation on the types for more information.
//!

use std::error;
use std::fmt;
use std::str::FromStr;
use std::cmp::Ordering;

/// Provides an unsigned amount type
pub mod unsigned;
/// Provides a signed amount type, identical to Bitcoin Core's C++ representation
pub mod camount;
/// Provides a API Amount type which is either Sats (i64) or Btc (float)
pub mod api_amount;
pub use self::unsigned::UnsignedAmount;
pub use self::camount::Amount;
/// Alias for Amount to be Symmetric with UnsignedAmount.
pub type SignedAmount = Amount;
pub use self::api_amount::ApiAmount;


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
            ParseAmountError::UnknownDenomination(ref d) => write!(f, "unknown denomination: {}",d),
        }
    }
}

impl error::Error for ParseAmountError {}

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
    //! use bitcoin::UnsignedAmount;
    //!
    //! #[derive(Serialize, Deserialize)]
    //! pub struct HasAmount {
    //!     #[serde(with = "bitcoin::util::amount::serde::as_btc")]
    //!     pub amount: UnsignedAmount,
    //! }
    //! ```

    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use util::amount::{UnsignedAmount, Denomination, SignedAmount};

    /// This trait is used only to avoid code duplication and naming collisions
    /// of the different serde serialization crates.
    pub trait SerdeAmount: Copy + Sized {
        fn ser_sat<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error>;
        fn des_sat<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error>;
        fn ser_btc<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error>;
        fn des_btc<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error>;
    }

    impl SerdeAmount for UnsignedAmount {
        fn ser_sat<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            u64::serialize(&self.as_sat(), s)
        }
        fn des_sat<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            Ok(UnsignedAmount::from_sat(u64::deserialize(d)?))
        }
        fn ser_btc<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            f64::serialize(&self.to_float_in(Denomination::Bitcoin), s)
        }
        fn des_btc<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            use serde::de::Error;
            Ok(UnsignedAmount::from_btc(f64::deserialize(d)?).map_err(D::Error::custom)?)
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

    pub mod as_sat {
        //! Serialize and deserialize [UnsignedAmount] as real numbers denominated in satoshi.
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
            //! Serialize and deserialize [Optoin<UnsignedAmount>] as real numbers denominated in satoshi.
            //! Use with `#[serde(default, with = "amount::serde::as_sat::opt")]`.

            use serde::{Deserializer, Serializer};
            use util::amount::serde::SerdeAmount;

            pub fn serialize<A: SerdeAmount, S: Serializer>(
                a: &Option<A>,
                s: S,
            ) -> Result<S::Ok, S::Error> {
                match *a {
                    Some(a) => a.ser_sat(s),
                    None => s.serialize_none(),
                }
            }

            pub fn deserialize<'d, A: SerdeAmount, D: Deserializer<'d>>(
                d: D,
            ) -> Result<Option<A>, D::Error> {
                Ok(Some(A::des_sat(d)?))
            }
        }
    }

    pub mod as_btc {
        //! Serialize and deserialize [UnsignedAmount] as JSON numbers denominated in BTC.
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
            //! Serialize and deserialize [Option<UnsignedAmount>] as JSON numbers denominated in BTC.
            //! Use with `#[serde(default, with = "amount::serde::as_btc::opt")]`.

            use serde::{Deserializer, Serializer};
            use util::amount::serde::SerdeAmount;

            pub fn serialize<A: SerdeAmount, S: Serializer>(
                a: &Option<A>,
                s: S,
            ) -> Result<S::Ok, S::Error> {
                match *a {
                    Some(a) => a.ser_btc(s),
                    None => s.serialize_none(),
                }
            }

            pub fn deserialize<'d, A: SerdeAmount, D: Deserializer<'d>>(
                d: D,
            ) -> Result<Option<A>, D::Error> {
                Ok(Some(A::des_btc(d)?))
            }
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use std::panic;
    use std::str::FromStr;

    #[cfg(feature = "serde")]
    use serde_test;

    #[test]
    fn add_sub_mul_div() {
        let sat = UnsignedAmount::from_sat;
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

        // panic on overflow
        let result = panic::catch_unwind(|| UnsignedAmount::max_value() + UnsignedAmount::from_sat(1));
        assert!(result.is_err());
        let result = panic::catch_unwind(|| UnsignedAmount::from_sat(8446744073709551615) * 3);
        assert!(result.is_err());
    }

    #[test]
    fn checked_arithmetic() {
        let sat = UnsignedAmount::from_sat;
        let ssat = SignedAmount::from_sat;

        assert_eq!(sat(42).checked_add(sat(1)), Some(sat(43)));
        assert_eq!(SignedAmount::max_value().checked_add(ssat(1)), None);
        assert_eq!(SignedAmount::min_value().checked_sub(ssat(1)), None);
        assert_eq!(UnsignedAmount::max_value().checked_add(sat(1)), None);
        assert_eq!(UnsignedAmount::min_value().checked_sub(sat(1)), None);

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
        let f = UnsignedAmount::from_float_in;
        let sf = SignedAmount::from_float_in;
        let sat = UnsignedAmount::from_sat;
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
            f(UnsignedAmount::max_value().to_float_in(D::Satoshi) + 1.0, D::Satoshi),
            Err(ParseAmountError::TooBig)
        );

        let btc = move |f| SignedAmount::from_btc(f).unwrap();
        assert_eq!(btc(2.5).to_float_in(D::Bitcoin), 2.5);
        assert_eq!(btc(-2.5).to_float_in(D::MilliBitcoin), -2500.0);
        assert_eq!(btc(2.5).to_float_in(D::Satoshi), 250000000.0);
        assert_eq!(btc(-2.5).to_float_in(D::MilliSatoshi), -250000000000.0);

        let btc = move |f| UnsignedAmount::from_btc(f).unwrap();
        assert_eq!(&btc(0.0012).to_float_in(D::Bitcoin).to_string(), "0.0012")
    }

    #[test]
    fn parsing() {
        use super::ParseAmountError as E;
        let btc = Denomination::Bitcoin;
        let sat = Denomination::Satoshi;
        let p = UnsignedAmount::from_str_in;
        let sp = SignedAmount::from_str_in;

        assert_eq!(p("x", btc), Err(E::InvalidCharacter('x')));
        assert_eq!(p("-", btc), Err(E::InvalidFormat));
        assert_eq!(sp("-", btc), Err(E::InvalidFormat));
        assert_eq!(p("-1.0x", btc), Err(E::InvalidCharacter('x')));
        assert_eq!(p("0.0 ", btc), Err(ParseAmountError::InvalidCharacter(' ')));
        assert_eq!(p("0.000.000", btc), Err(E::InvalidFormat));
        let more_than_max = format!("1{}", UnsignedAmount::max_value());
        assert_eq!(p(&more_than_max, btc), Err(E::TooBig));
        assert_eq!(p("0.000000042", btc), Err(E::TooPrecise));

        assert_eq!(p("1", btc), Ok(UnsignedAmount::from_sat(1_000_000_00)));
        assert_eq!(sp("-.5", btc), Ok(SignedAmount::from_sat(-500_000_00)));
        assert_eq!(p("1.1", btc), Ok(UnsignedAmount::from_sat(1_100_000_00)));
        assert_eq!(p("100", sat), Ok(UnsignedAmount::from_sat(100)));
        assert_eq!(p("55", sat), Ok(UnsignedAmount::from_sat(55)));
        assert_eq!(p("5500000000000000000", sat), Ok(UnsignedAmount::from_sat(5_500_000_000_000_000_000)));
        // Should this even pass?
        assert_eq!(p("5500000000000000000.", sat), Ok(UnsignedAmount::from_sat(5_500_000_000_000_000_000)));
        assert_eq!(
            p("12345678901.12345678", btc),
            Ok(UnsignedAmount::from_sat(12_345_678_901__123_456_78))
        );

        // make sure satoshi > i64::max_value() is checked.
        let amount = UnsignedAmount::from_sat(i64::max_value() as u64);
        assert_eq!(UnsignedAmount::from_str_in(&amount.to_string_in(sat), sat), Ok(amount));
        assert_eq!(UnsignedAmount::from_str_in(&(amount+UnsignedAmount::from_sat(1)).to_string_in(sat), sat), Err(E::TooBig));

        assert_eq!(p("12.000", Denomination::MilliSatoshi), Err(E::TooPrecise));
        // exactly 50 chars.
        assert_eq!(p("100000000000000.0000000000000000000000000000000000", Denomination::Bitcoin), Err(E::TooBig));
        // more than 50 chars.
        assert_eq!(p("100000000000000.00000000000000000000000000000000000", Denomination::Bitcoin), Err(E::InputTooLarge));
    }

    #[test]
    fn to_string() {
        use super::Denomination as D;

        assert_eq!(UnsignedAmount::ONE_BTC.to_string_in(D::Bitcoin), "1.00000000");
        assert_eq!(UnsignedAmount::ONE_BTC.to_string_in(D::Satoshi), "100000000");
        assert_eq!(UnsignedAmount::ONE_SAT.to_string_in(D::Bitcoin), "0.00000001");
        assert_eq!(SignedAmount::from_sat(-42).to_string_in(D::Bitcoin), "-0.00000042");

        assert_eq!(UnsignedAmount::ONE_BTC.to_string_with_denomination(D::Bitcoin), "1.00000000 BTC");
        assert_eq!(UnsignedAmount::ONE_SAT.to_string_with_denomination(D::MilliSatoshi), "1000 msat");
        assert_eq!(
            SignedAmount::ONE_BTC.to_string_with_denomination(D::Satoshi),
            "100000000 satoshi"
        );
        assert_eq!(UnsignedAmount::ONE_SAT.to_string_with_denomination(D::Bitcoin), "0.00000001 BTC");
        assert_eq!(
            SignedAmount::from_sat(-42).to_string_with_denomination(D::Bitcoin),
            "-0.00000042 BTC"
        );
    }

    #[test]
    fn test_unsigned_signed_conversion() {
        use super::ParseAmountError as E;
        let sa = SignedAmount::from_sat;
        let ua = UnsignedAmount::from_sat;

        assert_eq!(UnsignedAmount::max_value().to_signed(),  Err(E::TooBig));
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
        let p = UnsignedAmount::from_str;
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

        assert_eq!(p(".5 bits"), Ok(UnsignedAmount::from_sat(50)));
        assert_eq!(sp("-.5 bits"), Ok(SignedAmount::from_sat(-50)));
        assert_eq!(p("0.00253583 BTC"), Ok(UnsignedAmount::from_sat(253583)));
        assert_eq!(sp("-5 satoshi"), Ok(SignedAmount::from_sat(-5)));
        assert_eq!(p("0.10000000 BTC"), Ok(UnsignedAmount::from_sat(100_000_00)));
        assert_eq!(sp("-100 bits"), Ok(SignedAmount::from_sat(-10_000)));
    }

    #[test]
    fn to_from_string_in() {
        use super::Denomination as D;
        let ua_str = UnsignedAmount::from_str_in;
        let ua_sat = UnsignedAmount::from_sat;
        let sa_str = SignedAmount::from_str_in;
        let sa_sat = SignedAmount::from_sat;

        assert_eq!("0.50", UnsignedAmount::from_sat(50).to_string_in(D::Bit));
        assert_eq!("-0.50", SignedAmount::from_sat(-50).to_string_in(D::Bit));
        assert_eq!("0.00253583", UnsignedAmount::from_sat(253583).to_string_in(D::Bitcoin));
        assert_eq!("-5", SignedAmount::from_sat(-5).to_string_in(D::Satoshi));
        assert_eq!("0.10000000", UnsignedAmount::from_sat(100_000_00).to_string_in(D::Bitcoin));
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
        let amt = UnsignedAmount::from_sat(42);
        let denom = UnsignedAmount::to_string_with_denomination;
        assert_eq!(UnsignedAmount::from_str(&denom(amt, D::Bitcoin)), Ok(amt));
        assert_eq!(UnsignedAmount::from_str(&denom(amt, D::MilliBitcoin)), Ok(amt));
        assert_eq!(UnsignedAmount::from_str(&denom(amt, D::MicroBitcoin)), Ok(amt));
        assert_eq!(UnsignedAmount::from_str(&denom(amt, D::Bit)), Ok(amt));
        assert_eq!(UnsignedAmount::from_str(&denom(amt, D::Satoshi)), Ok(amt));
        assert_eq!(UnsignedAmount::from_str(&denom(amt, D::MilliSatoshi)), Ok(amt));

        assert_eq!(UnsignedAmount::from_str("42 satoshi BTC"), Err(ParseAmountError::InvalidFormat));
        assert_eq!(SignedAmount::from_str("-42 satoshi BTC"), Err(ParseAmountError::InvalidFormat));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_sat() {

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(with = "::util::amount::serde::as_sat")]
            pub amt: UnsignedAmount,
            #[serde(with = "::util::amount::serde::as_sat")]
            pub samt: SignedAmount,
        }

        serde_test::assert_tokens(
            &T {
                amt: UnsignedAmount::from_sat(123456789),
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
            pub amt: UnsignedAmount,
            #[serde(with = "::util::amount::serde::as_btc")]
            pub samt: SignedAmount,
        }

        let orig = T {
            amt: UnsignedAmount::from_sat(21_000_000__000_000_01),
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

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(default, with = "::util::amount::serde::as_btc::opt")]
            pub amt: Option<UnsignedAmount>,
            #[serde(default, with = "::util::amount::serde::as_btc::opt")]
            pub samt: Option<SignedAmount>,
        }

        let with = T {
            amt: Some(UnsignedAmount::from_sat(2__500_000_00)),
            samt: Some(SignedAmount::from_sat(-2__500_000_00)),
        };
        let without = T {
            amt: None,
            samt: None,
        };

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

    #[cfg(all(feature = "serde", feature = "schemars"))]
    #[test]
    fn api_amount() {
        use serde_json;

        #[derive(Serialize, Deserialize, Debug, PartialEq, schemars::JsonSchema)]
        struct T(Vec<ApiAmount>);

        let obj_schem = schemars::schema_for!(T);
        let string_schema = serde_json::to_string_pretty(&obj_schem).unwrap();
        let schema = serde_json::from_str(&string_schema).unwrap();

        let v = T(vec![ApiAmount::Sats(10), ApiAmount::Btc(5.0)]);
        let s = "[{\"Sats\":10},{\"Btc\":5.0}]";
        assert!(jsonschema_valid::is_valid(
            &serde_json::from_str(s).unwrap(),
            &schema,
            None,
            true
        ));
        let t: T = serde_json::from_str(s).unwrap();
        assert_eq!(t, v);
        let o = serde_json::to_value(&v).unwrap().to_string();
        assert!(jsonschema_valid::is_valid(
            &serde_json::from_str(&o).unwrap(),
            &schema,
            None,
            true
        ));
        assert_eq!(s, o);
    }

    #[cfg(all(feature = "serde", feature = "schemars"))]
    #[test]
    fn schemars_signed_amount() {
        use serde_json;

        #[derive(Serialize, Deserialize, Debug, PartialEq, schemars::JsonSchema)]
        struct T(Vec<Amount>);

        let obj_schem = schemars::schema_for!(T);
        let string_schema = serde_json::to_string_pretty(&obj_schem).unwrap();
        let schema = serde_json::from_str(&string_schema).unwrap();

        let v = T(vec![Amount::from_sat(10), Amount::from_btc(5.0).unwrap()]);
        let s = "[{\"Sats\":10},{\"Btc\":5.0}]";
        assert!(jsonschema_valid::is_valid(
            &serde_json::from_str(s).unwrap(),
            &schema,
            None,
            true
        ));
        let t: T = serde_json::from_str(s).unwrap();
        assert_eq!(t, v);
        let o = serde_json::to_value(&v).unwrap().to_string();
        assert!(jsonschema_valid::is_valid(
            &serde_json::from_str(&o).unwrap(),
            &schema,
            None,
            true
        ));
        let s2 = "[{\"Sats\":10},{\"Sats\":500000000}]";
        assert_eq!(s2, o);
    }

    #[cfg(all(feature = "serde", feature = "schemars"))]
    #[test]
    fn flat_repr() {
        use serde_json;

        #[derive(Serialize, Deserialize, Debug, PartialEq, schemars::JsonSchema)]
        struct T(
            #[serde(with = "::util::amount::serde::as_btc")]
            #[schemars(with = "f64")]
            Amount);

        let obj_schem = schemars::schema_for!(T);
        let string_schema = serde_json::to_string_pretty(&obj_schem).unwrap();
        let schema = serde_json::from_str(&string_schema).unwrap();
        println!("{}", string_schema);

        let v = T(Amount::from_btc(10.0).unwrap());
        let s = "10.0";
        assert!(jsonschema_valid::is_valid(
            &serde_json::from_str(s).unwrap(),
            &schema,
            None,
            true
        ));
        let t: T = serde_json::from_str(s).unwrap();
        assert_eq!(t, v);
        let o = serde_json::to_value(&v).unwrap().to_string();
        assert!(jsonschema_valid::is_valid(
            &serde_json::from_str(&o).unwrap(),
            &schema,
            None,
            true
        ));
        assert_eq!(s, o);
    }
}
