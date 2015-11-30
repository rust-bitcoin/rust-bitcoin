// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Floating-point decimal type
//!
//! `i64`-based floating-point decimal type designed to hold Bitcoin
//! amounts. For satoshi amounts (8 decimal places) the maximum
//! amounts that can be represented is ~92.25bn, well over the 21m
//! maximum number of bitcoin in existence. Be aware that some
//! altcoins with different granularity may require a wider type.
//!

use serde::{ser, de};
use strason::Json;

/// A fixed-point decimal type
#[derive(Copy, Clone, Debug, Eq, Ord)]
pub struct Decimal {
    mantissa: i64,
    exponent: usize,
}

impl PartialEq<Decimal> for Decimal {
    fn eq(&self, other: &Decimal) -> bool {
        use std::cmp::max;
        let exp = max(self.exponent(), other.exponent());
        self.integer_value(exp) == other.integer_value(exp)
    }
}

impl PartialOrd<Decimal> for Decimal {
    fn partial_cmp(&self, other: &Decimal) -> Option<::std::cmp::Ordering> {
        use std::cmp::max;
        let exp = max(self.exponent(), other.exponent());
        self.integer_value(exp).partial_cmp(&other.integer_value(exp))
    }
}

impl Decimal {
    /// Creates a new Decimal
    pub fn new(mantissa: i64, exponent: usize) -> Decimal {
        Decimal {
            mantissa: mantissa,
            exponent: exponent
        }
    }

    /// Returns the mantissa
    pub fn mantissa(&self) -> i64 { self.mantissa }
    /// Returns the exponent
    pub fn exponent(&self) -> usize { self.exponent }

    /// Get the decimal's value in an integer type, by multiplying
    /// by some power of ten to ensure the returned value is 10 **
    /// `exponent` types the actual value.
    pub fn integer_value(&self, exponent: usize) -> i64 {
        if exponent < self.exponent {
            self.mantissa / 10i64.pow((self.exponent - exponent) as u32)
        } else {
            self.mantissa * 10i64.pow((exponent - self.exponent) as u32)
        }
    }
}

impl ser::Serialize for Decimal {
    // Serialize through strason since it will not lose precision (when serializing
    // to strason itself, the value will be passed through; otherwise it will be
    // encoded as a string)
    fn serialize<S: ser::Serializer>(&self, s: &mut S) -> Result<(), S::Error> {
        let ten = 10i64.pow(self.exponent as u32);
        let int_part = self.mantissa / ten;
        let dec_part = self.mantissa % ten;
        let json = Json::from_str(&format!("{}.{:02$}", int_part, dec_part, self.exponent)).unwrap();
        ser::Serialize::serialize(&json, s)
    }
}

impl de::Deserialize for Decimal {
    // Deserialize through strason for the same reason as in `Serialize`
    fn deserialize<D: de::Deserializer>(d: &mut D) -> Result<Decimal, D::Error> {
        let json: Json = try!(de::Deserialize::deserialize(d));
        match json.num() {
            Some(s) => {
                 // We know this will be a well-formed Json number, so we can
                 // be pretty lax about parsing
                 let mut negative = false;
                 let mut past_dec = false;
                 let mut exponent = 0;
                 let mut mantissa = 0i64;

                 for b in s.as_bytes() {
                     match *b {
                         b'-' => { negative = true; }
                         b'0'...b'9' => {
                             mantissa = 10 * mantissa + (b - b'0') as i64;
                             if past_dec { exponent += 1; }
                         }
                         b'.' => { past_dec = true; }
                         _ => { /* whitespace or something, just ignore it */ }
                     }
                 }
                 if negative { mantissa *= -1; }
                 Ok(Decimal {
                     mantissa: mantissa,
                     exponent: exponent,
                 })
            }
            None => Err(de::Error::syntax("expected decimal, got non-numeric"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strason::Json;

    #[test]
    fn integer_value() {
        let d = Decimal::new(12345678, 4);
        assert_eq!(d.mantissa(), 12345678);
        assert_eq!(d.exponent(), 4);

        assert_eq!(d.integer_value(0), 1234);
        assert_eq!(d.integer_value(1), 12345);
        assert_eq!(d.integer_value(2), 123456);
        assert_eq!(d.integer_value(3), 1234567);
        assert_eq!(d.integer_value(4), 12345678);
        assert_eq!(d.integer_value(5), 123456780);
        assert_eq!(d.integer_value(6), 1234567800);
        assert_eq!(d.integer_value(7), 12345678000);
        assert_eq!(d.integer_value(8), 123456780000);
    }

    #[test]
    fn deserialize() {
        let d = Decimal::new(123456789001, 8);
        let encoded = Json::from_serialize(&d).unwrap();
        assert_eq!(encoded, Json::from_str("1234.56789001").unwrap());
        assert_eq!(encoded.to_bytes(), b"1234.56789001");

        let decoded: Decimal = encoded.into_deserialize().unwrap();
        assert_eq!(decoded, d);


        let d = Decimal::new(123400000001, 8);
        let encoded = Json::from_serialize(&d).unwrap();
        assert_eq!(encoded, Json::from_str("1234.00000001").unwrap());
        assert_eq!(encoded.to_bytes(), b"1234.00000001");

        let decoded: Decimal = encoded.into_deserialize().unwrap();
        assert_eq!(decoded, d);
    }

    #[test]
    fn equality() {
        let d1 = Decimal::new(1234, 8);
        let d2 = Decimal::new(12340, 9);
        let d3 = Decimal::new(12340, 8);
        assert_eq!(d1, d1);
        assert_eq!(d1, d2);
        assert!(d1 != d3);
        assert!(d2 != d3);

        assert!(d1 <= d1);
        assert!(d2 <= d2);
        assert!(d3 <= d3);
        assert!(d1 <= d2);
        assert!(d1 <= d3);
        assert!(d3 > d1);
        assert!(d3 > d2);
    }

    #[test]
    fn json_parse() {
        let json = Json::from_str("0.00980000").unwrap();
        assert_eq!(json.to_bytes(), b"0.00980000");
        let dec: Decimal = json.into_deserialize().unwrap();
        assert_eq!(dec, Decimal::new(980000, 8));
    }
}


