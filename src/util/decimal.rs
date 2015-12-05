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

use std::{fmt, ops};

use serde::{ser, de};
use strason::Json;

/// A fixed-point decimal type
#[derive(Copy, Clone, Debug, Eq, Ord)]
pub struct Decimal {
    mantissa: i64,
    exponent: usize,
}

/// Unsigned fixed-point decimal type
#[derive(Copy, Clone, Debug, Eq, Ord)]
pub struct UDecimal {
    mantissa: u64,
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

impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ten = 10i64.pow(self.exponent as u32);
        let int_part = self.mantissa / ten;
        let dec_part = (self.mantissa % ten).abs();
        write!(f, "{}.{:02$}", int_part, dec_part, self.exponent)
    }
}

impl ops::Add for Decimal {
    type Output = Decimal;

    #[inline]
    fn add(self, other: Decimal) -> Decimal {
        if self.exponent > other.exponent {
            Decimal {
                mantissa: other.mantissa * 10i64.pow((self.exponent - other.exponent) as u32) + self.mantissa,
                exponent: self.exponent
            }
        } else {
            Decimal {
                mantissa: self.mantissa * 10i64.pow((other.exponent - self.exponent) as u32) + other.mantissa,
                exponent: other.exponent
            }
        }
    }
}

impl ops::Neg for Decimal {
    type Output = Decimal;
    #[inline]
    fn neg(self) -> Decimal { Decimal { mantissa: -self.mantissa, exponent: self.exponent } }
}

impl ops::Sub for Decimal {
    type Output = Decimal;
    #[inline]
    fn sub(self, other: Decimal) -> Decimal { self + (-other) }
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
    #[inline]
    pub fn mantissa(&self) -> i64 { self.mantissa }
    /// Returns the exponent
    #[inline]
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

    /// Returns whether or not the number is nonnegative
    #[inline]
    pub fn nonnegative(&self) -> bool { self.mantissa >= 0 }
}

impl ser::Serialize for Decimal {
    // Serialize through strason since it will not lose precision (when serializing
    // to strason itself, the value will be passed through; otherwise it will be
    // encoded as a string)
    fn serialize<S: ser::Serializer>(&self, s: &mut S) -> Result<(), S::Error> {
        let json = Json::from_str(&self.to_string()).unwrap();
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


impl PartialEq<UDecimal> for UDecimal {
    fn eq(&self, other: &UDecimal) -> bool {
        use std::cmp::max;
        let exp = max(self.exponent(), other.exponent());
        self.integer_value(exp) == other.integer_value(exp)
    }
}

impl PartialOrd<UDecimal> for UDecimal {
    fn partial_cmp(&self, other: &UDecimal) -> Option<::std::cmp::Ordering> {
        use std::cmp::max;
        let exp = max(self.exponent(), other.exponent());
        self.integer_value(exp).partial_cmp(&other.integer_value(exp))
    }
}

impl fmt::Display for UDecimal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ten = 10u64.pow(self.exponent as u32);
        let int_part = self.mantissa / ten;
        let dec_part = self.mantissa % ten;
        write!(f, "{}.{:02$}", int_part, dec_part, self.exponent)
    }
}

impl ops::Add for UDecimal {
    type Output = UDecimal;

    #[inline]
    fn add(self, other: UDecimal) -> UDecimal {
        if self.exponent > other.exponent {
            UDecimal {
                mantissa: other.mantissa * 10u64.pow((self.exponent - other.exponent) as u32) + self.mantissa,
                exponent: self.exponent
            }
        } else {
            UDecimal {
                mantissa: self.mantissa * 10u64.pow((other.exponent - self.exponent) as u32) + other.mantissa,
                exponent: other.exponent
            }
        }
    }
}

impl UDecimal {
    /// Creates a new Decimal
    pub fn new(mantissa: u64, exponent: usize) -> UDecimal {
        UDecimal {
            mantissa: mantissa,
            exponent: exponent
        }
    }

    /// Returns the mantissa
    #[inline]
    pub fn mantissa(&self) -> u64 { self.mantissa }
    /// Returns the exponent
    #[inline]
    pub fn exponent(&self) -> usize { self.exponent }

    /// Get the decimal's value in an integer type, by multiplying
    /// by some power of ten to ensure the returned value is 10 **
    /// `exponent` types the actual value.
    pub fn integer_value(&self, exponent: usize) -> u64 {
        if exponent < self.exponent {
            self.mantissa / 10u64.pow((self.exponent - exponent) as u32)
        } else {
            self.mantissa * 10u64.pow((exponent - self.exponent) as u32)
        }
    }
}

impl ser::Serialize for UDecimal {
    // Serialize through strason since it will not lose precision (when serializing
    // to strason itself, the value will be passed through; otherwise it will be
    // encoded as a string)
    fn serialize<S: ser::Serializer>(&self, s: &mut S) -> Result<(), S::Error> {
        let json = Json::from_str(&self.to_string()).unwrap();
        ser::Serialize::serialize(&json, s)
    }
}

impl de::Deserialize for UDecimal {
    // Deserialize through strason for the same reason as in `Serialize`
    fn deserialize<D: de::Deserializer>(d: &mut D) -> Result<UDecimal, D::Error> {
        let json: Json = try!(de::Deserialize::deserialize(d));
        match json.num() {
            Some(s) => {
                 // We know this will be a well-formed Json number, so we can
                 // be pretty lax about parsing
                 let mut past_dec = false;
                 let mut exponent = 0;
                 let mut mantissa = 0u64;

                 for b in s.as_bytes() {
                     match *b {
                         b'0'...b'9' => {
                             mantissa = 10 * mantissa + (b - b'0') as u64;
                             if past_dec { exponent += 1; }
                         }
                         b'.' => { past_dec = true; }
                         _ => { /* whitespace or something, just ignore it */ }
                     }
                 }
                 Ok(UDecimal {
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

        let u = UDecimal::new(12345678, 4);
        assert_eq!(u.mantissa(), 12345678);
        assert_eq!(u.exponent(), 4);

        assert_eq!(u.integer_value(0), 1234);
        assert_eq!(u.integer_value(1), 12345);
        assert_eq!(u.integer_value(2), 123456);
        assert_eq!(u.integer_value(3), 1234567);
        assert_eq!(u.integer_value(4), 12345678);
        assert_eq!(u.integer_value(5), 123456780);
        assert_eq!(u.integer_value(6), 1234567800);
        assert_eq!(u.integer_value(7), 12345678000);
        assert_eq!(u.integer_value(8), 123456780000);
    }

    macro_rules! deserialize_round_trip(
        ($dec:expr, $s:expr) => ({
            let d = $dec;
            let encoded = Json::from_serialize(&d).unwrap();
            assert_eq!(encoded, Json::from_reader(&$s[..]).unwrap());
            assert_eq!(encoded.to_bytes(), &$s[..]);

            // hack to force type inference
            let mut decoded_res = encoded.into_deserialize();
            if false { decoded_res = Ok($dec); }
            let decoded = decoded_res.unwrap();
            assert_eq!(decoded, d);
        })
    );

    #[test]
    fn deserialize() {
        deserialize_round_trip!(Decimal::new(0, 0), b"0.0");
        deserialize_round_trip!(UDecimal::new(0, 0), b"0.0");

        deserialize_round_trip!(Decimal::new(123456789001, 8), b"1234.56789001");
        deserialize_round_trip!(UDecimal::new(123456789001, 8), b"1234.56789001");
        deserialize_round_trip!(Decimal::new(-123456789001, 8), b"-1234.56789001");
        deserialize_round_trip!(Decimal::new(123456789001, 1), b"12345678900.1");
        deserialize_round_trip!(UDecimal::new(123456789001, 1), b"12345678900.1");
        deserialize_round_trip!(Decimal::new(-123456789001, 1), b"-12345678900.1");
        deserialize_round_trip!(Decimal::new(123456789001, 0), b"123456789001.0");
        deserialize_round_trip!(UDecimal::new(123456789001, 0), b"123456789001.0");
        deserialize_round_trip!(Decimal::new(-123456789001, 0), b"-123456789001.0");

        deserialize_round_trip!(Decimal::new(123400000001, 8), b"1234.00000001");
        deserialize_round_trip!(UDecimal::new(123400000001, 8), b"1234.00000001");
        deserialize_round_trip!(Decimal::new(-123400000001, 8), b"-1234.00000001");
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
    fn arithmetic() {
        let d1 = Decimal::new(5, 1);   //  0.5
        let d2 = Decimal::new(-2, 2);  // -0.02
        let d3 = Decimal::new(3, 0);   //  3.0
        let d4 = Decimal::new(0, 5);  //   0.00000
        let u1 = UDecimal::new(5, 1);   //  0.5
        let u3 = UDecimal::new(3, 0);   //  3.0
        let u4 = UDecimal::new(0, 5);  //   0.00000

        assert!(d1.nonnegative());
        assert!(!d2.nonnegative());
        assert!(d3.nonnegative());
        assert!(d4.nonnegative());

        assert_eq!(d1 + d2, Decimal::new(48, 2));
        assert_eq!(d1 - d2, Decimal::new(52, 2));
        assert_eq!(d1 + d3, Decimal::new(35, 1));
        assert_eq!(u1 + u3, UDecimal::new(35, 1));
        assert_eq!(d1 - d3, Decimal::new(-25, 1));
        assert_eq!(d2 + d3, Decimal::new(298, 2));
        assert_eq!(d2 - d3, Decimal::new(-302, 2));

        assert_eq!(d1 + d4, d1);
        assert_eq!(u1 + u4, u1);
        assert_eq!(d1 - d4, d1);
        assert_eq!(d1 + d4, d1 - d4);
        assert_eq!(d4 + d4, d4);
        assert_eq!(u4 + u4, u4);
    }

    #[test]
    fn json_parse() {
        let json = Json::from_str("0.00980000").unwrap();
        assert_eq!(json.to_bytes(), b"0.00980000");
        let dec: Decimal = json.into_deserialize().unwrap();
        assert_eq!(dec, Decimal::new(980000, 8));

        let json = Json::from_str("0.00980000").unwrap();
        assert_eq!(json.to_bytes(), b"0.00980000");
        let dec: UDecimal = json.into_deserialize().unwrap();
        assert_eq!(dec, UDecimal::new(980000, 8));

        let json = Json::from_str("0.00980").unwrap();
        assert_eq!(json.to_bytes(), b"0.00980");
        let dec: Decimal = json.into_deserialize().unwrap();
        assert_eq!(dec, Decimal::new(98000, 7));

        let json = Json::from_str("0.00980").unwrap();
        assert_eq!(json.to_bytes(), b"0.00980");
        let dec: UDecimal = json.into_deserialize().unwrap();
        assert_eq!(dec, UDecimal::new(98000, 7));
    }
}


