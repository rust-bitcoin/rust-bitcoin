// Bitcoin Hashes Library
// Written in 2018 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! Hex encoding and decoding.
//!


#[cfg(all(feature = "alloc", not(feature = "std")))]
use crate::alloc::vec::Vec;

#[cfg(feature = "std")]
use std::io;
#[cfg(all(feature = "core2", not(feature = "std")))]
use core2::io;

use core::{fmt, str};

/// Hex decoding error.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Error {
    /// Non-hexadecimal character.
    InvalidChar(u8),
    /// Purported hex string had odd length.
    OddLengthString(usize),
    /// Tried to parse fixed-length hash from a string with the wrong type (expected, got).
    InvalidLength(usize, usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidChar(ch) => write!(f, "invalid hex character {}", ch),
            Error::OddLengthString(ell) => write!(f, "odd hex string length {}", ell),
            Error::InvalidLength(ell, ell2) => write!(f, "bad hex string length {} (expected {})", ell2, ell),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            InvalidChar(_) | OddLengthString(_) | InvalidLength(_, _) => None,
        }
    }
}

/// Trait for objects that can be deserialized from hex strings.
pub trait FromHex: Sized {
    /// Produces an object from a byte iterator.
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where
        I: Iterator<Item = Result<u8, Error>> + ExactSizeIterator + DoubleEndedIterator;

    /// Produces an object from a hex string.
    fn from_hex(s: &str) -> Result<Self, Error> {
        Self::from_byte_iter(HexIterator::new(s)?)
    }
}

/// Iterator over a hex-encoded string slice which decodes hex and yields bytes.
pub struct HexIterator<'a> {
    /// The `Bytes` iterator whose next two bytes will be decoded to yield
    /// the next byte.
    iter: str::Bytes<'a>,
}

impl<'a> HexIterator<'a> {
    /// Constructs a new `HexIterator` from a string slice.
    ///
    /// # Errors
    ///
    /// If the input string is of odd length.
    pub fn new(s: &'a str) -> Result<HexIterator<'a>, Error> {
        if s.len() % 2 != 0 {
            Err(Error::OddLengthString(s.len()))
        } else {
            Ok(HexIterator { iter: s.bytes() })
        }
    }
}

fn chars_to_hex(hi: u8, lo: u8) -> Result<u8, Error> {
    let hih = (hi as char)
        .to_digit(16)
        .ok_or(Error::InvalidChar(hi))?;
    let loh = (lo as char)
        .to_digit(16)
        .ok_or(Error::InvalidChar(lo))?;

    let ret = (hih << 4) + loh;
    Ok(ret as u8)
}

impl<'a> Iterator for HexIterator<'a> {
    type Item = Result<u8, Error>;

    fn next(&mut self) -> Option<Result<u8, Error>> {
        let hi = self.iter.next()?;
        let lo = self.iter.next().unwrap();
        Some(chars_to_hex(hi, lo))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (min, max) = self.iter.size_hint();
        (min / 2, max.map(|x| x / 2))
    }
}

#[cfg(any(feature = "std", feature = "core2"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "std", feature = "core2"))))]
impl<'a> io::Read for HexIterator<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut bytes_read = 0usize;
        for dst in buf {
            match self.next() {
                Some(Ok(src)) => {
                    *dst = src;
                    bytes_read += 1;
                },
                _ => break,
            }
        }
        Ok(bytes_read)
    }
}

impl<'a> DoubleEndedIterator for HexIterator<'a> {
    fn next_back(&mut self) -> Option<Result<u8, Error>> {
        let lo = self.iter.next_back()?;
        let hi = self.iter.next_back().unwrap();
        Some(chars_to_hex(hi, lo))
    }
}

impl<'a> ExactSizeIterator for HexIterator<'a> {}

#[cfg(any(test, feature = "std", feature = "alloc"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "std", feature = "alloc"))))]
impl FromHex for Vec<u8> {
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where
        I: Iterator<Item = Result<u8, Error>> + ExactSizeIterator + DoubleEndedIterator,
    {
        iter.collect()
    }
}

macro_rules! impl_fromhex_array {
    ($len:expr) => {
        impl FromHex for [u8; $len] {
            fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
            where
                I: Iterator<Item = Result<u8, Error>> + ExactSizeIterator + DoubleEndedIterator,
            {
                if iter.len() == $len {
                    let mut ret = [0; $len];
                    for (n, byte) in iter.enumerate() {
                        ret[n] = byte?;
                    }
                    Ok(ret)
                } else {
                    Err(Error::InvalidLength(2 * $len, 2 * iter.len()))
                }
            }
        }
    }
}

impl_fromhex_array!(2);
impl_fromhex_array!(4);
impl_fromhex_array!(6);
impl_fromhex_array!(8);
impl_fromhex_array!(10);
impl_fromhex_array!(12);
impl_fromhex_array!(14);
impl_fromhex_array!(16);
impl_fromhex_array!(20);
impl_fromhex_array!(24);
impl_fromhex_array!(28);
impl_fromhex_array!(32);
impl_fromhex_array!(33);
impl_fromhex_array!(64);
impl_fromhex_array!(65);
impl_fromhex_array!(128);
impl_fromhex_array!(256);
impl_fromhex_array!(384);
impl_fromhex_array!(512);

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;
    use internals::hex::exts::DisplayHex;

    #[test]
    fn hex_roundtrip() {
        let expected = "0123456789abcdef";
        let expected_up = "0123456789ABCDEF";

        let parse: Vec<u8> = FromHex::from_hex(expected).expect("parse lowercase string");
        assert_eq!(parse, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        let ser = parse.to_lower_hex_string();
        assert_eq!(ser, expected);

        let parse: Vec<u8> = FromHex::from_hex(expected_up).expect("parse uppercase string");
        assert_eq!(parse, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        let ser = parse.to_lower_hex_string();
        assert_eq!(ser, expected);

        let parse: [u8; 8] = FromHex::from_hex(expected_up).expect("parse uppercase string");
        assert_eq!(parse, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        let ser = parse.to_lower_hex_string();
        assert_eq!(ser, expected);
    }

    #[test]
    fn hex_error() {
        let oddlen = "0123456789abcdef0";
        let badchar1 = "Z123456789abcdef";
        let badchar2 = "012Y456789abcdeb";
        let badchar3 = "«23456789abcdef";

        assert_eq!(
            Vec::<u8>::from_hex(oddlen),
            Err(Error::OddLengthString(17))
        );
        assert_eq!(
            <[u8; 4]>::from_hex(oddlen),
            Err(Error::OddLengthString(17))
        );
        assert_eq!(
            <[u8; 8]>::from_hex(oddlen),
            Err(Error::OddLengthString(17))
        );
        assert_eq!(
            Vec::<u8>::from_hex(badchar1),
            Err(Error::InvalidChar(b'Z'))
        );
        assert_eq!(
            Vec::<u8>::from_hex(badchar2),
            Err(Error::InvalidChar(b'Y'))
        );
        assert_eq!(
            Vec::<u8>::from_hex(badchar3),
            Err(Error::InvalidChar(194))
        );
    }
}
