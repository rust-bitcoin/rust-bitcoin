// Written by the Rust Bitcoin developers
// SPDX-License-Identifier: CC0-1.0

//! Hex encoding and decoding.
//!
//! This module is only used to decode base58 checksum in unit tests.
//!

use core::fmt;

/// Decodes a hex string into a byte array.
pub fn decode(hex: &str) -> Result<Vec<u8>, Error> {
    if hex.len() % 2 != 0 {
        return Err(Error::OddLengthString(hex.len()));
    }

    let mut out: Vec<u8> = Vec::with_capacity(hex.len() / 2);

    let mut b = 0;
    let mut idx = 0;
    for c in hex.bytes() {
        b <<= 4;
        match c {
            b'A'..=b'F' => b |= c - b'A' + 10,
            b'a'..=b'f' => b |= c - b'a' + 10,
            b'0'..=b'9' => b |= c - b'0',
            d => return Err(Error::InvalidChar(d)),
        }
        if (idx & 1) == 1 {
            out.push(b);
            b = 0;
        }
        idx += 1;
    }
    Ok(out)
}

/// Encodes `data` into a hex string.
fn encode(data: &[u8]) -> String {
    let digits = data.len() * 2;

    let mut target: Vec<u8> = Vec::with_capacity(digits);

    const HEX_TABLE: [u8; 16] = *b"0123456789abcdef";

    for &b in data {
        target.push(HEX_TABLE[usize::from(b >> 4)]);
        target.push(HEX_TABLE[usize::from(b & 0b00001111)]);
    }
    String::from_utf8(target).expect("we only write valid digits")
}

/// Hex decoding error.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Error {
    /// Non-hexadecimal character.
    InvalidChar(u8),
    /// Purported hex string had odd length.
    OddLengthString(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidChar(ch) => write!(f, "invalid hex character {}", ch),
            Error::OddLengthString(ell) => write!(f, "odd hex string length {}", ell),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match *self {
            InvalidChar(_) | OddLengthString(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let lower = "0123456789abcdef";
        let upper = "0123456789ABCDEF";
        let bytes = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

        let parse = decode(lower).expect("parse lowercase string");
        assert_eq!(parse, bytes);
        let ser = encode(&parse);
        assert_eq!(ser, lower);

        let parse = decode(upper).expect("parse uppercase string");
        assert_eq!(parse, bytes);
        let ser = encode(&parse);
        assert_eq!(ser, lower);
    }

    #[test]
    #[should_panic]
    fn invalid_digit() { let _ = decode("invalid-hex").unwrap(); }
}
