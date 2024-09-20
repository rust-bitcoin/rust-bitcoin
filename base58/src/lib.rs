// SPDX-License-Identifier: CC0-1.0

//! Bitcoin base58 encoding and decoding.
//!
//! This crate can be used in a no-std environment but requires an allocator.

// NB: This crate is empty if `alloc` is not enabled.
#![cfg(feature = "alloc")]
#![no_std]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(bench, feature(test))]
// Coding conventions.
#![warn(missing_docs)]
#![doc(test(attr(warn(unused))))]
// Instead of littering the codebase for non-fuzzing and bench code just globally allow.
#![cfg_attr(fuzzing, allow(dead_code, unused_imports))]
#![cfg_attr(bench, allow(dead_code, unused_imports))]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.

extern crate alloc;

#[cfg(bench)]
extern crate test;

#[cfg(feature = "std")]
extern crate std;

static BASE58_CHARS: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub mod error;

#[cfg(not(feature = "std"))]
pub use alloc::{string::String, vec::Vec};
use core::fmt;
#[cfg(feature = "std")]
pub use std::{string::String, vec::Vec};

use hashes::sha256d;
use internals::array_vec::ArrayVec;

use crate::error::{IncorrectChecksumError, TooShortError};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::error::{Error, InvalidCharacterError};

#[rustfmt::skip]
static BASE58_DIGITS: [Option<u8>; 128] = [
    None,     None,     None,     None,     None,     None,     None,     None,     // 0-7
    None,     None,     None,     None,     None,     None,     None,     None,     // 8-15
    None,     None,     None,     None,     None,     None,     None,     None,     // 16-23
    None,     None,     None,     None,     None,     None,     None,     None,     // 24-31
    None,     None,     None,     None,     None,     None,     None,     None,     // 32-39
    None,     None,     None,     None,     None,     None,     None,     None,     // 40-47
    None,     Some(0),  Some(1),  Some(2),  Some(3),  Some(4),  Some(5),  Some(6),  // 48-55
    Some(7),  Some(8),  None,     None,     None,     None,     None,     None,     // 56-63
    None,     Some(9),  Some(10), Some(11), Some(12), Some(13), Some(14), Some(15), // 64-71
    Some(16), None,     Some(17), Some(18), Some(19), Some(20), Some(21), None,     // 72-79
    Some(22), Some(23), Some(24), Some(25), Some(26), Some(27), Some(28), Some(29), // 80-87
    Some(30), Some(31), Some(32), None,     None,     None,     None,     None,     // 88-95
    None,     Some(33), Some(34), Some(35), Some(36), Some(37), Some(38), Some(39), // 96-103
    Some(40), Some(41), Some(42), Some(43), None,     Some(44), Some(45), Some(46), // 104-111
    Some(47), Some(48), Some(49), Some(50), Some(51), Some(52), Some(53), Some(54), // 112-119
    Some(55), Some(56), Some(57), None,     None,     None,     None,     None,     // 120-127
];

/// Decodes a base58-encoded string into a byte vector.
pub fn decode(data: &str) -> Result<Vec<u8>, InvalidCharacterError> {
    // 11/15 is just over log_256(58)
    let mut scratch = Vec::with_capacity(1 + data.len() * 11 / 15);
    // Build in base 256
    for d58 in data.bytes() {
        // Compute "X = X * 58 + next_digit" in base 256
        if usize::from(d58) >= BASE58_DIGITS.len() {
            return Err(InvalidCharacterError { invalid: d58 });
        }
        let mut carry = match BASE58_DIGITS[usize::from(d58)] {
            Some(d58) => u32::from(d58),
            None => {
                return Err(InvalidCharacterError { invalid: d58 });
            }
        };
        if scratch.is_empty() {
            for _ in 0..scratch.capacity() {
                scratch.push(carry as u8);
                carry /= 256;
            }
        } else {
            for d256 in scratch.iter_mut() {
                carry += u32::from(*d256) * 58;
                *d256 = carry as u8; // cast loses data intentionally
                carry /= 256;
            }
        }
        assert_eq!(carry, 0);
    }

    // Copy leading zeroes directly
    let mut ret: Vec<u8> = data.bytes().take_while(|&x| x == BASE58_CHARS[0]).map(|_| 0).collect();
    // Copy rest of string
    ret.extend(scratch.into_iter().rev().skip_while(|&x| x == 0));
    Ok(ret)
}

/// Decodes a base58check-encoded string into a byte vector verifying the checksum.
pub fn decode_check(data: &str) -> Result<Vec<u8>, Error> {
    let mut ret: Vec<u8> = decode(data)?;
    if ret.len() < 4 {
        return Err(TooShortError { length: ret.len() }.into());
    }
    let check_start = ret.len() - 4;

    let hash_check =
        sha256d::Hash::hash(&ret[..check_start])[..4].try_into().expect("4 byte slice");
    let data_check = ret[check_start..].try_into().expect("4 byte slice");

    let expected = u32::from_le_bytes(hash_check);
    let actual = u32::from_le_bytes(data_check);

    if actual != expected {
        return Err(IncorrectChecksumError { incorrect: actual, expected }.into());
    }

    ret.truncate(check_start);
    Ok(ret)
}

const SHORT_OPT_BUFFER_LEN: usize = 128;

/// Encodes `data` as a base58 string (see also `base58::encode_check()`).
pub fn encode(data: &[u8]) -> String {
    let reserve_len = encoded_reserve_len(data.len());
    let mut res = String::with_capacity(reserve_len);
    if reserve_len <= SHORT_OPT_BUFFER_LEN {
        format_iter(
            &mut res,
            data.iter().copied(),
            &mut ArrayVec::<u8, SHORT_OPT_BUFFER_LEN>::new(),
        )
    } else {
        format_iter(&mut res, data.iter().copied(), &mut Vec::with_capacity(reserve_len))
    }
    .expect("string doesn't error");
    res
}

/// Encodes `data` as a base58 string including the checksum.
///
/// The checksum is the first four bytes of the sha256d of the data, concatenated onto the end.
pub fn encode_check(data: &[u8]) -> String {
    let mut res = String::with_capacity(encoded_check_reserve_len(data.len()));
    encode_check_to_writer(&mut res, data).expect("string doesn't fail");
    res
}

/// Encodes a slice as base58, including the checksum, into a formatter.
///
/// The checksum is the first four bytes of the sha256d of the data, concatenated onto the end.
pub fn encode_check_to_fmt(fmt: &mut fmt::Formatter, data: &[u8]) -> fmt::Result {
    encode_check_to_writer(fmt, data)
}

fn encode_check_to_writer(fmt: &mut impl fmt::Write, data: &[u8]) -> fmt::Result {
    let checksum = sha256d::Hash::hash(data);
    let iter = data.iter().cloned().chain(checksum[0..4].iter().cloned());
    let reserve_len = encoded_check_reserve_len(data.len());
    if reserve_len <= SHORT_OPT_BUFFER_LEN {
        format_iter(fmt, iter, &mut ArrayVec::<u8, SHORT_OPT_BUFFER_LEN>::new())
    } else {
        format_iter(fmt, iter, &mut Vec::with_capacity(reserve_len))
    }
}

/// Returns the length to reserve when encoding base58 without checksum
const fn encoded_reserve_len(unencoded_len: usize) -> usize {
    // log2(256) / log2(58) ~ 1.37 = 137 / 100
    unencoded_len * 137 / 100
}

/// Returns the length to reserve when encoding base58 with checksum
const fn encoded_check_reserve_len(unencoded_len: usize) -> usize {
    encoded_reserve_len(unencoded_len + 4)
}

trait Buffer: Sized {
    fn push(&mut self, val: u8);
    fn slice(&self) -> &[u8];
    fn slice_mut(&mut self) -> &mut [u8];
}

impl Buffer for Vec<u8> {
    fn push(&mut self, val: u8) { Vec::push(self, val) }

    fn slice(&self) -> &[u8] { self }

    fn slice_mut(&mut self) -> &mut [u8] { self }
}

impl<const N: usize> Buffer for ArrayVec<u8, N> {
    fn push(&mut self, val: u8) { ArrayVec::push(self, val) }

    fn slice(&self) -> &[u8] { self.as_slice() }

    fn slice_mut(&mut self) -> &mut [u8] { self.as_mut_slice() }
}

fn format_iter<I, W>(writer: &mut W, data: I, buf: &mut impl Buffer) -> Result<(), fmt::Error>
where
    I: Iterator<Item = u8> + Clone,
    W: fmt::Write,
{
    let mut leading_zero_count = 0;
    let mut leading_zeroes = true;
    // Build string in little endian with 0-58 in place of characters...
    for d256 in data {
        let mut carry = u32::from(d256);
        if leading_zeroes && carry == 0 {
            leading_zero_count += 1;
        } else {
            leading_zeroes = false;
        }

        for ch in buf.slice_mut() {
            let new_ch = u32::from(*ch) * 256 + carry;
            *ch = (new_ch % 58) as u8; // cast loses data intentionally
            carry = new_ch / 58;
        }

        while carry > 0 {
            buf.push((carry % 58) as u8); // cast loses data intentionally
            carry /= 58;
        }
    }

    // ... then reverse it and convert to chars
    for _ in 0..leading_zero_count {
        buf.push(0);
    }

    for ch in buf.slice().iter().rev() {
        writer.write_char(char::from(BASE58_CHARS[usize::from(*ch)]))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use hex::test_hex_unwrap as hex;

    use super::*;

    #[test]
    fn test_base58_encode() {
        // Basics
        assert_eq!(&encode(&[0][..]), "1");
        assert_eq!(&encode(&[1][..]), "2");
        assert_eq!(&encode(&[58][..]), "21");
        assert_eq!(&encode(&[13, 36][..]), "211");

        // Leading zeroes
        assert_eq!(&encode(&[0, 13, 36][..]), "1211");
        assert_eq!(&encode(&[0, 0, 0, 0, 13, 36][..]), "1111211");

        // Long input (>128 bytes => has to use heap)
        let res = encode(
            "BitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBit\
        coinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoin"
                .as_bytes(),
        );
        let exp =
            "ZqC5ZdfpZRi7fjA8hbhX5pEE96MdH9hEaC1YouxscPtbJF16qVWksHWR4wwvx7MotFcs2ChbJqK8KJ9X\
        wZznwWn1JFDhhTmGo9v6GjAVikzCsBWZehu7bm22xL8b5zBR5AsBygYRwbFJsNwNkjpyFuDKwmsUTKvkULCvucPJrN5\
        QUdxpGakhqkZFL7RU4yT";
        assert_eq!(&res, exp);

        // Addresses
        let addr = hex!("00f8917303bfa8ef24f292e8fa1419b20460ba064d");
        assert_eq!(&encode_check(&addr[..]), "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH");
    }

    #[test]
    fn test_base58_decode() {
        // Basics
        assert_eq!(decode("1").ok(), Some(vec![0u8]));
        assert_eq!(decode("2").ok(), Some(vec![1u8]));
        assert_eq!(decode("21").ok(), Some(vec![58u8]));
        assert_eq!(decode("211").ok(), Some(vec![13u8, 36]));

        // Leading zeroes
        assert_eq!(decode("1211").ok(), Some(vec![0u8, 13, 36]));
        assert_eq!(decode("111211").ok(), Some(vec![0u8, 0, 0, 13, 36]));

        // Addresses
        assert_eq!(
            decode_check("1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH").ok(),
            Some(hex!("00f8917303bfa8ef24f292e8fa1419b20460ba064d"))
        );
        // Non Base58 char.
        assert_eq!(decode("¢").unwrap_err(), InvalidCharacterError { invalid: 194 });
    }

    #[test]
    fn test_base58_roundtrip() {
        let s = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs";
        let v: Vec<u8> = decode_check(s).unwrap();
        assert_eq!(encode_check(&v[..]), s);
        assert_eq!(decode_check(&encode_check(&v[..])).ok(), Some(v));

        // Check that empty slice passes roundtrip.
        assert_eq!(decode_check(&encode_check(&[])), Ok(vec![]));
        // Check that `len > 4` is enforced.
        assert_eq!(decode_check(&encode(&[1, 2, 3])), Err(TooShortError { length: 3 }.into()));
    }
}

#[cfg(bench)]
mod benches {
    use test::{black_box, Bencher};

    #[bench]
    pub fn bench_encode_check_50(bh: &mut Bencher) {
        let data: alloc::vec::Vec<_> = (0u8..50).collect();

        bh.iter(|| {
            let r = super::encode_check(&data);
            black_box(&r);
        });
    }

    #[bench]
    pub fn bench_encode_check_xpub(bh: &mut Bencher) {
        let data: alloc::vec::Vec<_> = (0u8..78).collect(); // lenght of xpub

        bh.iter(|| {
            let r = super::encode_check(&data);
            black_box(&r);
        });
    }
}
