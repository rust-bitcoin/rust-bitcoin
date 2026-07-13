// SPDX-License-Identifier: CC0-1.0

//! # Bitcoin Base58 Encoding and Decoding
//!
//! This crate can be used in a no-std environment but requires an allocator for decoding.

#![no_std]
// Experimental features we need.
#![cfg_attr(bench, feature(test))]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Instead of littering the codebase for non-fuzzing and bench code just globally allow.
#![cfg_attr(fuzzing, allow(dead_code, unused_imports))]
#![cfg_attr(bench, allow(dead_code, unused_imports))]
// Exclude lints we don't think are valuable.
#![allow(clippy::incompatible_msrv)] // Has FPs and we're testing it which is more reliable anyway.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(bench)]
extern crate test;

#[cfg(feature = "std")]
extern crate std;

static BASE58_CHARS: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub mod error;

#[cfg(feature = "alloc")]
#[cfg(not(feature = "std"))]
pub use alloc::{string::String, vec::Vec};
#[cfg(feature = "alloc")]
use core::convert::Infallible;
use core::fmt;
#[cfg(feature = "std")]
pub use std::{string::String, vec::Vec};

use hashes::sha256d;
#[cfg(feature = "alloc")]
use internals::array::ArrayExt;
use internals::array_vec::ArrayVec;
#[allow(unused)] // MSRV polyfill
#[cfg(feature = "alloc")]
use internals::slice::SliceExt;

#[cfg(not(feature = "alloc"))]
use crate::error::InputTooLongErrorInner;
#[cfg(feature = "alloc")]
use crate::error::{IncorrectChecksumError, TooShortError};

#[rustfmt::skip]                // Keep public re-exports separate.
#[cfg(feature = "alloc")]
#[doc(no_inline)]
pub use self::error::{Error, InvalidCharacterError};
#[doc(no_inline)]
pub use self::error::InputTooLongError;

#[rustfmt::skip]
#[cfg(feature = "alloc")]
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
///
/// # Errors
///
/// Returns an error if the input contains an invalid base58 character (not in the base58 alphabet).
#[allow(clippy::missing_panics_doc)] // Internal assertion, not user-controllable.
#[cfg(feature = "alloc")]
pub fn decode(data: &str) -> Result<Vec<u8>, InvalidCharacterError> {
    // 11/15 is just over log_256(58)
    let mut scratch = Vec::with_capacity(1 + data.len() * 11 / 15);
    // Build in base 256
    for d58 in data.bytes() {
        // Compute "X = X * 58 + next_digit" in base 256
        if usize::from(d58) >= BASE58_DIGITS.len() {
            return Err(InvalidCharacterError::new(d58));
        }
        let mut carry = match BASE58_DIGITS[usize::from(d58)] {
            Some(d58) => u32::from(d58),
            None => {
                return Err(InvalidCharacterError::new(d58));
            }
        };
        if scratch.is_empty() {
            for _ in 0..scratch.capacity() {
                scratch.push(carry as u8);
                carry /= 256;
            }
        } else {
            for d256 in &mut scratch {
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
///
/// # Errors
///
/// * The input contains an invalid base58 character.
/// * The decoded data is less than 4 bytes (too short for checksum verification).
/// * The checksum does not match the expected value.
#[cfg(feature = "alloc")]
pub fn decode_check(data: &str) -> Result<Vec<u8>, Error> {
    let mut ret: Vec<u8> = decode(data)?;
    let (remaining, &data_check) =
        ret.split_last_chunk::<4>().ok_or(TooShortError { length: ret.len() })?;

    let hash_check = *sha256d::Hash::hash(remaining).as_byte_array().sub_array::<0, 4>();

    let expected = u32::from_le_bytes(hash_check);
    let actual = u32::from_le_bytes(data_check);

    if actual != expected {
        return Err(IncorrectChecksumError { incorrect: actual, expected }.into());
    }

    ret.truncate(remaining.len());
    Ok(ret)
}

const SHORT_OPT_BUFFER_LEN: usize = 128;

/// A base58check-encoded string (data followed by a 4 byte `SHA256d` checksum, base58-encoded).
///
/// Strings of at most 128 characters can be encoded without allocating. Longer strings can only
/// be produced when the `alloc` feature is enabled.
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct Base58CkString(Base58CkInner);

#[derive(Clone, Hash, PartialEq, Eq)]
enum Base58CkInner {
    /// ASCII string of length at most 128 base58 characters (roughly 93 bytes)
    Small(ArrayVec<u8, SHORT_OPT_BUFFER_LEN>),
    /// Unbounded string (available with "alloc" only).
    #[cfg(feature = "alloc")]
    Large(Vec<u8>),
}

impl Base58CkString {
    /// Encodes `data` as a base58check string, including the checksum.
    ///
    /// The checksum is the first four bytes of the `SHA256d` of the data, concatenated onto the
    /// end before encoding.
    ///
    /// # Errors
    ///
    /// If the `alloc` feature is disabled and `data` encodes to more than 128 base58 characters.
    /// With `alloc` enabled this function is infallible. If you will only be using this with `alloc`,
    /// you can alternatively call [`Self::encode_unbounded`].
    pub fn encode(data: &[u8]) -> Result<Self, InputTooLongError> {
        #[cfg(feature = "alloc")]
        {
            Ok(Self::encode_unbounded(data))
        }
        #[cfg(not(feature = "alloc"))]
        {
            let mut buf = ArrayVec::<u8, SHORT_OPT_BUFFER_LEN>::new();
            let checksum = sha256d::Hash::hash(data);
            let iter = data.iter().copied().chain(checksum.as_byte_array()[0..4].iter().copied());

            encode_to_buffer(iter, &mut buf)
                .map(|()| Self(Base58CkInner::Small(buf)))
                .map_err(|_| InputTooLongError(InputTooLongErrorInner { input_len: data.len() }))
        }
    }

    /// Encodes `data` of any length as a base58check string.
    #[allow(clippy::missing_panics_doc)] // encode_to_buffer is infallible in both cases
    #[cfg(feature = "alloc")]
    pub fn encode_unbounded(data: &[u8]) -> Self {
        let checksum = sha256d::Hash::hash(data);
        let iter = data.iter().copied().chain(checksum.as_byte_array()[0..4].iter().copied());
        let reserve_len = encoded_check_reserve_len(data.len());
        if reserve_len <= SHORT_OPT_BUFFER_LEN {
            let mut buf = ArrayVec::<u8, SHORT_OPT_BUFFER_LEN>::new();
            encode_to_buffer(iter, &mut buf)
                .expect("encode_to_buffer is infallible with well-sized ArrayVec buf");
            Self(Base58CkInner::Small(buf))
        } else {
            let mut buf = Vec::with_capacity(reserve_len);
            encode_to_buffer(iter, &mut buf).expect("encode_to_buffer is infallible with Vec buf");
            Self(Base58CkInner::Large(buf))
        }
    }

    /// Returns the base58check-encoded string.
    #[allow(clippy::missing_panics_doc)] // Base58 characters are always valid ASCII.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).expect("base58 characters are valid ASCII")
    }

    /// Returns the base58check-encoded string as ASCII bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self.0 {
            Base58CkInner::Small(ref data) => data.slice(),
            #[cfg(feature = "alloc")]
            Base58CkInner::Large(ref data) => data.slice(),
        }
    }

    /// Returns the number of bytes/ASCII chars in the base58check-encoded string.
    pub fn len(&self) -> usize { self.as_bytes().len() }

    /// Returns true if the base58check-encoded string is empty.
    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

impl AsRef<str> for Base58CkString {
    fn as_ref(&self) -> &str { self.as_str() }
}

impl AsRef<[u8]> for Base58CkString {
    fn as_ref(&self) -> &[u8] { self.as_bytes() }
}

impl fmt::Display for Base58CkString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { self.as_str().fmt(f) }
}

impl fmt::Debug for Base58CkString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Base58CkString").field(&self.as_str()).finish()
    }
}

/// Returns the length to reserve when encoding base58 without checksum
#[cfg(feature = "alloc")]
const fn encoded_reserve_len(unencoded_len: usize) -> usize {
    // log2(256) / log2(58) ~ 1.37 = 137 / 100
    unencoded_len * 137 / 100
}

/// Returns the length to reserve when encoding base58 with checksum
#[cfg(feature = "alloc")]
const fn encoded_check_reserve_len(unencoded_len: usize) -> usize {
    encoded_reserve_len(unencoded_len + 4)
}

trait Buffer: Sized {
    type Err: fmt::Debug;

    fn try_push(&mut self, val: u8) -> Result<(), Self::Err>;
    fn slice(&self) -> &[u8];
    fn slice_mut(&mut self) -> &mut [u8];
}

#[cfg(feature = "alloc")]
impl Buffer for Vec<u8> {
    type Err = Infallible;

    fn try_push(&mut self, val: u8) -> Result<(), Self::Err> {
        self.push(val);
        Ok(())
    }

    fn slice(&self) -> &[u8] { self }

    fn slice_mut(&mut self) -> &mut [u8] { self }
}

impl<const N: usize> Buffer for ArrayVec<u8, N> {
    type Err = internals::array_vec::error::Error;

    fn try_push(&mut self, val: u8) -> Result<(), Self::Err> { self.try_push(val) }

    fn slice(&self) -> &[u8] { self.as_slice() }

    fn slice_mut(&mut self) -> &mut [u8] { self.as_mut_slice() }
}

// Base58 encode the data in the iterator `data` to the buffer buf as ASCII bytes
fn encode_to_buffer<I: Iterator<Item = u8>, T: Buffer>(data: I, buf: &mut T) -> Result<(), T::Err> {
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
            buf.try_push((carry % 58) as u8)?; // cast loses data intentionally
            carry /= 58;
        }
    }

    // ... then reverse it and convert to ASCII
    for _ in 0..leading_zero_count {
        buf.try_push(0)?;
    }

    buf.slice_mut().reverse();
    for ch in buf.slice_mut() {
        *ch = BASE58_CHARS[usize::from(*ch)];
    }

    Ok(())
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use alloc::vec;

    use hex::hex;

    use super::*;

    #[test]
    fn base58_encode() {
        // Basics
        assert_eq!(Base58CkString::encode_unbounded(&[13, 36][..]).as_str(), "7YY3x3vS");

        // Leading zeroes
        assert_eq!(Base58CkString::encode_unbounded(&[0, 13, 36][..]).as_str(), "17YZPJu4L");
        assert_eq!(
            Base58CkString::encode_unbounded(&[0, 0, 0, 0, 13, 36][..]).as_str(),
            "11117YaXDHva"
        );

        // Long input (>128 bytes => has to use heap)
        let res = Base58CkString::encode_unbounded(
            "BitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBit\
        coinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoin"
                .as_bytes(),
        );
        let exp =
            "4hqMa7U6Kxg4YstWo7KztyYAAkTuhuLWTvrHia8nrgx5eb2E8cf79wD9dBjd4c9STsTTXWZT5pp985vP\
        nL4MVTQrt4EW5jgAk5Fh81PoF6jjhCyUZY2kZ8iYaM5XpfPkZ6aki57S6oiuVv4cmJz2ou8ssxEKNRJMWjSFL5izLbe\
        s9rugAdBdrboyHMSAtSNY1Nrb4";
        assert_eq!(res.as_str(), exp);

        // Addresses
        let addr = hex!("00f8917303bfa8ef24f292e8fa1419b20460ba064d");
        assert_eq!(
            Base58CkString::encode_unbounded(&addr[..]).as_str(),
            "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH"
        );
    }

    #[test]
    fn base58_decode() {
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
            decode_check("1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH").ok().unwrap().as_slice(),
            hex!("00f8917303bfa8ef24f292e8fa1419b20460ba064d")
        );
        // Non Base58 char.
        assert_eq!(decode("¢").unwrap_err(), InvalidCharacterError::new(194));
    }

    #[test]
    fn base58_roundtrip() {
        let s = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs";
        let v: Vec<u8> = decode_check(s).unwrap();
        assert_eq!(Base58CkString::encode_unbounded(&v[..]).as_str(), s);
        assert_eq!(decode_check(Base58CkString::encode_unbounded(&v[..]).as_str()).ok(), Some(v));

        // Check that empty slice passes roundtrip.
        assert_eq!(decode_check(Base58CkString::encode_unbounded(&[]).as_str()), Ok(vec![]));
        // Check that `len > 4` is enforced.
        assert_eq!(decode_check("Ldp"), Err(TooShortError { length: 3 }.into()));
    }
}

#[cfg(bench)]
mod benches {
    use test::{black_box, Bencher};

    #[bench]
    pub fn bench_encode_check_50(bh: &mut Bencher) {
        let data: alloc::vec::Vec<_> = (0u8..50).collect();

        bh.iter(|| {
            let r = super::Base58CkString::encode_unbounded(&data);
            black_box(r.as_str());
        });
    }

    #[bench]
    pub fn bench_encode_check_xpub(bh: &mut Bencher) {
        let data: alloc::vec::Vec<_> = (0u8..78).collect(); // length of xpub

        bh.iter(|| {
            let r = super::Base58CkString::encode_unbounded(&data);
            black_box(r.as_str());
        });
    }
}
