// Rust Bitcoin Library
// Written in 2014 by
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

//! # Base58 encoder and decoder

use std::io::extensions::{u64_to_le_bytes, u64_from_be_bytes};
use std::string;

use util::thinvec::ThinVec;
use util::hash::Sha256dHash;

/// An error that might occur during base58 decoding
#[deriving(Show, PartialEq, Eq, Clone)]
pub enum Base58Error {
  /// Invalid character encountered
  BadByte(u8),
  /// Checksum was not correct (expected, actual)
  BadChecksum(u32, u32),
  /// The length (in bytes) of the object was not correct
  InvalidLength(uint),
  /// Version byte(s) were not recognized
  InvalidVersion(Vec<u8>),
  /// Checked data was less than 4 bytes
  TooShort(uint),
  /// Any other error
  OtherBase58Error(String)
}

static BASE58_CHARS: &'static [u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static BASE58_DIGITS: [Option<u8>, ..128] = [
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

/// Trait for objects which can be read as base58
pub trait FromBase58 {
  /// Constructs an object flrom the byte-encoding (base 256)
  /// representation of its base58 format
  fn from_base58_layout(data: Vec<u8>) -> Result<Self, Base58Error>;

  /// Obtain an object from its base58 encoding
  fn from_base58(data: &str) -> Result<Self, Base58Error> {
    // 11/15 is just over log_256(58)
    let mut scratch = Vec::from_elem(1 + data.len() * 11 / 15, 0u8);
    // Build in base 256
    for d58 in data.bytes() {
      // Compute "X = X * 58 + next_digit" in base 256
      if d58 as uint > BASE58_DIGITS.len() {
        return Err(BadByte(d58));
      }
      let mut carry = match BASE58_DIGITS[d58 as uint] {
        Some(d58) => d58 as u32,
        None => { return Err(BadByte(d58)); }
      };
      for d256 in scratch.iter_mut().rev() {
        carry += *d256 as u32 * 58;
        *d256 = carry as u8;
        carry /= 256;
      }
      assert_eq!(carry, 0);
    }

    // Copy leading zeroes directly
    let mut ret: Vec<u8> = data.bytes().take_while(|&x| x == BASE58_CHARS[0])
                                       .map(|_| 0)
                                       .collect();
    // Copy rest of string
    ret.extend(scratch.move_iter().skip_while(|&x| x == 0));
    FromBase58::from_base58_layout(ret)
  }

  /// Obtain an object from its base58check encoding
  fn from_base58check(data: &str) -> Result<Self, Base58Error> {
    let mut ret: Vec<u8> = try!(FromBase58::from_base58(data));
    if ret.len() < 4 {
      return Err(TooShort(ret.len()));
    }
    let ck_start = ret.len() - 4;
    let expected = Sha256dHash::from_data(ret.slice_to(ck_start)).into_le().low_u32();
    let actual = Int::from_be(u64_from_be_bytes(ret.as_slice(), ck_start, 4) as u32);
    if expected != actual {
      return Err(BadChecksum(expected, actual));
    }

    ret.truncate(ck_start);
    FromBase58::from_base58_layout(ret)
  }
}

/// Directly encode a slice as base58
pub fn base58_encode_slice(data: &[u8]) -> String {
  // 7/5 is just over log_58(256)
  let mut scratch = Vec::from_elem(1 + data.len() * 7 / 5, 0u8);
  // Build in base 58
  for &d256 in data.base58_layout().iter() {
    // Compute "X = X * 256 + next_digit" in base 58
    let mut carry = d256 as u32;
    for d58 in scratch.iter_mut().rev() {
      carry += *d58 as u32 << 8;
      *d58 = (carry % 58) as u8;
      carry /= 58;
    }
    assert_eq!(carry, 0);
  }

  // Unsafely translate the bytes to a utf8 string
  unsafe {
    // Copy leading zeroes directly
    let mut ret = string::raw::from_utf8(data.iter().take_while(|&&x| x == 0)
                                                    .map(|_|  BASE58_CHARS[0])
                                                    .collect());
    // Copy rest of string
    ret.as_mut_vec().extend(scratch.move_iter().skip_while(|&x| x == 0)
                                               .map(|x| BASE58_CHARS[x as uint]));
    ret
  }
}

/// Trait for objects which can be written as base58
pub trait ToBase58 {
  /// The serialization to be converted into base58
  fn base58_layout(&self) -> Vec<u8>;

  /// Obtain a string with the base58 encoding of the object
  fn to_base58(&self) -> String {
    base58_encode_slice(self.base58_layout().as_slice())
  }

  /// Obtain a string with the base58check encoding of the object
  /// (Tack the first 4 256-digits of the object's Bitcoin hash onto the end.)
  fn to_base58check(&self) -> String {
    let mut data = self.base58_layout();
    let checksum = Sha256dHash::from_data(data.as_slice()).into_le().low_u32();
    u64_to_le_bytes(checksum as u64, 4,
                    |ck| { data.push_all(ck); base58_encode_slice(data.as_slice()) })
  }
}

// Trivial implementations for slices and vectors
impl<'a> ToBase58 for &'a [u8] {
  fn base58_layout(&self) -> Vec<u8> { (*self).to_vec() }
  fn to_base58(&self) -> String { base58_encode_slice(*self) }
}

impl ToBase58 for Vec<u8> {
  fn base58_layout(&self) -> Vec<u8> { self.clone() }
  fn to_base58(&self) -> String { base58_encode_slice(self.as_slice()) }
}

impl ToBase58 for ThinVec<u8> {
  fn base58_layout(&self) -> Vec<u8> { self.as_slice().to_vec() }
  fn to_base58(&self) -> String { base58_encode_slice(self.as_slice()) }
}

impl FromBase58 for Vec<u8> {
  fn from_base58_layout(data: Vec<u8>) -> Result<Vec<u8>, Base58Error> {
    Ok(data)
  }
}

impl FromBase58 for ThinVec<u8> {
  fn from_base58_layout(data: Vec<u8>) -> Result<ThinVec<u8>, Base58Error> {
    Ok(ThinVec::from_vec(data))
  }
}


#[cfg(test)]
mod tests {
  use serialize::hex::FromHex;

  use super::ToBase58;
  use super::FromBase58;

  #[test]
  fn test_base58_encode() {
    // Basics
    assert_eq!([0].as_slice().to_base58().as_slice(), "1");
    assert_eq!([1].as_slice().to_base58().as_slice(), "2");
    assert_eq!([58].as_slice().to_base58().as_slice(), "21");
    assert_eq!([13, 36].as_slice().to_base58().as_slice(), "211");

    // Leading zeroes
    assert_eq!([0, 13, 36].as_slice().to_base58().as_slice(), "1211");
    assert_eq!([0, 0, 0, 0, 13, 36].as_slice().to_base58().as_slice(), "1111211");

    // Addresses
    assert_eq!("00f8917303bfa8ef24f292e8fa1419b20460ba064d".from_hex().unwrap().to_base58check().as_slice(),
               "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH");
  }

  #[test]
  fn test_base58_decode() {
    // Basics
    assert_eq!(FromBase58::from_base58("1"), Ok(vec![0u8]));
    assert_eq!(FromBase58::from_base58("2"), Ok(vec![1u8]));
    assert_eq!(FromBase58::from_base58("21"), Ok(vec![58u8]));
    assert_eq!(FromBase58::from_base58("211"), Ok(vec![13u8, 36]));

    // Leading zeroes
    assert_eq!(FromBase58::from_base58("1211"), Ok(vec![0u8, 13, 36]));
    assert_eq!(FromBase58::from_base58("111211"), Ok(vec![0u8, 0, 0, 13, 36]));

    // Addresses
    assert_eq!(FromBase58::from_base58check("1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH"),
               Ok("00f8917303bfa8ef24f292e8fa1419b20460ba064d".from_hex().unwrap()))
  }

  #[test]
  fn test_base58_roundtrip() {
    let s = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs";
    let v: Vec<u8> = FromBase58::from_base58check(s).unwrap();
    assert_eq!(v.to_base58check().as_slice(), s);
    assert_eq!(FromBase58::from_base58check(v.to_base58check().as_slice()), Ok(v));
  }
}

