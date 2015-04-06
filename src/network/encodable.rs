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

//! # Consensus-encodable types
//!
//! This is basically a replacement of the `Encodable` trait which does
//! normalization for endianness, etc., to ensure that the encoding
//! matches for endianness, etc., to ensure that the encoding matches
//! the network consensus encoding.
//!
//! Essentially, anything that must go on the -disk- or -network- must
//! be encoded using the `ConsensusEncodable` trait, since this data
//! must be the same for all systems. Any data going to the -user-, e.g.
//! over JSONRPC, should use the ordinary `Encodable` trait. (This
//! should also be the same across systems, of course, but has some
//! critical differences from the network format, e.g. scripts come
//! with an opcode decode, hashes are big-endian, numbers are typically
//! big-endian decimals, etc.)
//!

use std::collections::HashMap;
use std::default::Default;
use std::hash::{Hash, Hasher};
use std::u32;

use util::hash::Sha256dHash;
use network::serialize::{SimpleDecoder, SimpleEncoder};

/// Data which can be encoded in a consensus-consistent way
pub trait ConsensusEncodable<S: SimpleEncoder> {
  /// Encode an object with a well-defined format
  fn consensus_encode(&self, e: &mut S) -> Result<(), S::Error>;
}

/// Data which can be encoded in a consensus-consistent way
pub trait ConsensusDecodable<D: SimpleDecoder> {
  /// Decode an object with a well-defined format
  fn consensus_decode(d: &mut D) -> Result<Self, D::Error>;
}

/// A variable-length unsigned integer
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct VarInt(pub u64);

/// Data which must be preceded by a 4-byte checksum
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CheckedData(pub Vec<u8>);

// Primitive types
impl<S: SimpleEncoder> ConsensusEncodable<S> for u8 {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> { s.emit_u8(*self) }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for u16 {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> { s.emit_u16(self.to_le()) }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for u32 {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> { s.emit_u32(self.to_le()) }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for u64 {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> { s.emit_u64(self.to_le()) }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for i32 {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> { s.emit_i32(self.to_le()) }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for i64 {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> { s.emit_i64(self.to_le()) }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for VarInt {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
    let &VarInt(n) = self;
    match n {
      0...0xFC             => { (n as u8).consensus_encode(s) }
      0xFD...0xFFFF        => { try!(s.emit_u8(0xFD)); (n as u16).consensus_encode(s) }
      0x10000...0xFFFFFFFF => { try!(s.emit_u8(0xFE)); (n as u32).consensus_encode(s) }
      _                    => { try!(s.emit_u8(0xFF)); (n as u64).consensus_encode(s) }
    }
  }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for u8 {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<u8, D::Error> { d.read_u8() }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for u16 {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<u16, D::Error> { d.read_u16().map(|n| u16::from_le(n)) }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for u32 {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<u32, D::Error> { d.read_u32().map(|n| u32::from_le(n)) }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for u64 {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<u64, D::Error> { d.read_u64().map(|n| u64::from_le(n)) }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for i32 {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<i32, D::Error> { d.read_i32().map(|n| i32::from_le(n)) }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for i64 {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<i64, D::Error> { d.read_i64().map(|n| i64::from_le(n)) }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for VarInt {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<VarInt, D::Error> {
    let n = try!(d.read_u8());
    match n {
      0xFF => d.read_u64().map(|n| VarInt(u64::from_le(n))),
      0xFE => d.read_u32().map(|n| VarInt(u32::from_le(n) as u64)),
      0xFD => d.read_u16().map(|n| VarInt(u16::from_le(n) as u64)),
      n => Ok(VarInt(n as u64))
    }
  }
}

// Booleans
impl<S: SimpleEncoder> ConsensusEncodable<S> for bool {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> { s.emit_u8(if *self {1} else {0}) }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for bool {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<bool, D::Error> { d.read_u8().map(|n| n != 0) }
}

// Strings
impl<S: SimpleEncoder> ConsensusEncodable<S> for String {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
    self.as_bytes().consensus_encode(s)
  }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for String {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<String, D::Error> {
    String::from_utf8(try!(ConsensusDecodable::consensus_decode(d))).map_err(|_| d.error("String was not valid UTF8"))
  }
}


// Arrays
macro_rules! impl_array {
  ( $size:expr ) => (
    impl<S: SimpleEncoder, T: ConsensusEncodable<S>> ConsensusEncodable<S> for [T; $size] {
      #[inline]
      fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
        for i in self.iter() { try!(i.consensus_encode(s)); }
        Ok(())
      }
    }

    impl<D: SimpleDecoder, T:ConsensusDecodable<D> + Copy> ConsensusDecodable<D> for [T; $size] {
      #[inline]
      fn consensus_decode(d: &mut D) -> Result<[T; $size], D::Error> {
        // Set everything to the first decode
        let mut ret = [try!(ConsensusDecodable::consensus_decode(d)); $size];
        // Set the rest
        for i in 1..$size { ret[i] = try!(ConsensusDecodable::consensus_decode(d)); }
        Ok(ret)
      }
    }
  );
}

impl_array!(2);
impl_array!(4);
impl_array!(8);
impl_array!(12);
impl_array!(16);
impl_array!(32);

impl<'a, S: SimpleEncoder, T: ConsensusEncodable<S>> ConsensusEncodable<S> for &'a [T] {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
    try!(VarInt(self.len() as u64).consensus_encode(s));
    for c in self.iter() { try!(c.consensus_encode(s)); }
    Ok(())
  }
}

// Cannot decode a slice

// Vectors
impl<S: SimpleEncoder, T: ConsensusEncodable<S>> ConsensusEncodable<S> for Vec<T> {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> { self.as_slice().consensus_encode(s) }
}

impl<D: SimpleDecoder, T: ConsensusDecodable<D>> ConsensusDecodable<D> for Vec<T> {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<Vec<T>, D::Error> {
    let VarInt(len): VarInt = try!(ConsensusDecodable::consensus_decode(d));
    let mut ret = Vec::with_capacity(len as usize);
    for _ in 0..len { ret.push(try!(ConsensusDecodable::consensus_decode(d))); }
    Ok(ret)
  }
}

impl<S: SimpleEncoder, T: ConsensusEncodable<S>> ConsensusEncodable<S> for Box<[T]> {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> { (&self[..]).consensus_encode(s) }
}

impl<D: SimpleDecoder, T: ConsensusDecodable<D>> ConsensusDecodable<D> for Box<[T]> {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<Box<[T]>, D::Error> {
    let VarInt(len): VarInt = try!(ConsensusDecodable::consensus_decode(d));
    unsafe {
      let len = len as usize;
      let mut ret = Vec::with_capacity(len);
      for i in 0..len { ret.push(try!(ConsensusDecodable::consensus_decode(d))); }
      Ok(ret.into_boxed_slice())
    }
  }
}

// Options (encoded as vectors of length 0 or 1)
impl<S: SimpleEncoder, T: ConsensusEncodable<S>> ConsensusEncodable<S> for Option<T> {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
    match *self {
      Some(ref data) => {
        try!(1u8.consensus_encode(s));
        try!(data.consensus_encode(s));
      }
      None => { try!(0u8.consensus_encode(s)); }
    }
    Ok(())
  }
}

impl<D: SimpleDecoder, T:ConsensusDecodable<D>> ConsensusDecodable<D> for Option<T> {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<Option<T>, D::Error> {
    let bit: u8 = try!(ConsensusDecodable::consensus_decode(d));
    Ok(if bit != 0 {
      Some(try!(ConsensusDecodable::consensus_decode(d)))
    } else {
      None
    })
  }
}


/// Do a double-SHA256 on some data and return the first 4 bytes
fn sha2_checksum(data: &[u8]) -> [u8; 4] {
  let checksum = Sha256dHash::from_data(data);
  [checksum[0], checksum[1], checksum[2], checksum[3]]
}

// Checked data
impl<S: SimpleEncoder> ConsensusEncodable<S> for CheckedData {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
    let &CheckedData(ref data) = self;
    try!((data.len() as u32).consensus_encode(s));
    try!(sha2_checksum(data.as_slice()).consensus_encode(s));
    // We can't just pass to the slice encoder since it'll insert a length
    for ch in data.iter() {
      try!(ch.consensus_encode(s));
    }
    Ok(())
  }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for CheckedData {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<CheckedData, D::Error> {
    let len: u32 = try!(ConsensusDecodable::consensus_decode(d));
    let checksum: [u8; 4] = try!(ConsensusDecodable::consensus_decode(d));
    let mut ret = Vec::with_capacity(len as usize);
    for _ in 0..len { ret.push(try!(ConsensusDecodable::consensus_decode(d))); }
    let expected_checksum = sha2_checksum(ret.as_slice());
    if expected_checksum != checksum {
      Err(d.error("bad checksum"))
    } else {
      Ok(CheckedData(ret))
    }
  }
}

// Tuples
macro_rules! tuple_encode {
  ($($x:ident),*) => (
    impl <S: SimpleEncoder, $($x: ConsensusEncodable<S>),*> ConsensusEncodable<S> for ($($x),*) {
      #[inline]
      #[allow(non_snake_case)]
      fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
        let &($(ref $x),*) = self;
        $( try!($x.consensus_encode(s)); )*
        Ok(())
      }
    }

    impl<D: SimpleDecoder, $($x: ConsensusDecodable<D>),*> ConsensusDecodable<D> for ($($x),*) {
      #[inline]
      #[allow(non_snake_case)]
      fn consensus_decode(d: &mut D) -> Result<($($x),*), D::Error> {
        Ok(($(try!({let $x = ConsensusDecodable::consensus_decode(d); $x })),*))
      }
    }
  );
}

tuple_encode!(T0, T1);
tuple_encode!(T0, T1, T2, T3);
tuple_encode!(T0, T1, T2, T3, T4, T5);
tuple_encode!(T0, T1, T2, T3, T4, T5, T6, T7);

// References
impl<S: SimpleEncoder, T: ConsensusEncodable<S>> ConsensusEncodable<S> for Box<T> {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> { (**self).consensus_encode(s) }
}

impl<D: SimpleDecoder, T: ConsensusDecodable<D>> ConsensusDecodable<D> for Box<T> {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<Box<T>, D::Error> {
    ConsensusDecodable::consensus_decode(d).map(|res| Box::new(res))
  }
}

// HashMap
impl<S, K, V, H> ConsensusEncodable<S> for HashMap<K, V, H>
  where S: SimpleEncoder,
        H: Hasher + Default,
        K: ConsensusEncodable<S> + Eq + Hash,
        V: ConsensusEncodable<S>
{
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
    try!(VarInt(self.len() as u64).consensus_encode(s));
    for (key, value) in self.iter() {
      try!(key.consensus_encode(s));
      try!(value.consensus_encode(s));
    }
    Ok(())
  }
}

impl<D, K, V, H> ConsensusDecodable<D> for HashMap<K, V, H>
  where D: SimpleDecoder,
        H: Hasher + Default,
        K: ConsensusDecodable<D> + Eq + Hash,
        V: ConsensusDecodable<D>
{
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<HashMap<K, V, H>, D::Error> {
    let VarInt(len): VarInt = try!(ConsensusDecodable::consensus_decode(d));

    let mut ret = HashMap::with_capacity_and_hasher(len as usize, Default::default());
    for _ in 0..len {
      ret.insert(try!(ConsensusDecodable::consensus_decode(d)),
                 try!(ConsensusDecodable::consensus_decode(d)));
    }
    Ok(ret)
  }
}



// Tests
#[cfg(test)]
mod tests {
  use super::{CheckedData, VarInt};

  use std::io::IoResult;

  use network::serialize::{deserialize, serialize};

  #[test]
  fn serialize_int_test() {
    // bool
    assert_eq!(serialize(&false), Ok(vec![0u8]));
    assert_eq!(serialize(&true), Ok(vec![1u8]));
    // u8
    assert_eq!(serialize(&1u8), Ok(vec![1u8]));
    assert_eq!(serialize(&0u8), Ok(vec![0u8]));
    assert_eq!(serialize(&255u8), Ok(vec![255u8]));
    // u16
    assert_eq!(serialize(&1u16), Ok(vec![1u8, 0]));
    assert_eq!(serialize(&256u16), Ok(vec![0u8, 1]));
    assert_eq!(serialize(&5000u16), Ok(vec![136u8, 19]));
    // u32
    assert_eq!(serialize(&1u32), Ok(vec![1u8, 0, 0, 0]));
    assert_eq!(serialize(&256u32), Ok(vec![0u8, 1, 0, 0]));
    assert_eq!(serialize(&5000u32), Ok(vec![136u8, 19, 0, 0]));
    assert_eq!(serialize(&500000u32), Ok(vec![32u8, 161, 7, 0]));
    assert_eq!(serialize(&168430090u32), Ok(vec![10u8, 10, 10, 10]));
    // TODO: test negative numbers
    assert_eq!(serialize(&1i32), Ok(vec![1u8, 0, 0, 0]));
    assert_eq!(serialize(&256i32), Ok(vec![0u8, 1, 0, 0]));
    assert_eq!(serialize(&5000i32), Ok(vec![136u8, 19, 0, 0]));
    assert_eq!(serialize(&500000i32), Ok(vec![32u8, 161, 7, 0]));
    assert_eq!(serialize(&168430090i32), Ok(vec![10u8, 10, 10, 10]));
    // u64
    assert_eq!(serialize(&1u64), Ok(vec![1u8, 0, 0, 0, 0, 0, 0, 0]));
    assert_eq!(serialize(&256u64), Ok(vec![0u8, 1, 0, 0, 0, 0, 0, 0]));
    assert_eq!(serialize(&5000u64), Ok(vec![136u8, 19, 0, 0, 0, 0, 0, 0]));
    assert_eq!(serialize(&500000u64), Ok(vec![32u8, 161, 7, 0, 0, 0, 0, 0]));
    assert_eq!(serialize(&723401728380766730u64), Ok(vec![10u8, 10, 10, 10, 10, 10, 10, 10]));
    // TODO: test negative numbers
    assert_eq!(serialize(&1i64), Ok(vec![1u8, 0, 0, 0, 0, 0, 0, 0]));
    assert_eq!(serialize(&256i64), Ok(vec![0u8, 1, 0, 0, 0, 0, 0, 0]));
    assert_eq!(serialize(&5000i64), Ok(vec![136u8, 19, 0, 0, 0, 0, 0, 0]));
    assert_eq!(serialize(&500000i64), Ok(vec![32u8, 161, 7, 0, 0, 0, 0, 0]));
    assert_eq!(serialize(&723401728380766730i64), Ok(vec![10u8, 10, 10, 10, 10, 10, 10, 10]));
  }

  #[test]
  fn serialize_varint_test() {
    assert_eq!(serialize(&VarInt(10)), Ok(vec![10u8]));
    assert_eq!(serialize(&VarInt(0xFC)), Ok(vec![0xFCu8]));
    assert_eq!(serialize(&VarInt(0xFD)), Ok(vec![0xFDu8, 0xFD, 0]));
    assert_eq!(serialize(&VarInt(0xFFF)), Ok(vec![0xFDu8, 0xFF, 0xF]));
    assert_eq!(serialize(&VarInt(0xF0F0F0F)), Ok(vec![0xFEu8, 0xF, 0xF, 0xF, 0xF]));
    assert_eq!(serialize(&VarInt(0xF0F0F0F0F0E0)), Ok(vec![0xFFu8, 0xE0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0, 0]));
  }

  #[test]
  fn serialize_checkeddata_test() {
    let cd = CheckedData(vec![1u8, 2, 3, 4, 5]);
    assert_eq!(serialize(&cd), Ok(vec![5, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5]));
  }

  #[test]
  fn serialize_vector_test() {
    assert_eq!(serialize(&vec![1u8, 2, 3]), Ok(vec![3u8, 1, 2, 3]));
    assert_eq!(serialize(&[1u8, 2, 3].as_slice()), Ok(vec![3u8, 1, 2, 3]));
    // TODO: test vectors of more interesting objects
  }

  #[test]
  fn serialize_strbuf_test() {
    assert_eq!(serialize(&"Andrew".to_string()), Ok(vec![6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]));
  }

  #[test]
  fn serialize_box_test() {
    assert_eq!(serialize(&Box::new(1u8)), Ok(vec![1u8]));
    assert_eq!(serialize(&Box::new(1u16)), Ok(vec![1u8, 0]));
    assert_eq!(serialize(&Box::new(1u64)), Ok(vec![1u8, 0, 0, 0, 0, 0, 0, 0]));
  }

  #[test]
  fn serialize_option_test() {
    let none_ser = serialize(&None::<u8>);
    let some_ser = serialize(&Some(0xFFu8));
    assert_eq!(none_ser, Ok(vec![0]));
    assert_eq!(some_ser, Ok(vec![1, 0xFF]));
  }

  #[test]
  fn deserialize_int_test() {
    // bool
    assert_eq!(deserialize(vec![58u8, 0]), Ok(true));
    assert_eq!(deserialize(vec![58u8]), Ok(true));
    assert_eq!(deserialize(vec![1u8]), Ok(true));
    assert_eq!(deserialize(vec![0u8]), Ok(false));
    assert_eq!(deserialize(vec![0u8, 1]), Ok(false));

    // u8
    assert_eq!(deserialize(vec![58u8]), Ok(58u8));

    // u16
    assert_eq!(deserialize(vec![0x01u8, 0x02]), Ok(0x0201u16));
    assert_eq!(deserialize(vec![0xABu8, 0xCD]), Ok(0xCDABu16));
    assert_eq!(deserialize(vec![0xA0u8, 0x0D]), Ok(0xDA0u16));
    let failure16: IoResult<u16> = deserialize(vec![1u8]);
    assert!(failure16.is_err());

    // u32
    assert_eq!(deserialize(vec![0xABu8, 0xCD, 0, 0]), Ok(0xCDABu32));
    assert_eq!(deserialize(vec![0xA0u8, 0x0D, 0xAB, 0xCD]), Ok(0xCDAB0DA0u32));
    let failure32: IoResult<u32> = deserialize(vec![1u8, 2, 3]);
    assert!(failure32.is_err());
    // TODO: test negative numbers
    assert_eq!(deserialize(vec![0xABu8, 0xCD, 0, 0]), Ok(0xCDABi32));
    assert_eq!(deserialize(vec![0xA0u8, 0x0D, 0xAB, 0x2D]), Ok(0x2DAB0DA0i32));
    let failurei32: IoResult<i32> = deserialize(vec![1u8, 2, 3]);
    assert!(failurei32.is_err());

    // u64
    assert_eq!(deserialize(vec![0xABu8, 0xCD, 0, 0, 0, 0, 0, 0]), Ok(0xCDABu64));
    assert_eq!(deserialize(vec![0xA0u8, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99]), Ok(0x99000099CDAB0DA0u64));
    let failure64: IoResult<u64> = deserialize(vec![1u8, 2, 3, 4, 5, 6, 7]);
    assert!(failure64.is_err());
    // TODO: test negative numbers
    assert_eq!(deserialize(vec![0xABu8, 0xCD, 0, 0, 0, 0, 0, 0]), Ok(0xCDABi64));
    assert_eq!(deserialize(vec![0xA0u8, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99]), Ok(-0x66ffff663254f260i64));
    let failurei64: IoResult<i64> = deserialize(vec![1u8, 2, 3, 4, 5, 6, 7]);
    assert!(failurei64.is_err());
  }

  #[test]
  fn deserialize_vec_test() {
    assert_eq!(deserialize(vec![3u8, 2, 3, 4]), Ok(vec![2u8, 3, 4]));
    assert_eq!(deserialize(vec![4u8, 2, 3, 4, 5, 6]), Ok(vec![2u8, 3, 4, 5]));
  }

  #[test]
  fn deserialize_strbuf_test() {
    assert_eq!(deserialize(vec![6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]), Ok(String::from_str("Andrew")));
  }

  #[test]
  fn deserialize_checkeddata_test() {
    let cd: IoResult<CheckedData> = deserialize(vec![5u8, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5]);
    assert_eq!(cd, Ok(CheckedData(vec![1u8, 2, 3, 4, 5])));
  }

  #[test]
  fn deserialize_option_test() {
    let none: IoResult<Option<u8>> = deserialize(vec![0u8]);
    let good: IoResult<Option<u8>> = deserialize(vec![1u8, 0xFF]);
    let bad: IoResult<Option<u8>> = deserialize(vec![2u8]);
    assert!(bad.is_err());
    assert_eq!(none, Ok(None));
    assert_eq!(good, Ok(Some(0xFF)));
  }

  #[test]
  fn deserialize_box_test() {
    let zero: IoResult<Box<u8>> = deserialize(vec![0u8]);
    let one: IoResult<Box<u8>> = deserialize(vec![1u8]);
    assert_eq!(zero, Ok(Box::new(0)));
    assert_eq!(one, Ok(Box::new(1)));
  }
}

