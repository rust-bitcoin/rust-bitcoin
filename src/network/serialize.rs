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

//! # Network Serialization
//!
//! This module defines the `Serializable` trait which is used for
//! (de)serializing Bitcoin objects for transmission on the network.
//! It also defines (de)serialization routines for many primitives.
//!

use collections::Vec;
use collections::bitv::{Bitv, from_bytes};
use std::io::{IoError, IoResult, InvalidInput, OtherIoError, standard_error};
use std::io::{BufferedReader, BufferedWriter, File, Truncate, Write};
use std::io::fs::rename;
use std::mem::transmute;
use std::u32;

use util::iter::{FixedTake, FixedTakeable, NullIterator};
use util::hash::Sha256dHash;
use util::thinvec::ThinVec;

/// An iterator which returns serialized data one byte at a time
pub struct SerializeIter<'a> {
  /// Iterator over actual data
  pub data_iter: Option<Box<Iterator<u8>>>,
  /// Objects which are serialized through their own `SerializeIter`s
  pub sub_iter_iter: Box<Iterator<&'a Serializable>>,
  /// Current subiterator
  pub sub_iter: Option<Box<SerializeIter<'a>>>,
  /// Whether we have started using sub_iter_iter
  pub sub_started: bool
} 

impl<'a> Iterator<u8> for SerializeIter<'a> {
  fn next(&mut self) -> Option<u8> { 
    let mut ret = None;
    // Try to use the data iterator
    if self.data_iter.is_some() {
      // Unwrap the current data iterator to use it
      let mut it = self.data_iter.take_unwrap();
      ret = it.next();
      // Delete the current data iterator if it's exhausted, by putting
      // it back only when it's -not- exhausted
      if ret.is_some() { self.data_iter = Some(it); }
    }
    // Failing that, start using the subobject iterator
    if ret.is_none() && !self.sub_started {
      // Unwrap the current data iterator to use it
      self.sub_started = true;
      self.sub_iter = self.sub_iter_iter.next().map(|obj| box obj.serialize_iter());
    }
    // If it doesn't work, find one that does
    while ret.is_none() && self.sub_iter.is_some() {
      let mut iter = self.sub_iter.take_unwrap();
      ret = iter.next();
      self.sub_iter = if ret.is_none() {
          self.sub_iter_iter.next().map(|obj| box obj.serialize_iter())
        } else {
          Some(iter)
        }
    }
    // Eventually we got Some(u8) --- or None and we're exhausted
    ret
  }
}

/// A string which must be encoded as 12 bytes, used in network message headers


#[deriving(PartialEq, Clone, Show)]
/// Data which must be preceded by a 4-byte checksum
pub struct CheckedData(pub Vec<u8>);

/// An object which can be (de)serialized. If the object can be sent on the
/// Bitcoin network, the serialization must be the standard p2p network
/// serialization.
pub trait Serializable {
  /// Turn an object into a bytestring that can be put on the wire
  fn serialize(&self) -> Vec<u8>;
  /// Serialize an object, returning an iterator rather than complete vector
  fn serialize_iter<'a>(&'a self) -> SerializeIter<'a> {
    SerializeIter {
      data_iter: Some(box self.serialize().move_iter() as Box<Iterator<u8>>),
      sub_iter_iter: box NullIterator::<&Serializable>::new(),
      sub_iter: None,
      sub_started: false
    }
  }
  /// Read an object off the wire
  fn deserialize<I: Iterator<u8>>(iter: I) -> IoResult<Self>;
  /// Obtain a hash of the object
  fn hash(&self) -> Sha256dHash {
    Sha256dHash::from_data(self.serialize().as_slice())
  }
  /// Dump the object to a file
  fn serialize_file(&self, p: &Path) -> IoResult<()> {
    let tmp_path = p.with_extension("0");
    {
      let file = File::open_mode(&tmp_path, Truncate, Write);
      let mut writer = BufferedWriter::new(file);
      for ch in self.serialize_iter() {
        try!(writer.write_u8(ch));
      }
      try!(writer.flush());
    }
    rename(&tmp_path, p)
  }
  /// Read the object from a file
  fn deserialize_file(p: &Path) -> IoResult<Self> {
    let file = try!(File::open(p));
    let mut reader = BufferedReader::new(file);
    let mut error: IoResult<u8> = Ok(0);
    // This is kinda a hacky way to catch file read errors
    let ret = Serializable::deserialize(reader.bytes().filter_map(|res| {
        if res.is_err() {
          error = res;
          None
        } else {
          res.ok()
        }
      }));
    // Return file error if there was one, else parse error
    match error {
      Ok(_) => ret,
      Err(e) => Err(e)
    }
  }
}

/// A variable-length unsigned integer
#[deriving(PartialEq, Show)]
pub enum VarInt {
  /// 8-bit int
  VarU8(u8),
  /// 16-bit int
  VarU16(u16),
  /// 32-bit int
  VarU32(u32),
  /// 64-bit int
  VarU64(u64)
}

// Utility functions
/// Convert a Rust uint to a Bitcoin network Varint
pub fn u64_to_varint(n: u64) -> VarInt {
  match n {
    n if n < 0xFD => VarU8(n as u8),
    n if n <= 0xFFFF => VarU16(n as u16),
    n if n <= 0xFFFFFFFF => VarU32(n as u32),
    n => VarU64(n)
  }
}

/// Convert a Bitcoin network Varint to a Rust uint
pub fn varint_to_u64(n: VarInt) -> u64 {
  match n {
    VarU8(m) => m as u64,
    VarU16(m) => m as u64,
    VarU32(m) => m as u64,
    VarU64(m) => m,
  }
}

fn read_uint_le<I: Iterator<u8>>(mut iter: FixedTake<I>) -> Option<u64> {
  let (rv, _) = iter.fold((0u64, 1u64), |(old, mult), next| (old + next as u64 * mult, mult * 0x100));
  match iter.is_err() {
    false => Some(rv),
    true => None
  }
}

/// Do a double-SHA256 on some data and return the first 4 bytes
fn sha2_checksum(data: &[u8]) -> u32 {
  let checksum = Sha256dHash::from_data(data);
  read_uint_le(checksum.as_slice().iter().map(|n| *n).fixed_take(4)).unwrap() as u32
}

/// Primitives
impl Serializable for bool {
  fn serialize(&self) -> Vec<u8> {
    if *self { Vec::from_slice(&[1u8]) } else { Vec::from_slice(&[0u8]) }
  }

  fn deserialize<I: Iterator<u8>>(mut iter: I) -> IoResult<bool> {
    match iter.next() {
      Some(u) => Ok(u != 0),
      None    => Err(standard_error(InvalidInput))
    }
  }
}

impl Serializable for u8 {
  fn serialize(&self) -> Vec<u8> {
    Vec::from_slice(&[*self])
  }

  fn deserialize<I: Iterator<u8>>(mut iter: I) -> IoResult<u8> {
    match iter.next() {
      Some(u) => Ok(u as u8),
      None    => Err(standard_error(InvalidInput))
    }
  }
}

impl Serializable for u16 {
  fn serialize(&self) -> Vec<u8> {
    unsafe { Vec::from_slice(transmute::<_, [u8, ..2]>(self.to_le())) }
  }

  fn deserialize<I: Iterator<u8>>(iter: I) -> IoResult<u16> {
    match read_uint_le(iter.fixed_take(2)) {
      Some(u) => Ok(u as u16),
      None    => Err(standard_error(InvalidInput))
    }
  }
}

impl Serializable for u32 {
  fn serialize(&self) -> Vec<u8> {
    unsafe { Vec::from_slice(transmute::<_, [u8, ..4]>(self.to_le())) }
  }

  fn deserialize<I: Iterator<u8>>(iter: I) -> IoResult<u32> {
    match read_uint_le(iter.fixed_take(4)) {
      Some(u) => Ok(u as u32),
      None    => Err(standard_error(InvalidInput))
    }
  }
}

impl Serializable for i32 {
  fn serialize(&self) -> Vec<u8> {
    unsafe { Vec::from_slice(transmute::<_, [u8, ..4]>(self.to_le())) }
  }

  fn deserialize<I: Iterator<u8>>(iter: I) -> IoResult<i32> {
    match read_uint_le(iter.fixed_take(4)) {
      Some(u) => Ok(u as i32),
      None    => Err(standard_error(InvalidInput))
    }
  }
}

impl Serializable for u64 {
  fn serialize(&self) -> Vec<u8> {
    unsafe { Vec::from_slice(transmute::<_, [u8, ..8]>(self.to_le())) }
  }

  fn deserialize<I: Iterator<u8>>(iter: I) -> IoResult<u64> {
    match read_uint_le(iter.fixed_take(8)) {
      Some(u) => Ok(u as u64),
      None    => Err(standard_error(InvalidInput))
    }
  }
}

impl Serializable for i64 {
  fn serialize(&self) -> Vec<u8> {
    unsafe { Vec::from_slice(transmute::<_, [u8, ..8]>(self.to_le())) }
  }

  fn deserialize<I: Iterator<u8>>(iter: I) -> IoResult<i64> {
    match read_uint_le(iter.fixed_take(8)) {
      Some(u) => Ok(u as i64),
      None    => Err(standard_error(InvalidInput))
    }
  }
}

impl Serializable for VarInt {
  fn serialize(&self) -> Vec<u8> {
    match *self {
      VarU8(n)  => Vec::from_slice(&[n]),
      VarU16(n) => { let mut rv = n.serialize(); rv.unshift(0xFD); rv },
      VarU32(n) => { let mut rv = n.serialize(); rv.unshift(0xFE); rv },
      VarU64(n) => { let mut rv = n.serialize(); rv.unshift(0xFF); rv },
    }
  }

  fn deserialize<I: Iterator<u8>>(mut iter: I) -> IoResult<VarInt> {
    match iter.next() {
      Some(n) if n < 0xFD => Ok(VarU8(n)),
      Some(n) if n == 0xFD => Ok(VarU16(try!(Serializable::deserialize(iter)))),
      Some(n) if n == 0xFE => Ok(VarU32(try!(Serializable::deserialize(iter)))),
      Some(n) if n == 0xFF => Ok(VarU64(try!(Serializable::deserialize(iter)))),
      _ => Err(standard_error(InvalidInput))
    }
  }
}

macro_rules! serialize_fixvec(
  ($($size:expr),+) => (
    $(
      impl Serializable for [u8, ..$size] {
        fn serialize(&self) -> Vec<u8> {
          Vec::from_slice(self.as_slice())
        }

        fn deserialize<I: Iterator<u8>>(iter: I) -> IoResult<[u8, ..$size]> {
          let mut v = [0u8, ..$size];
          let mut fixiter = iter.fixed_take($size);
          let mut n = 0;
          for ch in fixiter {
            v[n] = ch;
            n += 1;
          }
          match fixiter.is_err() {
            false => Ok(v),
            true => Err(standard_error(InvalidInput))
          }
        }
      }
    )+

    #[test]
    fn test_fixvec() {
      $(
        let vec = [5u8, ..$size];
        let short_vec = [5u8, ..($size - 1)];
        assert_eq!(vec.as_slice(), vec.serialize().as_slice());

        let decode: IoResult<[u8, ..$size]> = Serializable::deserialize(vec.iter().map(|n| *n));
        let short_decode: IoResult<[u8, ..$size]> = Serializable::deserialize(short_vec.iter().map(|n| *n));

        assert!(decode.is_ok());
        assert!(short_decode.is_err());
        assert_eq!(decode.unwrap().as_slice(), vec.as_slice());
      )+
    }
  );
)
// we need to do this in one call so that we can do a test for
// every value; we can't define a new test fn for each invocation
// because there are no gensyms.
serialize_fixvec!(4, 8, 12, 16, 32)

impl Serializable for CheckedData {
  fn serialize(&self) -> Vec<u8> {
    let &CheckedData(ref data) = self;
    let mut ret = (data.len() as u32).serialize();
    ret.extend(sha2_checksum(data.as_slice()).serialize().move_iter());
    ret.extend(data.iter().map(|n| *n));
    ret
  }

  fn deserialize<I: Iterator<u8>>(mut iter: I) -> IoResult<CheckedData> {
    let length: u32 = try!(Serializable::deserialize(iter.by_ref()));
    let checksum: u32 = try!(Serializable::deserialize(iter.by_ref()));

    let mut fixiter = iter.fixed_take(length as uint);
    let v: Vec<u8> =  FromIterator::from_iter(fixiter.by_ref());
    if fixiter.is_err() {
      return Err(IoError {
        kind: InvalidInput,
        desc: "overrun",
        detail: Some(format!("data length given as {:}, but read fewer bytes", length))
      });
    }

    let expected_checksum = sha2_checksum(v.as_slice());
    if checksum == expected_checksum {
      Ok(CheckedData(v))
    } else {
      Err(IoError {
        kind: OtherIoError,
        desc: "bad checksum",
        detail: Some(format!("checksum {:4x} did not match expected {:4x}", checksum, expected_checksum)),
      })
    }
  }
}

impl Serializable for String {
  fn serialize(&self) -> Vec<u8> {
    let mut rv = u64_to_varint(self.len() as u64).serialize();
    rv.push_all(self.as_bytes());
    rv
  }

  fn deserialize<I: Iterator<u8>>(mut iter: I) -> IoResult<String> {
    let length: VarInt = try!(Serializable::deserialize(iter.by_ref()));
    let mut fixiter = iter.fixed_take(varint_to_u64(length) as uint);
    let rv: String = FromIterator::from_iter(fixiter.by_ref().map(|u| u as char));
    match fixiter.is_err() {
      false => Ok(rv),
      true => Err(standard_error(InvalidInput))
    }
  }
}

impl<T: Serializable> Serializable for Vec<T> {
  fn serialize(&self) -> Vec<u8> {
    let n_elems = u64_to_varint(self.len() as u64);
    let mut rv = n_elems.serialize();
    for elem in self.iter() {
      rv.extend(elem.serialize().move_iter());
    }
    rv
  }

  fn deserialize<I: Iterator<u8>>(mut iter: I) -> IoResult<Vec<T>> {
    let mut n_elems = varint_to_u64(try!(Serializable::deserialize(iter.by_ref())));
    let mut v: Vec<T> = vec![];
    while n_elems > 0 {
      v.push(try!(Serializable::deserialize(iter.by_ref())));
      n_elems -= 1;
    }
    Ok(v)
  }
}

impl<T: Serializable> Serializable for ThinVec<T> {
  fn serialize(&self) -> Vec<u8> {
    let n_elems = u64_to_varint(self.len() as u64);
    let mut rv = n_elems.serialize();
    for elem in self.iter() {
      rv.extend(elem.serialize().move_iter());
    }
    rv
  }

  fn deserialize<I: Iterator<u8>>(mut iter: I) -> IoResult<ThinVec<T>> {
    let n_elems = varint_to_u64(try!(Serializable::deserialize(iter.by_ref())));
    assert!(n_elems < u32::MAX as u64);

    let mut v: ThinVec<T> = ThinVec::with_capacity(n_elems as u32);
    for i in range(0, n_elems) {
      unsafe {
        v.init(i as uint, try!(Serializable::deserialize(iter.by_ref())));
      };
    }
    Ok(v)
  }
}

impl<T:Serializable, U:Serializable> Serializable for (T, U) {
  fn serialize(&self) -> Vec<u8> {
    let &(ref self1, ref self2) = self;
    let mut ret = vec![];
    ret.extend(self1.serialize().move_iter());
    ret.extend(self2.serialize().move_iter());
    ret
  }

  fn deserialize<I: Iterator<u8>>(mut iter: I) -> IoResult<(T, U)> {
    Ok((try!(Serializable::deserialize(iter.by_ref())),
        try!(Serializable::deserialize(iter.by_ref()))))
  }
}

impl<T:Serializable+'static> Serializable for Option<T> {
  fn serialize(&self) -> Vec<u8> {
    match self {
      &Some(ref dat) => {
        let mut ret = vec![1];
        ret.extend(dat.serialize().move_iter());
        ret
      },
      &None => vec![0]
    }
  }

  fn serialize_iter<'a>(&'a self) -> SerializeIter<'a> {
    match self {
      &Some(ref dat) => SerializeIter {
        data_iter: Some(box Some(1u8).move_iter() as Box<Iterator<u8>>),
        sub_iter_iter: box vec![ dat as &Serializable ].move_iter(),
        sub_iter: None,
        sub_started: false
      },
      &None => SerializeIter {
        data_iter: Some(box Some(0u8).move_iter() as Box<Iterator<u8>>),
        sub_iter_iter: box NullIterator::<&Serializable>::new(),
        sub_iter: None,
        sub_started: false
      }
    }
  }

  fn deserialize<I: Iterator<u8>>(mut iter: I) -> IoResult<Option<T>> {
    match iter.next() {
      Some(0) => Ok(None),
      Some(1) => Ok(Some(try!(Serializable::deserialize(iter)))),
      _ => Err(standard_error(InvalidInput))
    }
  }
}

impl <T:Serializable> Serializable for Box<T> {
  fn serialize(&self) -> Vec<u8> {
    (**self).serialize()
  }

  fn serialize_iter<'a>(&'a self) -> SerializeIter<'a> {
    (**self).serialize_iter()
  }

  fn deserialize<I: Iterator<u8>>(iter: I) -> IoResult<Box<T>> {
    let ret: T = try!(Serializable::deserialize(iter));
    Ok(box ret)
  }
}

impl Serializable for Bitv {
  fn serialize(&self) -> Vec<u8> {
    let n_elems = u64_to_varint(self.len() as u64);
    let mut rv = n_elems.serialize();
    for elem in self.to_bytes().iter() {
      rv.extend(elem.serialize().move_iter());
    }
    rv
  }

  fn deserialize<I: Iterator<u8>>(mut iter: I) -> IoResult<Bitv> {
    let n_elems = varint_to_u64(try!(Serializable::deserialize(iter.by_ref())));
    let mut v: Vec<u8> = vec![];
    for _ in range(0, (n_elems + 7) / 8) {
      v.push(try!(Serializable::deserialize(iter.by_ref())));
    }
    let mut ret = from_bytes(v.as_slice());
    ret.truncate(n_elems as uint);  // from_bytes will round up to 8
    Ok(ret)
  }
}

#[test]
fn serialize_iter_test() {
  assert_eq!(true.serialize(), true.serialize_iter().collect());
  assert_eq!(1u8.serialize(), 1u8.serialize_iter().collect());
  assert_eq!(300u32.serialize(), 300u32.serialize_iter().collect());
  assert_eq!(20u64.serialize(), 20u64.serialize_iter().collect());
}

#[test]
fn serialize_int_test() {
  // bool
  assert_eq!(false.serialize(), Vec::from_slice([0u8]));
  assert_eq!(true.serialize(), Vec::from_slice([1u8]));
  // u8
  assert_eq!(1u8.serialize(), Vec::from_slice([1u8]));
  assert_eq!(0u8.serialize(), Vec::from_slice([0u8]));
  assert_eq!(255u8.serialize(), Vec::from_slice([255u8]));
  // u16
  assert_eq!(1u16.serialize(), Vec::from_slice([1u8, 0]));
  assert_eq!(256u16.serialize(), Vec::from_slice([0u8, 1]));
  assert_eq!(5000u16.serialize(), Vec::from_slice([136u8, 19]));
  // u32
  assert_eq!(1u32.serialize(), Vec::from_slice([1u8, 0, 0, 0]));
  assert_eq!(256u32.serialize(), Vec::from_slice([0u8, 1, 0, 0]));
  assert_eq!(5000u32.serialize(), Vec::from_slice([136u8, 19, 0, 0]));
  assert_eq!(500000u32.serialize(), Vec::from_slice([32u8, 161, 7, 0]));
  assert_eq!(168430090u32.serialize(), Vec::from_slice([10u8, 10, 10, 10]));
  // TODO: test negative numbers
  assert_eq!(1i32.serialize(), Vec::from_slice([1u8, 0, 0, 0]));
  assert_eq!(256i32.serialize(), Vec::from_slice([0u8, 1, 0, 0]));
  assert_eq!(5000i32.serialize(), Vec::from_slice([136u8, 19, 0, 0]));
  assert_eq!(500000i32.serialize(), Vec::from_slice([32u8, 161, 7, 0]));
  assert_eq!(168430090i32.serialize(), Vec::from_slice([10u8, 10, 10, 10]));
  // u64
  assert_eq!(1u64.serialize(), Vec::from_slice([1u8, 0, 0, 0, 0, 0, 0, 0]));
  assert_eq!(256u64.serialize(), Vec::from_slice([0u8, 1, 0, 0, 0, 0, 0, 0]));
  assert_eq!(5000u64.serialize(), Vec::from_slice([136u8, 19, 0, 0, 0, 0, 0, 0]));
  assert_eq!(500000u64.serialize(), Vec::from_slice([32u8, 161, 7, 0, 0, 0, 0, 0]));
  assert_eq!(723401728380766730u64.serialize(), Vec::from_slice([10u8, 10, 10, 10, 10, 10, 10, 10]));
  // TODO: test negative numbers
  assert_eq!(1i64.serialize(), Vec::from_slice([1u8, 0, 0, 0, 0, 0, 0, 0]));
  assert_eq!(256i64.serialize(), Vec::from_slice([0u8, 1, 0, 0, 0, 0, 0, 0]));
  assert_eq!(5000i64.serialize(), Vec::from_slice([136u8, 19, 0, 0, 0, 0, 0, 0]));
  assert_eq!(500000i64.serialize(), Vec::from_slice([32u8, 161, 7, 0, 0, 0, 0, 0]));
  assert_eq!(723401728380766730i64.serialize(), Vec::from_slice([10u8, 10, 10, 10, 10, 10, 10, 10]));
}

#[test]
fn serialize_varint_test() {
  assert_eq!(VarU8(10).serialize(), Vec::from_slice([10u8]));
  assert_eq!(VarU8(0xFC).serialize(), Vec::from_slice([0xFCu8]));
  assert_eq!(VarU16(0xFD).serialize(), Vec::from_slice([0xFDu8, 0xFD, 0]));
  assert_eq!(VarU16(0xFFF).serialize(), Vec::from_slice([0xFDu8, 0xFF, 0xF]));
  assert_eq!(VarU32(0xF0F0F0F).serialize(), Vec::from_slice([0xFEu8, 0xF, 0xF, 0xF, 0xF]));
  assert_eq!(VarU64(0xF0F0F0F0F0E0).serialize(), Vec::from_slice([0xFFu8, 0xE0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0, 0]));
}

#[test]
fn serialize_vector_test() {
  assert_eq!(Vec::from_slice([1u8, 2, 3]).serialize(), Vec::from_slice([3u8, 1, 2, 3]));
  // TODO: test vectors of more interesting objects
}

#[test]
fn serialize_strbuf_test() {
  assert_eq!(String::from_str("Andrew").serialize(), Vec::from_slice([6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]));
}

#[test]
fn serialize_checkeddata_test() {
  let cd = CheckedData(vec![1u8, 2, 3, 4, 5]);
  assert_eq!(cd.serialize(), vec![5, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5]);
}

#[test]
fn serialize_box_test() {
  assert_eq!((box 1u8).serialize(), vec![1u8]);
  assert_eq!((box 1u16).serialize(), vec![1u8, 0]);
  assert_eq!((box 1u64).serialize(), vec![1u8, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn serialize_option_test() {
  let none: Option<u8> = None;
  let none_ser = none.serialize();
  let some_ser = Some(0xFFu8).serialize();
  assert_eq!(none_ser, vec![0]);
  assert_eq!(some_ser, vec![1, 0xFF]);

  assert_eq!(none.serialize(), none.serialize_iter().collect());
  assert_eq!(Some(true).serialize(), Some(true).serialize_iter().collect());
}

#[test]
fn serialize_bitv_test() {
  let bv = Bitv::with_capacity(10, true);
  assert_eq!(bv.serialize(), vec![10, 0xFF, 0xC0]);
  assert_eq!(bv.serialize(), bv.serialize_iter().collect());
}

#[test]
fn deserialize_int_test() {
  // bool
  assert_eq!(Serializable::deserialize([58u8, 0].iter().map(|n| *n)), Ok(true));
  assert_eq!(Serializable::deserialize([58u8].iter().map(|n| *n)), Ok(true));
  assert_eq!(Serializable::deserialize([1u8].iter().map(|n| *n)), Ok(true));
  assert_eq!(Serializable::deserialize([0u8].iter().map(|n| *n)), Ok(false));
  assert_eq!(Serializable::deserialize([0u8, 1].iter().map(|n| *n)), Ok(false));

  // u8
  assert_eq!(Serializable::deserialize([58u8].iter().map(|n| *n)), Ok(58u8));

  // u16
  assert_eq!(Serializable::deserialize([0x01u8, 0x02].iter().map(|n| *n)), Ok(0x0201u16));
  assert_eq!(Serializable::deserialize([0xABu8, 0xCD].iter().map(|n| *n)), Ok(0xCDABu16));
  assert_eq!(Serializable::deserialize([0xA0u8, 0x0D].iter().map(|n| *n)), Ok(0xDA0u16));
  let failure16: IoResult<u16> = Serializable::deserialize([1u8].iter().map(|n| *n));
  assert!(failure16.is_err());

  // u32
  assert_eq!(Serializable::deserialize([0xABu8, 0xCD, 0, 0].iter().map(|n| *n)), Ok(0xCDABu32));
  assert_eq!(Serializable::deserialize([0xA0u8, 0x0D, 0xAB, 0xCD].iter().map(|n| *n)), Ok(0xCDAB0DA0u32));
  let failure32: IoResult<u32> = Serializable::deserialize([1u8, 2, 3].iter().map(|n| *n));
  assert!(failure32.is_err());
  // TODO: test negative numbers
  assert_eq!(Serializable::deserialize([0xABu8, 0xCD, 0, 0].iter().map(|n| *n)), Ok(0xCDABi32));
  assert_eq!(Serializable::deserialize([0xA0u8, 0x0D, 0xAB, 0x2D].iter().map(|n| *n)), Ok(0x2DAB0DA0i32));
  let failurei32: IoResult<i32> = Serializable::deserialize([1u8, 2, 3].iter().map(|n| *n));
  assert!(failurei32.is_err());

  // u64
  assert_eq!(Serializable::deserialize([0xABu8, 0xCD, 0, 0, 0, 0, 0, 0].iter().map(|n| *n)), Ok(0xCDABu64));
  assert_eq!(Serializable::deserialize([0xA0u8, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99].iter().map(|n| *n)), Ok(0x99000099CDAB0DA0u64));
  let failure64: IoResult<u64> = Serializable::deserialize([1u8, 2, 3, 4, 5, 6, 7].iter().map(|n| *n));
  assert!(failure64.is_err());
  // TODO: test negative numbers
  assert_eq!(Serializable::deserialize([0xABu8, 0xCD, 0, 0, 0, 0, 0, 0].iter().map(|n| *n)), Ok(0xCDABi64));
  assert_eq!(Serializable::deserialize([0xA0u8, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99].iter().map(|n| *n)), Ok(0x99000099CDAB0DA0i64));
  let failurei64: IoResult<i64> = Serializable::deserialize([1u8, 2, 3, 4, 5, 6, 7].iter().map(|n| *n));
  assert!(failurei64.is_err());
}

#[test]
fn deserialize_vec_test() {
  assert_eq!(Serializable::deserialize([3u8, 2, 3, 4].iter().map(|n| *n)), Ok(vec![2u8, 3, 4]));
  assert_eq!(Serializable::deserialize([4u8, 2, 3, 4, 5, 6].iter().map(|n| *n)), Ok(vec![2u8, 3, 4, 5]));
}

#[test]
fn deserialize_strbuf_test() {
  assert_eq!(Serializable::deserialize([6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77].iter().map(|n| *n)), Ok(String::from_str("Andrew")));
}

#[test]
fn deserialize_checkeddata_test() {
  let cd: IoResult<CheckedData> = Serializable::deserialize([5u8, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5].iter().map(|n| *n));
  assert!(cd.is_ok());
  assert_eq!(cd.unwrap(), CheckedData(Vec::from_slice([1u8, 2, 3, 4, 5])));
}

#[test]
fn deserialize_option_test() {
  let none: IoResult<Option<u8>> = Serializable::deserialize([0u8].iter().map(|n| *n));
  let good: IoResult<Option<u8>> = Serializable::deserialize([1u8, 0xFF].iter().map(|n| *n));
  let bad: IoResult<Option<u8>> = Serializable::deserialize([2u8].iter().map(|n| *n));
  assert!(bad.is_err());
  assert_eq!(none, Ok(None));
  assert_eq!(good, Ok(Some(0xFF)));
}

#[test]
fn deserialize_box_test() {
  let zero: IoResult<Box<u8>> = Serializable::deserialize([0u8].iter().map(|n| *n));
  let one: IoResult<Box<u8>> = Serializable::deserialize([1u8].iter().map(|n| *n));
  assert_eq!(zero, Ok(box 0));
  assert_eq!(one, Ok(box 1));
}

#[test]
fn deserialize_bitv_test() {
  let bv: IoResult<Bitv> = Serializable::deserialize([10u8, 0xFF, 0xC0].iter().map(|n| *n));
  assert!(bv.is_ok());
  assert_eq!(bv.unwrap(), Bitv::with_capacity(10, true));
}

