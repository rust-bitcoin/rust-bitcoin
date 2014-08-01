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
use std::io::{IoError, IoResult, OtherIoError, MemReader, MemWriter};

use network::encodable::{ConsensusDecodable, ConsensusEncodable};
use util::hash::Sha256dHash;

/// Objects which are referred to by hash
pub trait BitcoinHash {
  /// Produces a Sha256dHash which can be used to refer to the object
  fn bitcoin_hash(&self) -> Sha256dHash;
}

impl BitcoinHash for Vec<u8> {
  fn bitcoin_hash(&self) -> Sha256dHash {
    Sha256dHash::from_data(self.as_slice())
  }
}

/// Encode an object into a vector
pub fn serialize<T: ConsensusEncodable<RawEncoder<MemWriter>, IoError>>(obj: &T) -> IoResult<Vec<u8>> {
  let mut encoder = RawEncoder::new(MemWriter::new());
  try!(obj.consensus_encode(&mut encoder));
  Ok(encoder.unwrap().unwrap())
}

/// Deserialize an object from a vector
pub fn deserialize<T: ConsensusDecodable<RawDecoder<MemReader>, IoError>>(data: Vec<u8>) -> IoResult<T> {
  let mut decoder = RawDecoder::new(MemReader::new(data));
  ConsensusDecodable::consensus_decode(&mut decoder)
}

/// An encoder for raw binary data
pub struct RawEncoder<W> {
  writer: W
}

/// An decoder for raw binary data
pub struct RawDecoder<R> {
  reader: R
}

impl<W:Writer> RawEncoder<W> {
  /// Constructor
  pub fn new(writer: W) -> RawEncoder<W> {
    RawEncoder { writer: writer }
  }

  /// Returns the underlying Writer
  pub fn unwrap(self) -> W {
    self.writer
  }
}

impl<R:Reader> RawDecoder<R> {
  /// Constructor
  pub fn new(reader: R) -> RawDecoder<R> {
    RawDecoder { reader: reader }
  }

  /// Returns the underlying Reader
  pub fn unwrap(self) -> R {
    self.reader
  }
}

/// A simple Encoder trait
pub trait SimpleEncoder<E> {
  fn emit_u64(&mut self, v: u64) -> Result<(), E>;
  fn emit_u32(&mut self, v: u32) -> Result<(), E>;
  fn emit_u16(&mut self, v: u16) -> Result<(), E>;
  fn emit_u8(&mut self, v: u8) -> Result<(), E>;

  fn emit_i64(&mut self, v: i64) -> Result<(), E>;
  fn emit_i32(&mut self, v: i32) -> Result<(), E>;
  fn emit_i16(&mut self, v: i16) -> Result<(), E>;
  fn emit_i8(&mut self, v: i8) -> Result<(), E>;

  fn emit_bool(&mut self, v: bool) -> Result<(), E>;
}

/// A simple Decoder trait
pub trait SimpleDecoder<E> {
  fn read_u64(&mut self) -> Result<u64, E>;
  fn read_u32(&mut self) -> Result<u32, E>;
  fn read_u16(&mut self) -> Result<u16, E>;
  fn read_u8(&mut self) -> Result<u8, E>;

  fn read_i64(&mut self) -> Result<i64, E>;
  fn read_i32(&mut self) -> Result<i32, E>;
  fn read_i16(&mut self) -> Result<i16, E>;
  fn read_i8(&mut self) -> Result<i8, E>;

  fn read_bool(&mut self) -> Result<bool, E>;

  fn error(&mut self, err: &str) -> E;
}

// TODO: trait reform: impl SimpleEncoder for every Encoder, ditto for Decoder

impl<W:Writer> SimpleEncoder<IoError> for RawEncoder<W> {
  #[inline]
  fn emit_u64(&mut self, v: u64) -> IoResult<()> { self.writer.write_le_u64(v) }
  #[inline]
  fn emit_u32(&mut self, v: u32) -> IoResult<()> { self.writer.write_le_u32(v) }
  #[inline]
  fn emit_u16(&mut self, v: u16) -> IoResult<()> { self.writer.write_le_u16(v) }
  #[inline]
  fn emit_u8(&mut self, v: u8) -> IoResult<()> { self.writer.write_u8(v) }

  #[inline]
  fn emit_i64(&mut self, v: i64) -> IoResult<()> { self.writer.write_le_i64(v) }
  #[inline]
  fn emit_i32(&mut self, v: i32) -> IoResult<()> { self.writer.write_le_i32(v) }
  #[inline]
  fn emit_i16(&mut self, v: i16) -> IoResult<()> { self.writer.write_le_i16(v) }
  #[inline]
  fn emit_i8(&mut self, v: i8) -> IoResult<()> { self.writer.write_i8(v) }

  #[inline]
  fn emit_bool(&mut self, v: bool) -> IoResult<()> { self.writer.write_i8(if v {1} else {0}) }
}

impl<R:Reader> SimpleDecoder<IoError> for RawDecoder<R> {
  #[inline]
  fn read_u64(&mut self) -> IoResult<u64> { self.reader.read_le_u64() }
  #[inline]
  fn read_u32(&mut self) -> IoResult<u32> { self.reader.read_le_u32() }
  #[inline]
  fn read_u16(&mut self) -> IoResult<u16> { self.reader.read_le_u16() }
  #[inline]
  fn read_u8(&mut self) -> IoResult<u8> { self.reader.read_u8() }

  #[inline]
  fn read_i64(&mut self) -> IoResult<i64> { self.reader.read_le_i64() }
  #[inline]
  fn read_i32(&mut self) -> IoResult<i32> { self.reader.read_le_i32() }
  #[inline]
  fn read_i16(&mut self) -> IoResult<i16> { self.reader.read_le_i16() }
  #[inline]
  fn read_i8(&mut self) -> IoResult<i8> { self.reader.read_i8() }

  #[inline]
  fn read_bool(&mut self) -> IoResult<bool> { self.reader.read_u8().map(|res| res != 0) }

  #[inline]
  fn error(&mut self, err: &str) -> IoError {
    IoError {
      kind: OtherIoError,
      desc: "parse error",
      detail: Some(err.to_string())
    }
  }
}

// Aren't really any tests here.. the main functions are serialize and
// deserialize, which get the crap tested out of them it every other
// module.

