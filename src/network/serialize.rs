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

use std::io::{Cursor, Read, Write};
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt};
use serialize::hex::ToHex;

use network::encodable::{ConsensusDecodable, ConsensusEncodable};
use util::hash::Sha256dHash;
use util;

/// Objects which are referred to by hash
pub trait BitcoinHash {
    /// Produces a Sha256dHash which can be used to refer to the object
    fn bitcoin_hash(&self) -> Sha256dHash;
}

impl BitcoinHash for Vec<u8> {
    #[inline]
    fn bitcoin_hash(&self) -> Sha256dHash {
        Sha256dHash::from_data(&self[..])
    }
}

/// Encode an object into a vector
pub fn serialize<T: ?Sized>(data: &T) -> Result<Vec<u8>, util::Error>
     where T: ConsensusEncodable<RawEncoder<Cursor<Vec<u8>>>>,
{
    let mut encoder = RawEncoder::new(Cursor::new(vec![]));
    try!(data.consensus_encode(&mut encoder));
    Ok(encoder.into_inner().into_inner())
}

/// Encode an object into a hex-encoded string
pub fn serialize_hex<T: ?Sized>(data: &T) -> Result<String, util::Error>
     where T: ConsensusEncodable<RawEncoder<Cursor<Vec<u8>>>>
{
    let serial = try!(serialize(data));
    Ok(serial.to_hex())
}

/// Deserialize an object from a vector
pub fn deserialize<'a, T>(data: &'a [u8]) -> Result<T, util::Error>
     where T: ConsensusDecodable<RawDecoder<Cursor<&'a [u8]>>>
{
    let mut decoder = RawDecoder::new(Cursor::new(data));
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

impl<W: Write> RawEncoder<W> {
    /// Constructor
    pub fn new(writer: W) -> RawEncoder<W> { RawEncoder { writer: writer } }
    /// Returns the underlying Writer
    pub fn into_inner(self) -> W { self.writer }
}

impl<R: Read> RawDecoder<R> {
  /// Constructor
  pub fn new(reader: R) -> RawDecoder<R> { RawDecoder { reader: reader } }
  /// Returns the underlying Reader
  pub fn into_inner(self) -> R { self.reader }
}

/// A simple Encoder trait
pub trait SimpleEncoder {
    /// An encoding error
    type Error;
 
    /// Output a 64-bit uint
    fn emit_u64(&mut self, v: u64) -> Result<(), Self::Error>;
    /// Output a 32-bit uint
    fn emit_u32(&mut self, v: u32) -> Result<(), Self::Error>;
    /// Output a 16-bit uint
    fn emit_u16(&mut self, v: u16) -> Result<(), Self::Error>;
    /// Output a 8-bit uint
    fn emit_u8(&mut self, v: u8) -> Result<(), Self::Error>;

    /// Output a 64-bit int
    fn emit_i64(&mut self, v: i64) -> Result<(), Self::Error>;
    /// Output a 32-bit int
    fn emit_i32(&mut self, v: i32) -> Result<(), Self::Error>;
    /// Output a 16-bit int
    fn emit_i16(&mut self, v: i16) -> Result<(), Self::Error>;
    /// Output a 8-bit int
    fn emit_i8(&mut self, v: i8) -> Result<(), Self::Error>;

    /// Output a boolean
    fn emit_bool(&mut self, v: bool) -> Result<(), Self::Error>;
}

/// A simple Decoder trait
pub trait SimpleDecoder {
    /// A decoding error
    type Error;

    /// Read a 64-bit uint
    fn read_u64(&mut self) -> Result<u64, Self::Error>;
    /// Read a 32-bit uint
    fn read_u32(&mut self) -> Result<u32, Self::Error>;
    /// Read a 16-bit uint
    fn read_u16(&mut self) -> Result<u16, Self::Error>;
    /// Read a 8-bit uint
    fn read_u8(&mut self) -> Result<u8, Self::Error>;

    /// Read a 64-bit int
    fn read_i64(&mut self) -> Result<i64, Self::Error>;
    /// Read a 32-bit int
    fn read_i32(&mut self) -> Result<i32, Self::Error>;
    /// Read a 16-bit int
    fn read_i16(&mut self) -> Result<i16, Self::Error>;
    /// Read a 8-bit int
    fn read_i8(&mut self) -> Result<i8, Self::Error>;

    /// Read a boolean
    fn read_bool(&mut self) -> Result<bool, Self::Error>;

    /// Signal a decoding error
    fn error(&mut self, err: String) -> Self::Error;
}

macro_rules! encoder_fn {
    ($name:ident, $val_type:ty, $writefn:ident) => {
        #[inline]
        fn $name(&mut self, v: $val_type) -> Result<(), util::Error> {
            self.writer.$writefn::<LittleEndian>(v).map_err(util::Error::ByteOrder)
        }
    }
}

macro_rules! decoder_fn {
    ($name:ident, $val_type:ty, $readfn:ident) => {
        #[inline]
        fn $name(&mut self) -> Result<$val_type, util::Error> {
            self.reader.$readfn::<LittleEndian>().map_err(util::Error::ByteOrder)
        }
    }
}

impl<W: Write> SimpleEncoder for RawEncoder<W> {
    type Error = util::Error;

    encoder_fn!(emit_u64, u64, write_u64);
    encoder_fn!(emit_u32, u32, write_u32);
    encoder_fn!(emit_u16, u16, write_u16);
    encoder_fn!(emit_i64, i64, write_i64);
    encoder_fn!(emit_i32, i32, write_i32);
    encoder_fn!(emit_i16, i16, write_i16);

    #[inline]
    fn emit_i8(&mut self, v: i8) -> Result<(), util::Error> {
        self.writer.write_i8(v).map_err(util::Error::ByteOrder)
    }
    #[inline]
    fn emit_u8(&mut self, v: u8) -> Result<(), util::Error> {
        self.writer.write_u8(v).map_err(util::Error::ByteOrder)
    }
    #[inline]
    fn emit_bool(&mut self, v: bool) -> Result<(), util::Error> {
        self.writer.write_i8(if v {1} else {0}).map_err(util::Error::ByteOrder)
    }
}

impl<R: Read> SimpleDecoder for RawDecoder<R> {
    type Error = util::Error;

    decoder_fn!(read_u64, u64, read_u64);
    decoder_fn!(read_u32, u32, read_u32);
    decoder_fn!(read_u16, u16, read_u16);
    decoder_fn!(read_i64, i64, read_i64);
    decoder_fn!(read_i32, i32, read_i32);
    decoder_fn!(read_i16, i16, read_i16);

    #[inline]
    fn read_u8(&mut self) -> Result<u8, util::Error> {
        self.reader.read_u8().map_err(util::Error::ByteOrder)
    }
    #[inline]
    fn read_i8(&mut self) -> Result<i8, util::Error> {
        self.reader.read_i8().map_err(util::Error::ByteOrder)
    }
    #[inline]
    fn read_bool(&mut self) -> Result<bool, util::Error> {
        match self.reader.read_i8() {
            Ok(bit) => Ok(bit != 0),
            Err(e) => Err(util::Error::ByteOrder(e))
        }
    }

    #[inline]
    fn error(&mut self, err: String) -> util::Error {
        util::Error::Detail(err, Box::new(util::Error::ParseFailed))
    }
}

// Aren't really any tests here.. the main functions are serialize and
// deserialize, which get the crap tested out of them it every other
// module.

