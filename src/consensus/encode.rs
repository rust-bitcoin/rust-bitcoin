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

//! Consensus-encodable types
//!
//! This is basically a replacement of the `Encodable` trait which does
//! normalization for endianness, etc., to ensure that the encoding
//! matches for endianness, etc., to ensure that the encoding matches
//! the network consensus encoding.
//!
//! Essentially, anything that must go on the -disk- or -network- must
//! be encoded using the `Encodable` trait, since this data
//! must be the same for all systems. Any data going to the -user-, e.g.
//! over JSONRPC, should use the ordinary `Encodable` trait. (This
//! should also be the same across systems, of course, but has some
//! critical differences from the network format, e.g. scripts come
//! with an opcode decode, hashes are big-endian, numbers are typically
//! big-endian decimals, etc.)
//!

use std::collections::HashMap;
use std::hash::Hash;
use std::{mem, u32};

use std::error;
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt};
use hex::encode as hex_encode;

use bitcoin_bech32;
use bitcoin_hashes::{sha256d, Hash as HashTrait};
use secp256k1;

use util::base58;

/// Encoding error
#[derive(Debug)]
pub enum Error {
    /// And I/O error
    Io(io::Error),
    /// Base58 encoding error
    Base58(base58::Error),
    /// Bech32 encoding error
    Bech32(bitcoin_bech32::Error),
    /// Error from the `byteorder` crate
    ByteOrder(io::Error),
    /// secp-related error
    Secp256k1(secp256k1::Error),
    /// Network magic was not expected
    UnexpectedNetworkMagic {
        /// The expected network magic
        expected: u32,
        /// The unexpected network magic
        actual: u32,
    },
    /// Tried to allocate an oversized vector
    OversizedVectorAllocation{
        /// The capacity requested
        requested: usize,
        /// The maximum capacity
        max: usize,
    },
    /// Checksum was invalid
    InvalidChecksum {
        /// The expected checksum
        expected: [u8; 4],
        /// The invalid checksum
        actual: [u8; 4],
    },
    /// Network magic was unknown
    UnknownNetworkMagic(u32),
    /// Parsing error
    ParseFailed(&'static str),
    /// Unsupported witness version
    UnsupportedWitnessVersion(u8),
    /// Unsupported Segwit flag
    UnsupportedSegwitFlag(u8),
    /// Unrecognized network command
    UnrecognizedNetworkCommand(String),
    /// Unexpected hex digit
    UnexpectedHexDigit(char),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => fmt::Display::fmt(e, f),
            Error::Base58(ref e) => fmt::Display::fmt(e, f),
            Error::Bech32(ref e) => fmt::Display::fmt(e, f),
            Error::ByteOrder(ref e) => fmt::Display::fmt(e, f),
            Error::Secp256k1(ref e) => fmt::Display::fmt(e, f),
            Error::UnexpectedNetworkMagic { expected: ref e, actual: ref a } => write!(f, "{}: expected {}, actual {}", error::Error::description(self), e, a),
            Error::OversizedVectorAllocation { requested: ref r, max: ref m } => write!(f, "{}: requested {}, maximum {}", error::Error::description(self), r, m),
            Error::InvalidChecksum { expected: ref e, actual: ref a } => write!(f, "{}: expected {}, actual {}", error::Error::description(self), hex_encode(e), hex_encode(a)),
            Error::UnknownNetworkMagic(ref m) => write!(f, "{}: {}", error::Error::description(self), m),
            Error::ParseFailed(ref e) => write!(f, "{}: {}", error::Error::description(self), e),
            Error::UnsupportedWitnessVersion(ref wver) => write!(f, "{}: {}", error::Error::description(self), wver),
            Error::UnsupportedSegwitFlag(ref swflag) => write!(f, "{}: {}", error::Error::description(self), swflag),
            Error::UnrecognizedNetworkCommand(ref nwcmd) => write!(f, "{}: {}", error::Error::description(self), nwcmd),
            Error::UnexpectedHexDigit(ref d) => write!(f, "{}: {}", error::Error::description(self), d),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Io(ref e) => Some(e),
            Error::Base58(ref e) => Some(e),
            Error::Bech32(ref e) => Some(e),
            Error::ByteOrder(ref e) => Some(e),
            Error::Secp256k1(ref e) => Some(e),
            Error::UnexpectedNetworkMagic { .. }
            | Error::OversizedVectorAllocation { .. }
            | Error::InvalidChecksum { .. }
            | Error::UnknownNetworkMagic(..)
            | Error::ParseFailed(..)
            | Error::UnsupportedWitnessVersion(..)
            | Error::UnsupportedSegwitFlag(..)
            | Error::UnrecognizedNetworkCommand(..)
            | Error::UnexpectedHexDigit(..) => None,
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::Io(ref e) => e.description(),
            Error::Base58(ref e) => e.description(),
            Error::Bech32(ref e) => e.description(),
            Error::ByteOrder(ref e) => e.description(),
            Error::Secp256k1(ref e) => e.description(),
            Error::UnexpectedNetworkMagic { .. } => "unexpected network magic",
            Error::OversizedVectorAllocation { .. } => "allocation of oversized vector requested",
            Error::InvalidChecksum { .. } => "invalid checksum",
            Error::UnknownNetworkMagic(..) => "unknown network magic",
            Error::ParseFailed(..) => "parse failed",
            Error::UnsupportedWitnessVersion(..) => "unsupported witness version",
            Error::UnsupportedSegwitFlag(..) => "unsupported segwit version",
            Error::UnrecognizedNetworkCommand(..) => "unrecognized network command",
            Error::UnexpectedHexDigit(..) => "unexpected hex digit",
        }
    }
}

#[doc(hidden)]
impl From<base58::Error> for Error {
    fn from(e: base58::Error) -> Error {
        Error::Base58(e)
    }
}

#[doc(hidden)]
impl From<bitcoin_bech32::Error> for Error {
    fn from(e: bitcoin_bech32::Error) -> Error {
        Error::Bech32(e)
    }
}

#[doc(hidden)]
impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Secp256k1(e)
    }
}

#[doc(hidden)]
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

/// Encode an object into a vector
pub fn serialize<T: ?Sized>(data: &T) -> Vec<u8>
     where T: Encodable<Cursor<Vec<u8>>>,
{
    let mut encoder = Cursor::new(vec![]);
    data.consensus_encode(&mut encoder).unwrap();
    encoder.into_inner()
}

/// Encode an object into a hex-encoded string
pub fn serialize_hex<T: ?Sized>(data: &T) -> String
     where T: Encodable<Cursor<Vec<u8>>>
{
    hex_encode(serialize(data))
}

/// Deserialize an object from a vector, will error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize<'a, T>(data: &'a [u8]) -> Result<T, Error>
     where T: Decodable<Cursor<&'a [u8]>>
{
    let (rv, consumed) = deserialize_partial(data)?;

    // Fail if data are not consumed entirely.
    if consumed == data.len() {
        Ok(rv)
    } else {
        Err(Error::ParseFailed("data not consumed entirely when explicitly deserializing"))
    }
}

/// Deserialize an object from a vector, but will not report an error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize_partial<'a, T>(data: &'a [u8]) -> Result<(T, usize), Error>
    where T: Decodable<Cursor<&'a [u8]>>
{
    let mut decoder = Cursor::new(data);
    let rv = Decodable::consensus_decode(&mut decoder)?;
    let consumed = decoder.position() as usize;

    Ok((rv, consumed))
}


/// A simple Encoder trait
pub trait Encoder {
    /// Output a 64-bit uint
    fn emit_u64(&mut self, v: u64) -> Result<(), Error>;
    /// Output a 32-bit uint
    fn emit_u32(&mut self, v: u32) -> Result<(), Error>;
    /// Output a 16-bit uint
    fn emit_u16(&mut self, v: u16) -> Result<(), Error>;
    /// Output a 8-bit uint
    fn emit_u8(&mut self, v: u8) -> Result<(), Error>;

    /// Output a 64-bit int
    fn emit_i64(&mut self, v: i64) -> Result<(), Error>;
    /// Output a 32-bit int
    fn emit_i32(&mut self, v: i32) -> Result<(), Error>;
    /// Output a 16-bit int
    fn emit_i16(&mut self, v: i16) -> Result<(), Error>;
    /// Output a 8-bit int
    fn emit_i8(&mut self, v: i8) -> Result<(), Error>;

    /// Output a boolean
    fn emit_bool(&mut self, v: bool) -> Result<(), Error>;
}

/// A simple Decoder trait
pub trait Decoder {
    /// Read a 64-bit uint
    fn read_u64(&mut self) -> Result<u64, Error>;
    /// Read a 32-bit uint
    fn read_u32(&mut self) -> Result<u32, Error>;
    /// Read a 16-bit uint
    fn read_u16(&mut self) -> Result<u16, Error>;
    /// Read a 8-bit uint
    fn read_u8(&mut self) -> Result<u8, Error>;

    /// Read a 64-bit int
    fn read_i64(&mut self) -> Result<i64, Error>;
    /// Read a 32-bit int
    fn read_i32(&mut self) -> Result<i32, Error>;
    /// Read a 16-bit int
    fn read_i16(&mut self) -> Result<i16, Error>;
    /// Read a 8-bit int
    fn read_i8(&mut self) -> Result<i8, Error>;

    /// Read a boolean
    fn read_bool(&mut self) -> Result<bool, Error>;
}

macro_rules! encoder_fn {
    ($name:ident, $val_type:ty, $writefn:ident) => {
        #[inline]
        fn $name(&mut self, v: $val_type) -> Result<(), Error> {
            WriteBytesExt::$writefn::<LittleEndian>(self, v).map_err(Error::Io)
        }
    }
}

macro_rules! decoder_fn {
    ($name:ident, $val_type:ty, $readfn:ident) => {
        #[inline]
        fn $name(&mut self) -> Result<$val_type, Error> {
            ReadBytesExt::$readfn::<LittleEndian>(self).map_err(Error::Io)
        }
    }
}

impl<W: Write> Encoder for W {
    encoder_fn!(emit_u64, u64, write_u64);
    encoder_fn!(emit_u32, u32, write_u32);
    encoder_fn!(emit_u16, u16, write_u16);
    encoder_fn!(emit_i64, i64, write_i64);
    encoder_fn!(emit_i32, i32, write_i32);
    encoder_fn!(emit_i16, i16, write_i16);

    #[inline]
    fn emit_i8(&mut self, v: i8) -> Result<(), Error> {
        self.write_i8(v).map_err(Error::Io)
    }
    #[inline]
    fn emit_u8(&mut self, v: u8) -> Result<(), Error> {
        self.write_u8(v).map_err(Error::Io)
    }
    #[inline]
    fn emit_bool(&mut self, v: bool) -> Result<(), Error> {
        self.write_i8(if v {1} else {0}).map_err(Error::Io)
    }
}

impl<R: Read> Decoder for R {
    decoder_fn!(read_u64, u64, read_u64);
    decoder_fn!(read_u32, u32, read_u32);
    decoder_fn!(read_u16, u16, read_u16);
    decoder_fn!(read_i64, i64, read_i64);
    decoder_fn!(read_i32, i32, read_i32);
    decoder_fn!(read_i16, i16, read_i16);

    #[inline]
    fn read_u8(&mut self) -> Result<u8, Error> {
        ReadBytesExt::read_u8(self).map_err(Error::Io)
    }
    #[inline]
    fn read_i8(&mut self) -> Result<i8, Error> {
        ReadBytesExt::read_i8(self).map_err(Error::Io)
    }
    #[inline]
    fn read_bool(&mut self) -> Result<bool, Error> {
        Decoder::read_i8(self).map(|bit| bit != 0)
    }
}

/// Maximum size, in bytes, of a vector we are allowed to decode
pub const MAX_VEC_SIZE: usize = 32 * 1024 * 1024;

/// Data which can be encoded in a consensus-consistent way
pub trait Encodable<S: Encoder> {
    /// Encode an object with a well-defined format, should only ever error if
    /// the underlying Encoder errors.
    fn consensus_encode(&self, e: &mut S) -> Result<(), self::Error>;
}

/// Data which can be encoded in a consensus-consistent way
pub trait Decodable<D: Decoder>: Sized {
    /// Decode an object with a well-defined format
    fn consensus_decode(d: &mut D) -> Result<Self, self::Error>;
}

/// A variable-length unsigned integer
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct VarInt(pub u64);

/// Data which must be preceded by a 4-byte checksum
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CheckedData(pub Vec<u8>);

// Primitive types
macro_rules! impl_int_encodable{
    ($ty:ident, $meth_dec:ident, $meth_enc:ident) => (
        impl<D: Decoder> Decodable<D> for $ty {
            #[inline]
            fn consensus_decode(d: &mut D) -> Result<$ty, self::Error> { d.$meth_dec().map($ty::from_le) }
        }

        impl<S: Encoder> Encodable<S> for $ty {
            #[inline]
            fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> { s.$meth_enc(self.to_le()) }
        }
    )
}

impl_int_encodable!(u8,  read_u8,  emit_u8);
impl_int_encodable!(u16, read_u16, emit_u16);
impl_int_encodable!(u32, read_u32, emit_u32);
impl_int_encodable!(u64, read_u64, emit_u64);
impl_int_encodable!(i8,  read_i8,  emit_i8);
impl_int_encodable!(i16, read_i16, emit_i16);
impl_int_encodable!(i32, read_i32, emit_i32);
impl_int_encodable!(i64, read_i64, emit_i64);

impl VarInt {
    /// Gets the length of this VarInt when encoded.
    /// Returns 1 for 0...0xFC, 3 for 0xFD...(2^16-1), 5 for 0x10000...(2^32-1),
    /// and 9 otherwise.
    #[inline]
    pub fn encoded_length(&self) -> u64 {
        match self.0 {
            0...0xFC             => { 1 }
            0xFD...0xFFFF        => { 3 }
            0x10000...0xFFFFFFFF => { 5 }
            _                    => { 9 }
        }
    }
}

impl<S: Encoder> Encodable<S> for VarInt {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> {
        match self.0 {
            0...0xFC             => { (self.0 as u8).consensus_encode(s) }
            0xFD...0xFFFF        => { s.emit_u8(0xFD)?; (self.0 as u16).consensus_encode(s) }
            0x10000...0xFFFFFFFF => { s.emit_u8(0xFE)?; (self.0 as u32).consensus_encode(s) }
            _                    => { s.emit_u8(0xFF)?; (self.0 as u64).consensus_encode(s) }
        }
    }
}

impl<D: Decoder> Decodable<D> for VarInt {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<VarInt, self::Error> {
        let n = d.read_u8()?;
        match n {
            0xFF => {
                let x = d.read_u64()?;
                if x < 0x100000000 {
                    Err(self::Error::ParseFailed("non-minimal varint"))
                } else {
                    Ok(VarInt(x))
                }
            }
            0xFE => {
                let x = d.read_u32()?;
                if x < 0x10000 {
                    Err(self::Error::ParseFailed("non-minimal varint"))
                } else {
                    Ok(VarInt(x as u64))
                }
            }
            0xFD => {
                let x = d.read_u16()?;
                if x < 0xFD {
                    Err(self::Error::ParseFailed("non-minimal varint"))
                } else {
                    Ok(VarInt(x as u64))
                }
            }
            n => Ok(VarInt(n as u64))
        }
    }
}


// Booleans
impl<S: Encoder> Encodable<S> for bool {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> { s.emit_u8(if *self {1} else {0}) }
}

impl<D: Decoder> Decodable<D> for bool {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<bool, self::Error> { d.read_u8().map(|n| n != 0) }
}

// Strings
impl<S: Encoder> Encodable<S> for String {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> {
        self.as_bytes().consensus_encode(s)
    }
}

impl<D: Decoder> Decodable<D> for String {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<String, self::Error> {
        String::from_utf8(Decodable::consensus_decode(d)?)
            .map_err(|_| self::Error::ParseFailed("String was not valid UTF8"))
    }
}


// Arrays
macro_rules! impl_array {
    ( $size:expr ) => (
        impl<S: Encoder, T: Encodable<S>> Encodable<S> for [T; $size] {
            #[inline]
            fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> {
                for i in self.iter() { i.consensus_encode(s)?; }
                Ok(())
            }
        }

        impl<D: Decoder, T:Decodable<D> + Copy> Decodable<D> for [T; $size] {
            #[inline]
            fn consensus_decode(d: &mut D) -> Result<[T; $size], self::Error> {
                // Set everything to the first decode
                let mut ret = [Decodable::consensus_decode(d)?; $size];
                // Set the rest
                for item in ret.iter_mut().take($size).skip(1) { *item = Decodable::consensus_decode(d)?; }
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

impl<S: Encoder, T: Encodable<S>> Encodable<S> for [T] {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> {
        VarInt(self.len() as u64).consensus_encode(s)?;
        for c in self.iter() { c.consensus_encode(s)?; }
        Ok(())
    }
}

// Cannot decode a slice

// Vectors
impl<S: Encoder, T: Encodable<S>> Encodable<S> for Vec<T> {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> { (&self[..]).consensus_encode(s) }
}

impl<D: Decoder, T: Decodable<D>> Decodable<D> for Vec<T> {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<Vec<T>, self::Error> {
        let len = VarInt::consensus_decode(d)?.0;
        let byte_size = (len as usize)
                            .checked_mul(mem::size_of::<T>())
                            .ok_or(self::Error::ParseFailed("Invalid length"))?;
        if byte_size > MAX_VEC_SIZE {
            return Err(self::Error::OversizedVectorAllocation { requested: byte_size, max: MAX_VEC_SIZE })
        }
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len { ret.push(Decodable::consensus_decode(d)?); }
        Ok(ret)
    }
}

impl<S: Encoder, T: Encodable<S>> Encodable<S> for Box<[T]> {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> { (&self[..]).consensus_encode(s) }
}

impl<D: Decoder, T: Decodable<D>> Decodable<D> for Box<[T]> {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<Box<[T]>, self::Error> {
        let len = VarInt::consensus_decode(d)?.0;
        let len = len as usize;
        if len > MAX_VEC_SIZE {
            return Err(self::Error::OversizedVectorAllocation { requested: len, max: MAX_VEC_SIZE })
        }
        let mut ret = Vec::with_capacity(len);
        for _ in 0..len { ret.push(Decodable::consensus_decode(d)?); }
        Ok(ret.into_boxed_slice())
    }
}

// Options (encoded as vectors of length 0 or 1)
impl<S: Encoder, T: Encodable<S>> Encodable<S> for Option<T> {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> {
        match *self {
            Some(ref data) => {
                1u8.consensus_encode(s)?;
                data.consensus_encode(s)?;
            }
            None => { 0u8.consensus_encode(s)?; }
        }
        Ok(())
    }
}

impl<D: Decoder, T:Decodable<D>> Decodable<D> for Option<T> {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<Option<T>, self::Error> {
        let bit: u8 = Decodable::consensus_decode(d)?;
        Ok(if bit != 0 {
            Some(Decodable::consensus_decode(d)?)
        } else {
            None
        })
    }
}


/// Do a double-SHA256 on some data and return the first 4 bytes
fn sha2_checksum(data: &[u8]) -> [u8; 4] {
    let checksum = <sha256d::Hash as HashTrait>::hash(data);
    [checksum[0], checksum[1], checksum[2], checksum[3]]
}

// Checked data
impl<S: Encoder> Encodable<S> for CheckedData {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> {
        (self.0.len() as u32).consensus_encode(s)?;
        sha2_checksum(&self.0).consensus_encode(s)?;
        // We can't just pass to the slice encoder since it'll insert a length
        for ch in &self.0 {
            ch.consensus_encode(s)?;
        }
        Ok(())
    }
}

impl<D: Decoder> Decodable<D> for CheckedData {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<CheckedData, self::Error> {
        let len: u32 = Decodable::consensus_decode(d)?;
        let checksum: [u8; 4] = Decodable::consensus_decode(d)?;
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len { ret.push(Decodable::consensus_decode(d)?); }
        let expected_checksum = sha2_checksum(&ret);
        if expected_checksum != checksum {
            Err(self::Error::InvalidChecksum {
                expected: expected_checksum,
                actual: checksum,
            })
        } else {
            Ok(CheckedData(ret))
        }
    }
}

// Tuples
macro_rules! tuple_encode {
    ($($x:ident),*) => (
        impl <S: Encoder, $($x: Encodable<S>),*> Encodable<S> for ($($x),*) {
            #[inline]
            #[allow(non_snake_case)]
            fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> {
                let &($(ref $x),*) = self;
                $( $x.consensus_encode(s)?; )*
                Ok(())
            }
        }

        impl<D: Decoder, $($x: Decodable<D>),*> Decodable<D> for ($($x),*) {
            #[inline]
            #[allow(non_snake_case)]
            fn consensus_decode(d: &mut D) -> Result<($($x),*), self::Error> {
                Ok(($({let $x = Decodable::consensus_decode(d)?; $x }),*))
            }
        }
    );
}

tuple_encode!(T0, T1);
tuple_encode!(T0, T1, T2, T3);
tuple_encode!(T0, T1, T2, T3, T4, T5);
tuple_encode!(T0, T1, T2, T3, T4, T5, T6, T7);

// References
impl<S: Encoder, T: Encodable<S>> Encodable<S> for Box<T> {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> { (**self).consensus_encode(s) }
}

impl<D: Decoder, T: Decodable<D>> Decodable<D> for Box<T> {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<Box<T>, self::Error> {
        Decodable::consensus_decode(d).map(Box::new)
    }
}

// HashMap
impl<S, K, V> Encodable<S> for HashMap<K, V>
    where S: Encoder,
          K: Encodable<S> + Eq + Hash,
          V: Encodable<S>
{
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> {
        VarInt(self.len() as u64).consensus_encode(s)?;
        for (key, value) in self.iter() {
            key.consensus_encode(s)?;
            value.consensus_encode(s)?;
        }
        Ok(())
    }
}

impl<D, K, V> Decodable<D> for HashMap<K, V>
    where D: Decoder,
          K: Decodable<D> + Eq + Hash,
          V: Decodable<D>
{
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<HashMap<K, V>, self::Error> {
        let len = VarInt::consensus_decode(d)?.0;

        let mut ret = HashMap::with_capacity(len as usize);
        for _ in 0..len {
            ret.insert(Decodable::consensus_decode(d)?,
                                 Decodable::consensus_decode(d)?);
        }
        Ok(ret)
    }
}

impl<S: Encoder> Encodable<S> for sha256d::Hash {
    fn consensus_encode(&self, s: &mut S) -> Result<(), self::Error> {
        self.into_inner().consensus_encode(s)
    }
}

impl<D: Decoder> Decodable<D> for sha256d::Hash {
    fn consensus_decode(d: &mut D) -> Result<sha256d::Hash, self::Error> {
        let inner: [u8; 32] = Decodable::consensus_decode(d)?;
        Ok(sha256d::Hash::from_slice(&inner).unwrap())
    }
}

// Tests
#[cfg(test)]
mod tests {
    use super::{CheckedData, VarInt};

    use super::{deserialize, serialize, Error};

    #[test]
    fn serialize_int_test() {
        // bool
        assert_eq!(serialize(&false), vec![0u8]);
        assert_eq!(serialize(&true), vec![1u8]);
        // u8
        assert_eq!(serialize(&1u8), vec![1u8]);
        assert_eq!(serialize(&0u8), vec![0u8]);
        assert_eq!(serialize(&255u8), vec![255u8]);
        // u16
        assert_eq!(serialize(&1u16), vec![1u8, 0]);
        assert_eq!(serialize(&256u16), vec![0u8, 1]);
        assert_eq!(serialize(&5000u16), vec![136u8, 19]);
        // u32
        assert_eq!(serialize(&1u32), vec![1u8, 0, 0, 0]);
        assert_eq!(serialize(&256u32), vec![0u8, 1, 0, 0]);
        assert_eq!(serialize(&5000u32), vec![136u8, 19, 0, 0]);
        assert_eq!(serialize(&500000u32), vec![32u8, 161, 7, 0]);
        assert_eq!(serialize(&168430090u32), vec![10u8, 10, 10, 10]);
        // TODO: test negative numbers
        assert_eq!(serialize(&1i32), vec![1u8, 0, 0, 0]);
        assert_eq!(serialize(&256i32), vec![0u8, 1, 0, 0]);
        assert_eq!(serialize(&5000i32), vec![136u8, 19, 0, 0]);
        assert_eq!(serialize(&500000i32), vec![32u8, 161, 7, 0]);
        assert_eq!(serialize(&168430090i32), vec![10u8, 10, 10, 10]);
        // u64
        assert_eq!(serialize(&1u64), vec![1u8, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&256u64), vec![0u8, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&5000u64), vec![136u8, 19, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&500000u64), vec![32u8, 161, 7, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&723401728380766730u64), vec![10u8, 10, 10, 10, 10, 10, 10, 10]);
        // TODO: test negative numbers
        assert_eq!(serialize(&1i64), vec![1u8, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&256i64), vec![0u8, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&5000i64), vec![136u8, 19, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&500000i64), vec![32u8, 161, 7, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&723401728380766730i64), vec![10u8, 10, 10, 10, 10, 10, 10, 10]);
    }

    #[test]
    fn serialize_varint_test() {
        assert_eq!(serialize(&VarInt(10)), vec![10u8]);
        assert_eq!(serialize(&VarInt(0xFC)), vec![0xFCu8]);
        assert_eq!(serialize(&VarInt(0xFD)), vec![0xFDu8, 0xFD, 0]);
        assert_eq!(serialize(&VarInt(0xFFF)), vec![0xFDu8, 0xFF, 0xF]);
        assert_eq!(serialize(&VarInt(0xF0F0F0F)), vec![0xFEu8, 0xF, 0xF, 0xF, 0xF]);
        assert_eq!(serialize(&VarInt(0xF0F0F0F0F0E0)), vec![0xFFu8, 0xE0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0, 0]);
    }

    #[test]
    fn deserialize_nonminimal_vec() {
        match deserialize::<Vec<u8>>(&[0xfd, 0x00, 0x00]) {
            Err(Error::ParseFailed("non-minimal varint")) => {},
            x => panic!(x)
        }
        match deserialize::<Vec<u8>>(&[0xfd, 0xfc, 0x00]) {
            Err(Error::ParseFailed("non-minimal varint")) => {},
            x => panic!(x)
        }
        match deserialize::<Vec<u8>>(&[0xfe, 0xff, 0x00, 0x00, 0x00]) {
            Err(Error::ParseFailed("non-minimal varint")) => {},
            x => panic!(x)
        }
        match deserialize::<Vec<u8>>(&[0xfe, 0xff, 0xff, 0x00, 0x00]) {
            Err(Error::ParseFailed("non-minimal varint")) => {},
            x => panic!(x)
        }
        match deserialize::<Vec<u8>>(&[0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) {
            Err(Error::ParseFailed("non-minimal varint")) => {},
            x => panic!(x)
        }
        match deserialize::<Vec<u8>>(&[0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00]) {
            Err(Error::ParseFailed("non-minimal varint")) => {},
            x => panic!(x)
        }

        let mut vec_256 = vec![0; 259];
        vec_256[0] = 0xfd;
        vec_256[1] = 0x00;
        vec_256[2] = 0x01;
        assert!(deserialize::<Vec<u8>>(&vec_256).is_ok());

        let mut vec_253 = vec![0; 256];
        vec_253[0] = 0xfd;
        vec_253[1] = 0xfd;
        vec_253[2] = 0x00;
        assert!(deserialize::<Vec<u8>>(&vec_253).is_ok());
    }

    #[test]
    fn serialize_checkeddata_test() {
        let cd = CheckedData(vec![1u8, 2, 3, 4, 5]);
        assert_eq!(serialize(&cd), vec![5, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn serialize_vector_test() {
        assert_eq!(serialize(&vec![1u8, 2, 3]), vec![3u8, 1, 2, 3]);
        assert_eq!(serialize(&[1u8, 2, 3][..]), vec![3u8, 1, 2, 3]);
        // TODO: test vectors of more interesting objects
    }

    #[test]
    fn serialize_strbuf_test() {
        assert_eq!(serialize(&"Andrew".to_string()), vec![6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]);
    }

    #[test]
    fn serialize_box_test() {
        assert_eq!(serialize(&Box::new(1u8)), vec![1u8]);
        assert_eq!(serialize(&Box::new(1u16)), vec![1u8, 0]);
        assert_eq!(serialize(&Box::new(1u64)), vec![1u8, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn serialize_option_test() {
        assert_eq!(serialize(&None::<u8>), vec![0]);
        assert_eq!(serialize(&Some(0xFFu8)), vec![1, 0xFF]);
    }

    #[test]
    fn deserialize_int_test() {
        // bool
        assert!((deserialize(&[58u8, 0]) as Result<bool, _>).is_err());
        assert_eq!(deserialize(&[58u8]).ok(), Some(true));
        assert_eq!(deserialize(&[1u8]).ok(), Some(true));
        assert_eq!(deserialize(&[0u8]).ok(), Some(false));
        assert!((deserialize(&[0u8, 1]) as Result<bool, _>).is_err());

        // u8
        assert_eq!(deserialize(&[58u8]).ok(), Some(58u8));

        // u16
        assert_eq!(deserialize(&[0x01u8, 0x02]).ok(), Some(0x0201u16));
        assert_eq!(deserialize(&[0xABu8, 0xCD]).ok(), Some(0xCDABu16));
        assert_eq!(deserialize(&[0xA0u8, 0x0D]).ok(), Some(0xDA0u16));
        let failure16: Result<u16, _> = deserialize(&[1u8]);
        assert!(failure16.is_err());

        // u32
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0]).ok(), Some(0xCDABu32));
        assert_eq!(deserialize(&[0xA0u8, 0x0D, 0xAB, 0xCD]).ok(), Some(0xCDAB0DA0u32));
        let failure32: Result<u32, _> = deserialize(&[1u8, 2, 3]);
        assert!(failure32.is_err());
        // TODO: test negative numbers
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0]).ok(), Some(0xCDABi32));
        assert_eq!(deserialize(&[0xA0u8, 0x0D, 0xAB, 0x2D]).ok(), Some(0x2DAB0DA0i32));
        let failurei32: Result<i32, _> = deserialize(&[1u8, 2, 3]);
        assert!(failurei32.is_err());

        // u64
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0, 0, 0, 0, 0]).ok(), Some(0xCDABu64));
        assert_eq!(deserialize(&[0xA0u8, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99]).ok(), Some(0x99000099CDAB0DA0u64));
        let failure64: Result<u64, _> = deserialize(&[1u8, 2, 3, 4, 5, 6, 7]);
        assert!(failure64.is_err());
        // TODO: test negative numbers
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0, 0, 0, 0, 0]).ok(), Some(0xCDABi64));
        assert_eq!(deserialize(&[0xA0u8, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99]).ok(), Some(-0x66ffff663254f260i64));
        let failurei64: Result<i64, _> = deserialize(&[1u8, 2, 3, 4, 5, 6, 7]);
        assert!(failurei64.is_err());
    }

    #[test]
    fn deserialize_vec_test() {
        assert_eq!(deserialize(&[3u8, 2, 3, 4]).ok(), Some(vec![2u8, 3, 4]));
        assert!((deserialize(&[4u8, 2, 3, 4, 5, 6]) as Result<Vec<u8>, _>).is_err());
        // found by cargo fuzz
        assert!(deserialize::<Vec<u64>>(&[0xff,0xff,0xff,0xff,0x6b,0x6b,0x6b,0x6b,0x6b,0x6b,0x6b,0x6b,0x6b,0x6b,0x6b,0x6b,0xa,0xa,0x3a]).is_err());
    }

    #[test]
    fn deserialize_strbuf_test() {
        assert_eq!(deserialize(&[6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]).ok(), Some("Andrew".to_string()));
    }

    #[test]
    fn deserialize_checkeddata_test() {
        let cd: Result<CheckedData, _> = deserialize(&[5u8, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5]);
        assert_eq!(cd.ok(), Some(CheckedData(vec![1u8, 2, 3, 4, 5])));
    }

    #[test]
    fn deserialize_option_test() {
        let none: Result<Option<u8>, _> = deserialize(&[0u8]);
        let good: Result<Option<u8>, _> = deserialize(&[1u8, 0xFF]);
        let bad: Result<Option<u8>, _> = deserialize(&[2u8]);
        assert!(bad.is_err());
        assert_eq!(none.ok(), Some(None));
        assert_eq!(good.ok(), Some(Some(0xFF)));
    }

    #[test]
    fn deserialize_box_test() {
        let zero: Result<Box<u8>, _> = deserialize(&[0u8]);
        let one: Result<Box<u8>, _> = deserialize(&[1u8]);
        assert_eq!(zero.ok(), Some(Box::new(0)));
        assert_eq!(one.ok(), Some(Box::new(1)));
    }
}

