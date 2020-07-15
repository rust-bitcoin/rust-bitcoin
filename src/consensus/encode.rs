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

use std::{fmt, error, io, mem, u32};
use std::borrow::Cow;
use std::io::{Cursor, Read, Write};
use hashes::hex::ToHex;

use hashes::{sha256d, Hash};
use hash_types::{BlockHash, FilterHash, TxMerkleNode};

use util::endian;
use util::psbt;

use blockdata::transaction::{TxOut, Transaction, TxIn};
use network::message_blockdata::Inventory;
use network::address::Address;

/// Encoding error
#[derive(Debug)]
pub enum Error {
    /// And I/O error
    Io(io::Error),
    /// PSBT-related error
    Psbt(psbt::Error),
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
    /// VarInt was encoded in a non-minimal way
    NonMinimalVarInt,
    /// Network magic was unknown
    UnknownNetworkMagic(u32),
    /// Parsing error
    ParseFailed(&'static str),
    /// Unsupported Segwit flag
    UnsupportedSegwitFlag(u8),
    /// Unrecognized network command
    UnrecognizedNetworkCommand(String),
    /// Invalid Inventory type
    UnknownInventoryType(u32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => write!(f, "I/O error: {}", e),
            Error::Psbt(ref e) => write!(f, "PSBT error: {}", e),
            Error::UnexpectedNetworkMagic { expected: ref e, actual: ref a } => write!(f,
                "unexpected network magic: expected {}, actual {}", e, a),
            Error::OversizedVectorAllocation { requested: ref r, max: ref m } => write!(f,
                "allocation of oversized vector: requested {}, maximum {}", r, m),
            Error::InvalidChecksum { expected: ref e, actual: ref a } => write!(f,
                "invalid checksum: expected {}, actual {}", e.to_hex(), a.to_hex()),
            Error::NonMinimalVarInt => write!(f, "non-minimal varint"),
            Error::UnknownNetworkMagic(ref m) => write!(f, "unknown network magic: {}", m),
            Error::ParseFailed(ref e) => write!(f, "parse failed: {}", e),
            Error::UnsupportedSegwitFlag(ref swflag) => write!(f,
                "unsupported segwit version: {}", swflag),
            Error::UnrecognizedNetworkCommand(ref nwcmd) => write!(f,
                "unrecognized network command: {}", nwcmd),
            Error::UnknownInventoryType(ref tp) => write!(f, "Unknown Inventory type: {}", tp),
        }
    }
}

#[allow(deprecated)]
impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Io(ref e) => Some(e),
            Error::Psbt(ref e) => Some(e),
            Error::UnexpectedNetworkMagic { .. }
            | Error::OversizedVectorAllocation { .. }
            | Error::InvalidChecksum { .. }
            | Error::NonMinimalVarInt
            | Error::UnknownNetworkMagic(..)
            | Error::ParseFailed(..)
            | Error::UnsupportedSegwitFlag(..)
            | Error::UnrecognizedNetworkCommand(..)
            | Error::UnknownInventoryType(..) => None,
        }
    }

    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }
}

#[doc(hidden)]

#[doc(hidden)]
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

#[doc(hidden)]
impl From<psbt::Error> for Error {
    fn from(e: psbt::Error) -> Error {
        Error::Psbt(e)
    }
}

/// Encode an object into a vector
pub fn serialize<T: Encodable + ?Sized>(data: &T) -> Vec<u8> {
    let mut encoder = Vec::new();
    let len = data.consensus_encode(&mut encoder).unwrap();
    assert_eq!(len, encoder.len());
    encoder
}

/// Encode an object into a hex-encoded string
pub fn serialize_hex<T: Encodable + ?Sized>(data: &T) -> String {
    serialize(data)[..].to_hex()
}

/// Deserialize an object from a vector, will error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize<T: Decodable>(data: &[u8]) -> Result<T, Error> {
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
pub fn deserialize_partial<T: Decodable>(
    data: &[u8],
) -> Result<(T, usize), Error> {
    let mut decoder = Cursor::new(data);
    let rv = Decodable::consensus_decode(&mut decoder)?;
    let consumed = decoder.position() as usize;

    Ok((rv, consumed))
}


/// Extensions of `Write` to encode data as per Bitcoin consensus
pub trait WriteExt {
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

    /// Output a byte slice
    fn emit_slice(&mut self, v: &[u8]) -> Result<(), Error>;
}

/// Extensions of `Read` to decode data as per Bitcoin consensus
pub trait ReadExt {
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

    /// Read a byte slice
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), Error>;
}

macro_rules! encoder_fn {
    ($name:ident, $val_type:ty, $writefn:ident) => {
        #[inline]
        fn $name(&mut self, v: $val_type) -> Result<(), Error> {
            self.write_all(&endian::$writefn(v)).map_err(Error::Io)
        }
    }
}

macro_rules! decoder_fn {
    ($name:ident, $val_type:ty, $readfn:ident, $byte_len: expr) => {
        #[inline]
        fn $name(&mut self) -> Result<$val_type, Error> {
            assert_eq!(::std::mem::size_of::<$val_type>(), $byte_len); // size_of isn't a constfn in 1.22
            let mut val = [0; $byte_len];
            self.read_exact(&mut val[..]).map_err(Error::Io)?;
            Ok(endian::$readfn(&val))
        }
    }
}

impl<W: Write> WriteExt for W {
    encoder_fn!(emit_u64, u64, u64_to_array_le);
    encoder_fn!(emit_u32, u32, u32_to_array_le);
    encoder_fn!(emit_u16, u16, u16_to_array_le);
    encoder_fn!(emit_i64, i64, i64_to_array_le);
    encoder_fn!(emit_i32, i32, i32_to_array_le);
    encoder_fn!(emit_i16, i16, i16_to_array_le);

    #[inline]
    fn emit_i8(&mut self, v: i8) -> Result<(), Error> {
        self.write_all(&[v as u8]).map_err(Error::Io)
    }
    #[inline]
    fn emit_u8(&mut self, v: u8) -> Result<(), Error> {
        self.write_all(&[v]).map_err(Error::Io)
    }
    #[inline]
    fn emit_bool(&mut self, v: bool) -> Result<(), Error> {
        self.write_all(&[v as u8]).map_err(Error::Io)
    }
    #[inline]
    fn emit_slice(&mut self, v: &[u8]) -> Result<(), Error> {
        self.write_all(v).map_err(Error::Io)
    }
}

impl<R: Read> ReadExt for R {
    decoder_fn!(read_u64, u64, slice_to_u64_le, 8);
    decoder_fn!(read_u32, u32, slice_to_u32_le, 4);
    decoder_fn!(read_u16, u16, slice_to_u16_le, 2);
    decoder_fn!(read_i64, i64, slice_to_i64_le, 8);
    decoder_fn!(read_i32, i32, slice_to_i32_le, 4);
    decoder_fn!(read_i16, i16, slice_to_i16_le, 2);

    #[inline]
    fn read_u8(&mut self) -> Result<u8, Error> {
        let mut slice = [0u8; 1];
        self.read_exact(&mut slice)?;
        Ok(slice[0])
    }
    #[inline]
    fn read_i8(&mut self) -> Result<i8, Error> {
        let mut slice = [0u8; 1];
        self.read_exact(&mut slice)?;
        Ok(slice[0] as i8)
    }
    #[inline]
    fn read_bool(&mut self) -> Result<bool, Error> {
        ReadExt::read_i8(self).map(|bit| bit != 0)
    }
    #[inline]
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), Error> {
        self.read_exact(slice).map_err(Error::Io)
    }
}

/// Maximum size, in bytes, of a vector we are allowed to decode
pub const MAX_VEC_SIZE: usize = 4_000_000;

/// Data which can be encoded in a consensus-consistent way
pub trait Encodable {
    /// Encode an object with a well-defined format, should only ever error if
    /// the underlying `Write` errors. Returns the number of bytes written on
    /// success
    fn consensus_encode<W: io::Write>(&self, e: W) -> Result<usize, Error>;
}

/// Data which can be encoded in a consensus-consistent way
pub trait Decodable: Sized {
    /// Decode an object with a well-defined format
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error>;
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
        impl Decodable for $ty {
            #[inline]
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
                ReadExt::$meth_dec(&mut d).map($ty::from_le)
            }
        }
        impl Encodable for $ty {
            #[inline]
            fn consensus_encode<S: WriteExt>(
                &self,
                mut s: S,
            ) -> Result<usize, self::Error> {
                s.$meth_enc(self.to_le())?;
                Ok(mem::size_of::<$ty>())
            }
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
    pub fn len(&self) -> usize {
        match self.0 {
            0...0xFC             => { 1 }
            0xFD...0xFFFF        => { 3 }
            0x10000...0xFFFFFFFF => { 5 }
            _                    => { 9 }
        }
    }
}

impl Encodable for VarInt {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, Error> {
        match self.0 {
            0...0xFC => {
                (self.0 as u8).consensus_encode(s)?;
                Ok(1)
            },
            0xFD...0xFFFF => {
                s.emit_u8(0xFD)?;
                (self.0 as u16).consensus_encode(s)?;
                Ok(3)
            },
            0x10000...0xFFFFFFFF => {
                s.emit_u8(0xFE)?;
                (self.0 as u32).consensus_encode(s)?;
                Ok(5)
            },
            _ => {
                s.emit_u8(0xFF)?;
                (self.0 as u64).consensus_encode(s)?;
                Ok(9)
            },
        }
    }
}

impl Decodable for VarInt {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let n = ReadExt::read_u8(&mut d)?;
        match n {
            0xFF => {
                let x = ReadExt::read_u64(&mut d)?;
                if x < 0x100000000 {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt(x))
                }
            }
            0xFE => {
                let x = ReadExt::read_u32(&mut d)?;
                if x < 0x10000 {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt(x as u64))
                }
            }
            0xFD => {
                let x = ReadExt::read_u16(&mut d)?;
                if x < 0xFD {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt(x as u64))
                }
            }
            n => Ok(VarInt(n as u64))
        }
    }
}


// Booleans
impl Encodable for bool {
    #[inline]
    fn consensus_encode<S: WriteExt>(&self, mut s: S) -> Result<usize, Error> {
        s.emit_bool(*self)?;
        Ok(1)
    }
}

impl Decodable for bool {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<bool, Error> {
        ReadExt::read_bool(&mut d)
    }
}

// Strings
impl Encodable for String {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, Error> {
        let b = self.as_bytes();
        let vi_len = VarInt(b.len() as u64).consensus_encode(&mut s)?;
        s.emit_slice(&b)?;
        Ok(vi_len + b.len())
    }
}

impl Decodable for String {
    #[inline]
    fn consensus_decode<D: io::Read>(d: D) -> Result<String, Error> {
        String::from_utf8(Decodable::consensus_decode(d)?)
            .map_err(|_| self::Error::ParseFailed("String was not valid UTF8"))
    }
}

// Cow<'static, str>
impl Encodable for Cow<'static, str> {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, Error> {
        let b = self.as_bytes();
        let vi_len = VarInt(b.len() as u64).consensus_encode(&mut s)?;
        s.emit_slice(&b)?;
        Ok(vi_len + b.len())
    }
}

impl Decodable for Cow<'static, str> {
    #[inline]
    fn consensus_decode<D: io::Read>(d: D) -> Result<Cow<'static, str>, Error> {
        String::from_utf8(Decodable::consensus_decode(d)?)
            .map_err(|_| self::Error::ParseFailed("String was not valid UTF8"))
            .map(Cow::Owned)
    }
}


// Arrays
macro_rules! impl_array {
    ( $size:expr ) => (
        impl Encodable for [u8; $size] {
            #[inline]
            fn consensus_encode<S: WriteExt>(
                &self,
                mut s: S,
            ) -> Result<usize, Error> {
                s.emit_slice(&self[..])?;
                Ok(self.len())
            }
        }

        impl Decodable for [u8; $size] {
            #[inline]
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
                let mut ret = [0; $size];
                d.read_slice(&mut ret)?;
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
impl_array!(33);

impl Decodable for [u16; 8] {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut res = [0; 8];
        for item in &mut res {
            *item = Decodable::consensus_decode(&mut d)?;
        }
        Ok(res)
    }
}

impl Encodable for [u16; 8] {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, Error> {
        for c in self.iter() { c.consensus_encode(&mut s)?; }
        Ok(16)
    }
}

// Vectors
macro_rules! impl_vec {
    ($type: ty) => {
        impl Encodable for Vec<$type> {
            #[inline]
            fn consensus_encode<S: io::Write>(
                &self,
                mut s: S,
            ) -> Result<usize, Error> {
                let mut len = 0;
                len += VarInt(self.len() as u64).consensus_encode(&mut s)?;
                for c in self.iter() {
                    len += c.consensus_encode(&mut s)?;
                }
                Ok(len)
            }
        }
        impl Decodable for Vec<$type> {
            #[inline]
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
                let len = VarInt::consensus_decode(&mut d)?.0;
                let byte_size = (len as usize)
                                    .checked_mul(mem::size_of::<$type>())
                                    .ok_or(self::Error::ParseFailed("Invalid length"))?;
                if byte_size > MAX_VEC_SIZE {
                    return Err(self::Error::OversizedVectorAllocation { requested: byte_size, max: MAX_VEC_SIZE })
                }
                let mut ret = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    ret.push(Decodable::consensus_decode(&mut d)?);
                }
                Ok(ret)
            }
        }
    }
}
impl_vec!(BlockHash);
impl_vec!(FilterHash);
impl_vec!(TxMerkleNode);
impl_vec!(Transaction);
impl_vec!(TxOut);
impl_vec!(TxIn);
impl_vec!(Inventory);
impl_vec!(Vec<u8>);
impl_vec!((u32, Address));
impl_vec!(u64);

fn consensus_encode_with_size<S: io::Write>(data: &[u8], mut s: S) -> Result<usize, Error> {
    let vi_len = VarInt(data.len() as u64).consensus_encode(&mut s)?;
    s.emit_slice(&data)?;
    Ok(vi_len + data.len())
}


impl Encodable for Vec<u8> {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, Error> {
        consensus_encode_with_size(self, s)
    }
}

impl Decodable for Vec<u8> {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = VarInt::consensus_decode(&mut d)?.0 as usize;
        if len > MAX_VEC_SIZE {
            return Err(self::Error::OversizedVectorAllocation { requested: len, max: MAX_VEC_SIZE })
        }
        let mut ret = vec![0u8; len];
        d.read_slice(&mut ret)?;
        Ok(ret)
    }
}

impl Encodable for Box<[u8]> {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, Error> {
        consensus_encode_with_size(self, s)
    }
}

impl Decodable for Box<[u8]> {
    #[inline]
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        <Vec<u8>>::consensus_decode(d).map(From::from)
    }
}


/// Do a double-SHA256 on some data and return the first 4 bytes
fn sha2_checksum(data: &[u8]) -> [u8; 4] {
    let checksum = <sha256d::Hash as Hash>::hash(data);
    [checksum[0], checksum[1], checksum[2], checksum[3]]
}

// Checked data
impl Encodable for CheckedData {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, Error> {
        (self.0.len() as u32).consensus_encode(&mut s)?;
        sha2_checksum(&self.0).consensus_encode(&mut s)?;
        s.emit_slice(&self.0)?;
        Ok(8 + self.0.len())
    }
}

impl Decodable for CheckedData {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = u32::consensus_decode(&mut d)?;
        if len > MAX_VEC_SIZE as u32 {
            return Err(self::Error::OversizedVectorAllocation {
                requested: len as usize,
                max: MAX_VEC_SIZE
            });
        }
        let checksum = <[u8; 4]>::consensus_decode(&mut d)?;
        let mut ret = vec![0u8; len as usize];
        d.read_slice(&mut ret)?;
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
        impl <$($x: Encodable),*> Encodable for ($($x),*) {
            #[inline]
            #[allow(non_snake_case)]
            fn consensus_encode<S: io::Write>(
                &self,
                mut s: S,
            ) -> Result<usize, self::Error> {
                let &($(ref $x),*) = self;
                let mut len = 0;
                $(len += $x.consensus_encode(&mut s)?;)*
                Ok(len)
            }
        }

        impl<$($x: Decodable),*> Decodable for ($($x),*) {
            #[inline]
            #[allow(non_snake_case)]
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
                Ok(($({let $x = Decodable::consensus_decode(&mut d)?; $x }),*))
            }
        }
    );
}

tuple_encode!(T0, T1);
tuple_encode!(T0, T1, T2, T3);
tuple_encode!(T0, T1, T2, T3, T4, T5);
tuple_encode!(T0, T1, T2, T3, T4, T5, T6, T7);

impl Encodable for sha256d::Hash {
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, Error> {
        self.into_inner().consensus_encode(s)
    }
}

impl Decodable for sha256d::Hash {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::from_inner(<<Self as Hash>::Inner>::consensus_decode(d)?))
    }
}

// Tests
#[cfg(test)]
mod tests {
    use std::{io, mem, fmt};
    use std::mem::discriminant;
    use super::{deserialize, serialize, Error, CheckedData, VarInt};
    use super::{Transaction, BlockHash, FilterHash, TxMerkleNode, TxOut, TxIn};
    use consensus::{Encodable, deserialize_partial, Decodable};
    use util::endian::{u64_to_array_le, u32_to_array_le, u16_to_array_le};
    use secp256k1::rand::{thread_rng, Rng};
    use network::message_blockdata::Inventory;
    use network::Address;

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
        // i32
        assert_eq!(serialize(&-1i32), vec![255u8, 255, 255, 255]);
        assert_eq!(serialize(&-256i32), vec![0u8, 255, 255, 255]);
        assert_eq!(serialize(&-5000i32), vec![120u8, 236, 255, 255]);
        assert_eq!(serialize(&-500000i32), vec![224u8, 94, 248, 255]);
        assert_eq!(serialize(&-168430090i32), vec![246u8, 245, 245, 245]);
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
        // i64
        assert_eq!(serialize(&-1i64), vec![255u8, 255, 255, 255, 255, 255, 255, 255]);
        assert_eq!(serialize(&-256i64), vec![0u8, 255, 255, 255, 255, 255, 255, 255]);
        assert_eq!(serialize(&-5000i64), vec![120u8, 236, 255, 255, 255, 255, 255, 255]);
        assert_eq!(serialize(&-500000i64), vec![224u8, 94, 248, 255, 255, 255, 255, 255]);
        assert_eq!(serialize(&-723401728380766730i64), vec![246u8, 245, 245, 245, 245, 245, 245, 245]);
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
        assert_eq!(test_varint_encode(0xFF, &u64_to_array_le(0x100000000)).unwrap(), VarInt(0x100000000));
        assert_eq!(test_varint_encode(0xFE, &u64_to_array_le(0x10000)).unwrap(), VarInt(0x10000));
        assert_eq!(test_varint_encode(0xFD, &u64_to_array_le(0xFD)).unwrap(), VarInt(0xFD));

        // Test that length calc is working correctly
        test_varint_len(VarInt(0), 1);
        test_varint_len(VarInt(0xFC), 1);
        test_varint_len(VarInt(0xFD), 3);
        test_varint_len(VarInt(0xFFFF), 3);
        test_varint_len(VarInt(0x10000), 5);
        test_varint_len(VarInt(0xFFFFFFFF), 5);
        test_varint_len(VarInt(0xFFFFFFFF+1), 9);
        test_varint_len(VarInt(u64::max_value()), 9);
    }

    fn test_varint_len(varint: VarInt, expected: usize) {
        let mut encoder = io::Cursor::new(vec![]);
        assert_eq!(varint.consensus_encode(&mut encoder).unwrap(), expected);
        assert_eq!(varint.len(), expected);
    }

    fn test_varint_encode(n: u8, x: &[u8]) -> Result<VarInt, Error> {
        let mut input = [0u8; 9];
        input[0] = n;
        input[1..x.len()+1].copy_from_slice(x);
        deserialize_partial::<VarInt>(&input).map(|t|t.0)
    }

    #[test]
    fn deserialize_nonminimal_vec() {
        // Check the edges for variant int
        assert_eq!(discriminant(&test_varint_encode(0xFF, &u64_to_array_le(0x100000000-1)).unwrap_err()),
                   discriminant(&Error::NonMinimalVarInt));
        assert_eq!(discriminant(&test_varint_encode(0xFE, &u32_to_array_le(0x10000-1)).unwrap_err()),
                   discriminant(&Error::NonMinimalVarInt));
        assert_eq!(discriminant(&test_varint_encode(0xFD, &u16_to_array_le(0xFD-1)).unwrap_err()),
                   discriminant(&Error::NonMinimalVarInt));

        assert_eq!(discriminant(&deserialize::<Vec<u8>>(&[0xfd, 0x00, 0x00]).unwrap_err()),
                   discriminant(&Error::NonMinimalVarInt));
        assert_eq!(discriminant(&deserialize::<Vec<u8>>(&[0xfd, 0xfc, 0x00]).unwrap_err()),
                   discriminant(&Error::NonMinimalVarInt));
        assert_eq!(discriminant(&deserialize::<Vec<u8>>(&[0xfd, 0xfc, 0x00]).unwrap_err()),
                   discriminant(&Error::NonMinimalVarInt));
        assert_eq!(discriminant(&deserialize::<Vec<u8>>(&[0xfe, 0xff, 0x00, 0x00, 0x00]).unwrap_err()),
                   discriminant(&Error::NonMinimalVarInt));
        assert_eq!(discriminant(&deserialize::<Vec<u8>>(&[0xfe, 0xff, 0xff, 0x00, 0x00]).unwrap_err()),
                   discriminant(&Error::NonMinimalVarInt));
        assert_eq!(discriminant(&deserialize::<Vec<u8>>(&[0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap_err()),
                   discriminant(&Error::NonMinimalVarInt));
        assert_eq!(discriminant(&deserialize::<Vec<u8>>(&[0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap_err()),
                   discriminant(&Error::NonMinimalVarInt));


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
        // TODO: test vectors of more interesting objects
    }

    #[test]
    fn serialize_strbuf_test() {
        assert_eq!(serialize(&"Andrew".to_string()), vec![6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]);
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

        let rand_io_err = Error::Io(io::Error::new(io::ErrorKind::Other, ""));

        // Check serialization that `if len > MAX_VEC_SIZE {return err}` isn't inclusive,
        // by making sure it fails with IO Error and not an `OversizedVectorAllocation` Error.
        let err = deserialize::<CheckedData>(&serialize(&(super::MAX_VEC_SIZE as u32))).unwrap_err();
        assert_eq!(discriminant(&err), discriminant(&rand_io_err));

        test_len_is_max_vec::<u8>();
        test_len_is_max_vec::<BlockHash>();
        test_len_is_max_vec::<FilterHash>();
        test_len_is_max_vec::<TxMerkleNode>();
        test_len_is_max_vec::<Transaction>();
        test_len_is_max_vec::<TxOut>();
        test_len_is_max_vec::<TxIn>();
        test_len_is_max_vec::<Inventory>();
        test_len_is_max_vec::<Vec<u8>>();
        test_len_is_max_vec::<(u32, Address)>();
        test_len_is_max_vec::<u64>();
    }

    fn test_len_is_max_vec<T>() where Vec<T>: Decodable, T: fmt::Debug {
        let rand_io_err = Error::Io(io::Error::new(io::ErrorKind::Other, ""));
        let varint = VarInt((super::MAX_VEC_SIZE / mem::size_of::<T>()) as u64);
        let err = deserialize::<Vec<T>>(&serialize(&varint)).unwrap_err();
        assert_eq!(discriminant(&err), discriminant(&rand_io_err));
    }

    #[test]
    fn deserialize_strbuf_test() {
        assert_eq!(deserialize(&[6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]).ok(), Some("Andrew".to_string()));
        assert_eq!(
            deserialize(&[6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]).ok(),
            Some(::std::borrow::Cow::Borrowed("Andrew"))
        );
    }

    #[test]
    fn deserialize_checkeddata_test() {
        let cd: Result<CheckedData, _> = deserialize(&[5u8, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5]);
        assert_eq!(cd.ok(), Some(CheckedData(vec![1u8, 2, 3, 4, 5])));
    }

    #[test]
    fn serialization_round_trips() {
        macro_rules! round_trip {
            ($($val_type:ty),*) => {
                $(
                    let r: $val_type = thread_rng().gen();
                    assert_eq!(deserialize::<$val_type>(&serialize(&r)).unwrap(), r);
                )*
            };
        }
        macro_rules! round_trip_bytes {
            ($(($val_type:ty, $data:expr)),*) => {
                $(
                    thread_rng().fill(&mut $data[..]);
                    assert_eq!(deserialize::<$val_type>(&serialize(&$data)).unwrap()[..], $data[..]);
                )*
            };
        }

        let mut data = Vec::with_capacity(256);
        let mut data64 = Vec::with_capacity(256);
        for _ in 0..10 {
            round_trip!{bool, i8, u8, i16, u16, i32, u32, i64, u64,
            (bool, i8, u16, i32), (u64, i64, u32, i32, u16, i16), (i8, u8, i16, u16, i32, u32, i64, u64),
            [u8; 2], [u8; 4], [u8; 8], [u8; 12], [u8; 16], [u8; 32]};

            data.clear();
            data64.clear();
            let len = thread_rng().gen_range(1, 256);
            data.resize(len, 0u8);
            data64.resize(len, 0u64);
            let mut arr33 = [0u8; 33];
            let mut arr16 = [0u16; 8];
            round_trip_bytes!{(Vec<u8>, data), ([u8; 33], arr33), ([u16; 8], arr16), (Vec<u64>, data64)};


        }
    }
}

