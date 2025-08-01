// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin - consensus encoding and decoding
//!
//! This library provides traits that can be used to encode/decode objects in a
//! consensus-consistent way.
//!
//! ## Notes on I/O
//!
//! I/O in Rust has a few problems in relation to no-std, as such we depend on the [`bitcoin-io`]
//! crate and this library uses `io::Read` and `io::Write` to read and write respectively to readers
//! and writers that are, to the best of our ability, interoperable with `std::io`. This includes
//! error handling by way of the [`bitcoin_io::Error`].
//!
//! [bitcoin-io]: io
//! [`bitcoin_io::Error`]: io::Error

#![no_std]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Exclude lints we don't think are valuable.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)`instead of enforcing `format!("{x}")`

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "hashes")]
pub extern crate hashes;

mod decode;
mod encode;
#[cfg(feature = "hashes")]
mod hash;

pub mod error;

#[cfg(all(feature = "alloc", feature = "hex"))]
use core::fmt;
use core::mem;

use internals::ToU64;
use io::{Read, Write};

#[cfg(all(feature = "alloc", feature = "hex"))]
use self::prelude::String;
#[cfg(feature = "alloc")]
use self::prelude::Vec;

#[rustfmt::skip]                // Keep public re-exports separate.
pub use self::{
    decode::{Decodable, MAX_VEC_SIZE, ReadExt},
    encode::{Encodable, WriteExt},
    error::{DecodeError, Error, ParseError, DeserializeError},
};
#[cfg(feature = "hex")]
pub use self::error::FromHexError;

/// Encodes an object into a vector.
#[cfg(feature = "alloc")]
pub fn serialize<T: Encodable + ?Sized>(data: &T) -> Vec<u8> {
    let mut encoder = Vec::new();
    let len = data.consensus_encode(&mut encoder).expect("in-memory writers don't error");
    debug_assert_eq!(len, encoder.len());
    encoder
}

/// Encodes an object into a hex-encoded string.
#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
pub fn serialize_hex<T: Encodable + ?Sized>(data: &T) -> String {
    use hex::DisplayHex as _;
    serialize(data).to_lower_hex_string()
}

/// Deserializes an object from a vector, will error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize<T: Decodable>(data: &[u8]) -> Result<T, DeserializeError> {
    let (rv, consumed) = deserialize_partial(data)?;

    // Fail if data are not consumed entirely.
    if consumed == data.len() {
        Ok(rv)
    } else {
        Err(DeserializeError::Unconsumed)
    }
}

/// Deserialize any decodable type from a hex string, will error if said deserialization
/// doesn't consume the entire vector.
#[cfg(feature = "hex")]
pub fn deserialize_hex<T: Decodable>(hex: &str) -> Result<T, FromHexError> {
    let iter = hex::HexSliceToBytesIter::new(hex)?;
    let reader = IterReader::new(iter);
    Ok(reader.decode().map_err(FromHexError::Decode)?)
}

/// Deserializes an object from a vector, but will not report an error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize_partial<T: Decodable>(data: &[u8]) -> Result<(T, usize), ParseError> {
    let mut decoder = io::Cursor::new(data);

    let rv = match Decodable::consensus_decode_from_finite_reader(&mut decoder) {
        Ok(rv) => rv,
        Err(Error::Parse(e)) => return Err(e),
        Err(Error::Io(_)) =>
            unreachable!("consensus_decode code never returns an I/O error for in-memory reads"),
    };
    let consumed = decoder.position() as usize;

    Ok((rv, consumed))
}

// Primitive types
macro_rules! impl_int_encodable {
    ($ty:ident, $meth_dec:ident, $meth_enc:ident) => {
        impl Decodable for $ty {
            #[inline]
            fn consensus_decode<R: io::Read + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<Self, Error> {
                ReadExt::$meth_dec(r)
            }
        }
        impl Encodable for $ty {
            #[inline]
            fn consensus_encode<W: Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> core::result::Result<usize, io::Error> {
                w.$meth_enc(*self)?;
                Ok(mem::size_of::<$ty>())
            }
        }
    };
}

impl_int_encodable!(u8, read_u8, emit_u8);
impl_int_encodable!(u16, read_u16, emit_u16);
impl_int_encodable!(u32, read_u32, emit_u32);
impl_int_encodable!(u64, read_u64, emit_u64);
impl_int_encodable!(i8, read_i8, emit_i8);
impl_int_encodable!(i16, read_i16, emit_i16);
impl_int_encodable!(i32, read_i32, emit_i32);
impl_int_encodable!(i64, read_i64, emit_i64);

/// Returns 1 for 0..=0xFC, 3 for 0xFD..=(2^16-1), 5 for 0x10000..=(2^32-1), and 9 otherwise.
#[inline]
pub const fn varint_size_u64(v: u64) -> usize {
    match v {
        0..=0xFC => 1,
        0xFD..=0xFFFF => 3,
        0x10000..=0xFFFFFFFF => 5,
        _ => 9,
    }
}

/// Returns 1 for 0..=0xFC, 3 for 0xFD..=(2^16-1), 5 for 0x10000..=(2^32-1), and 9 otherwise.
#[inline]
pub fn varint_size(v: impl ToU64) -> usize { varint_size_u64(v.to_u64()) }

macro_rules! impl_array {
    ( $size:literal ) => {
        impl Encodable for [u8; $size] {
            #[inline]
            fn consensus_encode<W: WriteExt + ?Sized>(
                &self,
                w: &mut W,
            ) -> core::result::Result<usize, io::Error> {
                let n = w.emit_slice(&self[..])?;
                Ok(n)
            }
        }

        impl Decodable for [u8; $size] {
            #[inline]
            fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> core::result::Result<Self, Error> {
                let mut ret = [0; $size];
                r.read_slice(&mut ret)?;
                Ok(ret)
            }
        }
    };
}

impl_array!(2);
impl_array!(4);
impl_array!(6);
impl_array!(8);
impl_array!(10);
impl_array!(12);
impl_array!(16);
impl_array!(32);
impl_array!(33);

macro_rules! tuple_encode {
    ($($x:ident),*) => {
        impl <$($x: Encodable),*> Encodable for ($($x),*) {
            #[inline]
            #[allow(non_snake_case)]
            fn consensus_encode<W: Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> core::result::Result<usize, io::Error> {
                let &($(ref $x),*) = self;
                let mut len = 0;
                $(len += $x.consensus_encode(w)?;)*
                Ok(len)
            }
        }

        impl<$($x: Decodable),*> Decodable for ($($x),*) {
            #[inline]
            #[allow(non_snake_case)]
            fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> core::result::Result<Self, Error> {
                Ok(($({let $x = Decodable::consensus_decode(r)?; $x }),*))
            }
        }
    };
}

tuple_encode!(T0, T1);
tuple_encode!(T0, T1, T2);
tuple_encode!(T0, T1, T2, T3);
tuple_encode!(T0, T1, T2, T3, T4);
tuple_encode!(T0, T1, T2, T3, T4, T5);
tuple_encode!(T0, T1, T2, T3, T4, T5, T6);
tuple_encode!(T0, T1, T2, T3, T4, T5, T6, T7);

#[cfg(feature = "hex")]
struct IterReader<E: fmt::Debug, I: Iterator<Item = Result<u8, E>>> {
    iterator: core::iter::Fuse<I>,
    buf: Option<u8>,
    error: Option<E>,
}

#[cfg(feature = "hex")]
impl<E: fmt::Debug, I: Iterator<Item = Result<u8, E>>> IterReader<E, I> {
    pub(crate) fn new(iterator: I) -> Self {
        IterReader { iterator: iterator.fuse(), buf: None, error: None }
    }

    fn decode<T: Decodable>(mut self) -> Result<T, DecodeError<E>> {
        let result = T::consensus_decode(&mut self);
        match (result, self.error) {
            (Ok(_), None) if self.iterator.next().is_some() => Err(DecodeError::Unconsumed),
            (Ok(value), None) => Ok(value),
            (Ok(_), Some(error)) => panic!("{} silently ate the error: {:?}", core::any::type_name::<T>(), error),

            #[cfg(not(feature = "alloc"))]
            (Err(Error::Io(io_error)), Some(de_error)) if io_error.kind() == io::ErrorKind::Other => Err(DecodeError::Other(de_error)),
            #[cfg(feature = "alloc")]
            (Err(Error::Io(io_error)), Some(de_error)) if io_error.kind() == io::ErrorKind::Other && io_error.get_ref().is_none()=> Err(DecodeError::Other(de_error)),
            (Err(Error::Parse(parse_error)), None) => Err(DecodeError::Parse(parse_error)),
            (Err(Error::Io(io_error)), de_error) => panic!("unexpected I/O error {:?} returned from {}::consensus_decode(), deserialization error: {:?}", io_error, core::any::type_name::<T>(), de_error),
            (Err(consensus_error), Some(de_error)) => panic!("{} should've returned `Other` I/O error because of deserialization error {:?} but it returned consensus error {:?} instead", core::any::type_name::<T>(), de_error, consensus_error),
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
impl<E: fmt::Debug, I: Iterator<Item = Result<u8, E>>> Read for IterReader<E, I> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let mut count = 0;
        if buf.is_empty() {
            return Ok(0);
        }

        if let Some(first) = self.buf.take() {
            buf[0] = first;
            buf = &mut buf[1..];
            count += 1;
        }
        for (dst, src) in buf.iter_mut().zip(&mut self.iterator) {
            match src {
                Ok(byte) => *dst = byte,
                Err(error) => {
                    self.error = Some(error);
                    return Err(io::ErrorKind::Other.into());
                }
            }
            // bounded by the length of buf
            count += 1;
        }
        Ok(count)
    }
}

#[rustfmt::skip]
#[allow(unused_imports)]
mod prelude {
    #[cfg(feature = "alloc")]
    pub use alloc::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(feature = "alloc")]
    pub use alloc::{string::{String, ToString}, vec, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, slice, rc};

    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    pub use alloc::sync;
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::vec;
    #[cfg(feature = "alloc")]
    use core::mem::discriminant;

    use super::*;
    #[cfg(feature = "alloc")]
    use crate::prelude::{Cow, ToString, Vec};

    #[test]
    #[cfg(feature = "alloc")]
    fn serialize_int() {
        // bool
        assert_eq!(serialize(&false), [0u8]);
        assert_eq!(serialize(&true), [1u8]);
        // u8
        assert_eq!(serialize(&1u8), [1u8]);
        assert_eq!(serialize(&0u8), [0u8]);
        assert_eq!(serialize(&255u8), [255u8]);
        // u16
        assert_eq!(serialize(&1u16), [1u8, 0]);
        assert_eq!(serialize(&256u16), [0u8, 1]);
        assert_eq!(serialize(&5000u16), [136u8, 19]);
        // u32
        assert_eq!(serialize(&1u32), [1u8, 0, 0, 0]);
        assert_eq!(serialize(&256u32), [0u8, 1, 0, 0]);
        assert_eq!(serialize(&5000u32), [136u8, 19, 0, 0]);
        assert_eq!(serialize(&500000u32), [32u8, 161, 7, 0]);
        assert_eq!(serialize(&168430090u32), [10u8, 10, 10, 10]);
        // i32
        assert_eq!(serialize(&-1i32), [255u8, 255, 255, 255]);
        assert_eq!(serialize(&-256i32), [0u8, 255, 255, 255]);
        assert_eq!(serialize(&-5000i32), [120u8, 236, 255, 255]);
        assert_eq!(serialize(&-500000i32), [224u8, 94, 248, 255]);
        assert_eq!(serialize(&-168430090i32), [246u8, 245, 245, 245]);
        assert_eq!(serialize(&1i32), [1u8, 0, 0, 0]);
        assert_eq!(serialize(&256i32), [0u8, 1, 0, 0]);
        assert_eq!(serialize(&5000i32), [136u8, 19, 0, 0]);
        assert_eq!(serialize(&500000i32), [32u8, 161, 7, 0]);
        assert_eq!(serialize(&168430090i32), [10u8, 10, 10, 10]);
        // u64
        assert_eq!(serialize(&1u64), [1u8, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&256u64), [0u8, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&5000u64), [136u8, 19, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&500000u64), [32u8, 161, 7, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&723401728380766730u64), [10u8, 10, 10, 10, 10, 10, 10, 10]);
        // i64
        assert_eq!(serialize(&-1i64), [255u8, 255, 255, 255, 255, 255, 255, 255]);
        assert_eq!(serialize(&-256i64), [0u8, 255, 255, 255, 255, 255, 255, 255]);
        assert_eq!(serialize(&-5000i64), [120u8, 236, 255, 255, 255, 255, 255, 255]);
        assert_eq!(serialize(&-500000i64), [224u8, 94, 248, 255, 255, 255, 255, 255]);
        assert_eq!(serialize(&-723401728380766730i64), [246u8, 245, 245, 245, 245, 245, 245, 245]);
        assert_eq!(serialize(&1i64), [1u8, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&256i64), [0u8, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&5000i64), [136u8, 19, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&500000i64), [32u8, 161, 7, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&723401728380766730i64), [10u8, 10, 10, 10, 10, 10, 10, 10]);
    }

    #[cfg(feature = "alloc")]
    fn test_varint_encode(n: u8, x: &[u8]) -> Result<u64, Error> {
        let mut input = [0u8; 9];
        input[0] = n;
        input[1..x.len() + 1].copy_from_slice(x);
        (&input[..]).read_compact_size()
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn serialize_varint() {
        fn encode(v: u64) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.emit_compact_size(v).unwrap();
            buf
        }

        assert_eq!(encode(10), [10u8]);
        assert_eq!(encode(0xFC), [0xFCu8]);
        assert_eq!(encode(0xFD), [0xFDu8, 0xFD, 0]);
        assert_eq!(encode(0xFFF), [0xFDu8, 0xFF, 0xF]);
        assert_eq!(encode(0xF0F0F0F), [0xFEu8, 0xF, 0xF, 0xF, 0xF]);
        assert_eq!(encode(0xF0F0F0F0F0E0), vec![0xFFu8, 0xE0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0, 0],);
        assert_eq!(test_varint_encode(0xFF, &0x100000000_u64.to_le_bytes()).unwrap(), 0x100000000,);
        assert_eq!(test_varint_encode(0xFE, &0x10000_u64.to_le_bytes()).unwrap(), 0x10000);
        assert_eq!(test_varint_encode(0xFD, &0xFD_u64.to_le_bytes()).unwrap(), 0xFD);

        // Test that length calc is working correctly
        fn test_varint_len(varint: u64, expected: usize) {
            let mut encoder = vec![];
            assert_eq!(encoder.emit_compact_size(varint).unwrap(), expected);
            assert_eq!(varint_size(varint), expected);
        }
        test_varint_len(0, 1);
        test_varint_len(0xFC, 1);
        test_varint_len(0xFD, 3);
        test_varint_len(0xFFFF, 3);
        test_varint_len(0x10000, 5);
        test_varint_len(0xFFFFFFFF, 5);
        test_varint_len(0xFFFFFFFF + 1, 9);
        test_varint_len(u64::MAX, 9);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn deserialize_nonminimal_vec() {
        // Check the edges for variant int
        assert_eq!(
            discriminant(
                &test_varint_encode(0xFF, &(0x100000000_u64 - 1).to_le_bytes()).unwrap_err()
            ),
            discriminant(&ParseError::NonMinimalCompactSize.into())
        );
        assert_eq!(
            discriminant(&test_varint_encode(0xFE, &(0x10000_u64 - 1).to_le_bytes()).unwrap_err()),
            discriminant(&ParseError::NonMinimalCompactSize.into())
        );
        assert_eq!(
            discriminant(&test_varint_encode(0xFD, &(0xFD_u64 - 1).to_le_bytes()).unwrap_err()),
            discriminant(&ParseError::NonMinimalCompactSize.into())
        );

        assert_eq!(
            discriminant(&deserialize::<Vec<u8>>(&[0xfd, 0x00, 0x00]).unwrap_err()),
            discriminant(&ParseError::NonMinimalCompactSize.into())
        );
        assert_eq!(
            discriminant(&deserialize::<Vec<u8>>(&[0xfd, 0xfc, 0x00]).unwrap_err()),
            discriminant(&ParseError::NonMinimalCompactSize.into())
        );
        assert_eq!(
            discriminant(&deserialize::<Vec<u8>>(&[0xfd, 0xfc, 0x00]).unwrap_err()),
            discriminant(&ParseError::NonMinimalCompactSize.into())
        );
        assert_eq!(
            discriminant(&deserialize::<Vec<u8>>(&[0xfe, 0xff, 0x00, 0x00, 0x00]).unwrap_err()),
            discriminant(&ParseError::NonMinimalCompactSize.into())
        );
        assert_eq!(
            discriminant(&deserialize::<Vec<u8>>(&[0xfe, 0xff, 0xff, 0x00, 0x00]).unwrap_err()),
            discriminant(&ParseError::NonMinimalCompactSize.into())
        );
        assert_eq!(
            discriminant(
                &deserialize::<Vec<u8>>(&[0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                    .unwrap_err()
            ),
            discriminant(&ParseError::NonMinimalCompactSize.into())
        );
        assert_eq!(
            discriminant(
                &deserialize::<Vec<u8>>(&[0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00])
                    .unwrap_err()
            ),
            discriminant(&ParseError::NonMinimalCompactSize.into())
        );

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
    #[cfg(feature = "alloc")]
    fn serialize_vector() {
        assert_eq!(serialize(&vec![1u8, 2, 3]), [3u8, 1, 2, 3]);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn serialize_strbuf() {
        assert_eq!(serialize(&"Andrew".to_string()), [6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]);
    }

    #[test]
    fn deserialize_int() {
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

        // i16
        assert_eq!(deserialize(&[0x32_u8, 0xF4]).ok(), Some(-0x0bce_i16));
        assert_eq!(deserialize(&[0xFF_u8, 0xFE]).ok(), Some(-0x0101_i16));
        assert_eq!(deserialize(&[0x00_u8, 0x00]).ok(), Some(-0_i16));
        assert_eq!(deserialize(&[0xFF_u8, 0xFA]).ok(), Some(-0x0501_i16));

        // u32
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0]).ok(), Some(0xCDABu32));
        assert_eq!(deserialize(&[0xA0u8, 0x0D, 0xAB, 0xCD]).ok(), Some(0xCDAB0DA0u32));

        let failure32: Result<u32, _> = deserialize(&[1u8, 2, 3]);
        assert!(failure32.is_err());

        // i32
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0]).ok(), Some(0xCDABi32));
        assert_eq!(deserialize(&[0xA0u8, 0x0D, 0xAB, 0x2D]).ok(), Some(0x2DAB0DA0i32));

        assert_eq!(deserialize(&[0, 0, 0, 0]).ok(), Some(-0_i32));
        assert_eq!(deserialize(&[0, 0, 0, 0]).ok(), Some(0_i32));

        assert_eq!(deserialize(&[0xFF, 0xFF, 0xFF, 0xFF]).ok(), Some(-1_i32));
        assert_eq!(deserialize(&[0xFE, 0xFF, 0xFF, 0xFF]).ok(), Some(-2_i32));
        assert_eq!(deserialize(&[0x01, 0xFF, 0xFF, 0xFF]).ok(), Some(-255_i32));
        assert_eq!(deserialize(&[0x02, 0xFF, 0xFF, 0xFF]).ok(), Some(-254_i32));

        let failurei32: Result<i32, _> = deserialize(&[1u8, 2, 3]);
        assert!(failurei32.is_err());

        // u64
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0, 0, 0, 0, 0]).ok(), Some(0xCDABu64));
        assert_eq!(
            deserialize(&[0xA0u8, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99]).ok(),
            Some(0x99000099CDAB0DA0u64)
        );
        let failure64: Result<u64, _> = deserialize(&[1u8, 2, 3, 4, 5, 6, 7]);
        assert!(failure64.is_err());

        // i64
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0, 0, 0, 0, 0]).ok(), Some(0xCDABi64));
        assert_eq!(
            deserialize(&[0xA0u8, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99]).ok(),
            Some(-0x66ffff663254f260i64)
        );
        assert_eq!(
            deserialize(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).ok(),
            Some(-1_i64)
        );
        assert_eq!(
            deserialize(&[0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).ok(),
            Some(-2_i64)
        );
        assert_eq!(
            deserialize(&[0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).ok(),
            Some(-255_i64)
        );
        assert_eq!(
            deserialize(&[0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).ok(),
            Some(-254_i64)
        );

        let failurei64: Result<i64, _> = deserialize(&[1u8, 2, 3, 4, 5, 6, 7]);
        assert!(failurei64.is_err());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn deserialize_strbuf() {
        assert_eq!(
            deserialize(&[6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]).ok(),
            Some("Andrew".to_string())
        );
        assert_eq!(
            deserialize(&[6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]).ok(),
            Some(Cow::Borrowed("Andrew"))
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn limit_read() {
        let witness = vec![vec![0u8; 3_999_999]; 2];
        let ser = serialize(&witness);
        let mut reader = io::Cursor::new(ser);
        let err = Vec::<Vec<u8>>::consensus_decode(&mut reader);
        assert!(err.is_err());
    }

    #[test]
    #[cfg(feature = "alloc")]
    // TODO: The rand dependency adds a bunch to the lock files, can we remove it?
    fn serialization_round_trips() {
        use rand::Rng;

        macro_rules! round_trip {
            ($($val_type:ty),*) => {
                $(
                    let r: $val_type = rand::rng().random();
                    assert_eq!(deserialize::<$val_type>(&serialize(&r)).unwrap(), r);
                )*
            };
        }
        macro_rules! round_trip_bytes {
            ($(($val_type:ty, $data:expr)),*) => {
                $(
                    rand::rng().fill(&mut $data[..]);
                    assert_eq!(deserialize::<$val_type>(&serialize(&$data)).unwrap()[..], $data[..]);
                )*
            };
        }

        let mut data = Vec::with_capacity(256);
        let mut data64 = Vec::with_capacity(256);
        for _ in 0..10 {
            round_trip! {bool, i8, u8, i16, u16, i32, u32, i64, u64,
            (bool, i8, u16, i32), (u64, i64, u32, i32, u16, i16), (i8, u8, i16, u16, i32, u32, i64, u64),
            [u8; 2], [u8; 4], [u8; 8], [u8; 12], [u8; 16], [u8; 32]};

            data.clear();
            data64.clear();
            let len = rand::rng().random_range(1..256);
            data.resize(len, 0u8);
            data64.resize(len, 0u64);
            let mut arr33 = [0u8; 33];
            let mut arr16 = [0u16; 8];
            round_trip_bytes! {(Vec<u8>, data), ([u8; 33], arr33), ([u16; 8], arr16), (Vec<u64>, data64)};
        }
    }
}
