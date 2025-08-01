// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus decoding.

#[cfg(feature = "alloc")]
use core::any::TypeId;
#[cfg(feature = "alloc")]
use core::{cmp, mem};

use internals::ToU64 as _;
use io::{self, Read};

#[cfg(feature = "alloc")]
use crate::prelude::{vec, Box, Cow, String, Vec};
use crate::Error;
#[cfg(feature = "alloc")]
use crate::{error, ParseError};

/// Maximum size, in bytes, of a vector we are allowed to decode.
pub const MAX_VEC_SIZE: usize = 4_000_000;

/// Data which can be encoded in a consensus-consistent way.
pub trait Decodable: Sized {
    /// Decode `Self` from a size-limited reader.
    ///
    /// Like `consensus_decode` but relies on the reader being limited in the amount of data it
    /// returns, e.g. by being wrapped in [`std::io::Take`].
    ///
    /// Failing to abide to this requirement might lead to memory exhaustion caused by malicious
    /// inputs.
    ///
    /// Users should default to `consensus_decode`, but when data to be decoded is already in a byte
    /// vector of a limited size, calling this function directly might be marginally faster (due to
    /// avoiding extra checks).
    ///
    /// # Rules for trait implementations
    ///
    /// * Simple types that have a fixed size (own and member fields), don't have to overwrite
    ///   this method, or be concern with it.
    /// * Types that deserialize using externally provided length should implement it:
    ///   * Make `consensus_decode` forward to `consensus_decode_bytes_from_finite_reader` with the
    ///     reader wrapped by `Take`. Failure to do so, without other forms of memory exhaustion
    ///     protection might lead to resource exhaustion vulnerability.
    ///   * Put a max cap on things like `Vec::with_capacity` to avoid oversized allocations, and
    ///     rely on the reader running out of data, and collections reallocating on a legitimately
    ///     oversized input data, instead of trying to enforce arbitrary length limits.
    /// * Types that contain other types that implement custom
    ///   `consensus_decode_from_finite_reader`, should also implement it applying same rules, and
    ///   in addition make sure to call `consensus_decode_from_finite_reader` on all members, to
    ///   avoid creating redundant `Take` wrappers. Failure to do so might result only in a tiny
    ///   performance hit.
    #[inline]
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, Error> {
        // This method is always strictly less general than, `consensus_decode`, so it's safe and
        // make sense to default to just calling it. This way most types, that don't care about
        // protecting against resource exhaustion due to malicious input, can just ignore it.
        Self::consensus_decode(reader)
    }

    /// Decode an object with a well-defined format.
    ///
    /// This is the method that should be implemented for a typical, fixed sized type
    /// implementing this trait. Default implementation is wrapping the reader
    /// in [`bitcoin_io::Take`] to limit the input size to [`MAX_VEC_SIZE`], and forwards the call to
    /// [`Self::consensus_decode_from_finite_reader`], which is convenient
    /// for types that override [`Self::consensus_decode_from_finite_reader`]
    /// instead.
    #[inline]
    fn consensus_decode<R: Read + ?Sized>(reader: &mut R) -> Result<Self, Error> {
        Self::consensus_decode_from_finite_reader(&mut reader.take(MAX_VEC_SIZE.to_u64()))
    }
}

/// Extensions of `Read` to decode data as per Bitcoin consensus.
pub trait ReadExt: Read {
    /// Reads a 64-bit unsigned integer.
    fn read_u64(&mut self) -> Result<u64, Error>;
    /// Reads a 32-bit unsigned integer.
    fn read_u32(&mut self) -> Result<u32, Error>;
    /// Reads a 16-bit unsigned integer.
    fn read_u16(&mut self) -> Result<u16, Error>;
    /// Reads an 8-bit unsigned integer.
    fn read_u8(&mut self) -> Result<u8, Error>;

    /// Reads a 64-bit signed integer.
    fn read_i64(&mut self) -> Result<i64, Error>;
    /// Reads a 32-bit signed integer.
    fn read_i32(&mut self) -> Result<i32, Error>;
    /// Reads a 16-bit signed integer.
    fn read_i16(&mut self) -> Result<i16, Error>;
    /// Reads an 8-bit signed integer.
    fn read_i8(&mut self) -> Result<i8, Error>;

    /// Reads a variable sized integer ([`CompactSize`]).
    ///
    /// [`CompactSize`]: <https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer>
    #[cfg(feature = "alloc")]
    fn read_compact_size(&mut self) -> Result<u64, Error>;

    /// Reads a boolean.
    fn read_bool(&mut self) -> Result<bool, Error>;

    /// Reads a byte slice.
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), Error>;
}

macro_rules! decoder_fn {
    ($name:ident, $val_type:ty, $byte_len: expr) => {
        #[inline]
        fn $name(&mut self) -> core::result::Result<$val_type, Error> {
            let mut val = [0; $byte_len];
            self.read_exact(&mut val[..])?;
            Ok(<$val_type>::from_le_bytes(val))
        }
    };
}

impl<R: Read + ?Sized> ReadExt for R {
    decoder_fn!(read_u64, u64, 8);
    decoder_fn!(read_u32, u32, 4);
    decoder_fn!(read_u16, u16, 2);
    decoder_fn!(read_i64, i64, 8);
    decoder_fn!(read_i32, i32, 4);
    decoder_fn!(read_i16, i16, 2);

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
    fn read_bool(&mut self) -> Result<bool, Error> { ReadExt::read_i8(self).map(|bit| bit != 0) }
    #[inline]
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), Error> { Ok(self.read_exact(slice)?) }
    #[inline]
    #[rustfmt::skip] // Formatter munges code comments below.
    #[cfg(feature = "alloc")]
    fn read_compact_size(&mut self) -> Result<u64, Error> {
        match self.read_u8()? {
            0xFF => {
                let x = self.read_u64()?;
                if x < 0x1_0000_0000 { // I.e., would have fit in a `u32`.
                    Err(ParseError::NonMinimalCompactSize.into())
                } else {
                    Ok(x)
                }
            }
            0xFE => {
                let x = self.read_u32()?;
                if x < 0x1_0000 { // I.e., would have fit in a `u16`.
                    Err(ParseError::NonMinimalCompactSize.into())
                } else {
                    Ok(x as u64)
                }
            }
            0xFD => {
                let x = self.read_u16()?;
                if x < 0xFD {   // Could have been encoded as a `u8`.
                    Err(ParseError::NonMinimalCompactSize.into())
                } else {
                    Ok(x as u64)
                }
            }
            n => Ok(n as u64),
        }
    }
}

impl Decodable for bool {
    #[inline]
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<bool, Error> {
        ReadExt::read_bool(r)
    }
}

#[cfg(feature = "alloc")]
impl Decodable for String {
    #[inline]
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<String, Error> {
        String::from_utf8(Decodable::consensus_decode(r)?)
            .map_err(|_| error::parse_failed_error("String was not valid UTF8"))
    }
}

#[cfg(feature = "alloc")]
impl Decodable for Cow<'static, str> {
    #[inline]
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Cow<'static, str>, Error> {
        String::from_utf8(Decodable::consensus_decode(r)?)
            .map_err(|_| error::parse_failed_error("String was not valid UTF8"))
            .map(Cow::Owned)
    }
}

impl Decodable for [u16; 8] {
    #[inline]
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let mut res = [0; 8];
        for item in &mut res {
            *item = Decodable::consensus_decode(r)?;
        }
        Ok(res)
    }
}

#[cfg(feature = "alloc")]
impl<T: Decodable + 'static> Decodable for Vec<T> {
    #[inline]
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(r: &mut R) -> Result<Vec<T>, Error> {
        if TypeId::of::<T>() == TypeId::of::<u8>() {
            let len = r.read_compact_size()? as usize;
            // most real-world vec of bytes data, wouldn't be larger than 128KiB
            let opts = ReadBytesFromFiniteReaderOpts { len, chunk_size: 128 * 1024 };
            let bytes = read_bytes_from_finite_reader(r, opts)?;

            let len = bytes.len();
            let capacity = bytes.capacity();
            let ptr = bytes.as_ptr();

            // Prevent the original Vec<u8> from being dropped.
            mem::forget(bytes);

            // Safe because `T` is a `u8`.
            unsafe { Ok(Vec::from_raw_parts(ptr as *mut T, len, capacity)) }
        } else {
            let len = r.read_compact_size()?;
            // Do not allocate upfront more items than if the sequence of type
            // occupied roughly quarter a block. This should never be the case
            // for normal data, but even if that's not true - `push` will just
            // reallocate.
            // Note: OOM protection relies on reader eventually running out of
            // data to feed us.
            let max_capacity = MAX_VEC_SIZE / 4 / mem::size_of::<T>();
            let mut ret = Vec::with_capacity(cmp::min(len as usize, max_capacity));
            for _ in 0..len {
                ret.push(Decodable::consensus_decode_from_finite_reader(r)?);
            }
            Ok(ret)
        }
    }
}

#[cfg(feature = "alloc")]
impl Decodable for Box<[u8]> {
    #[inline]
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        <Vec<u8>>::consensus_decode_from_finite_reader(r).map(From::from)
    }
}

// Duplicate of `bitcoin::consensus::encode::ReadBytesFromFiniteReaderOpts`.
#[cfg(feature = "alloc")]
struct ReadBytesFromFiniteReaderOpts {
    len: usize,
    chunk_size: usize,
}

/// Read `opts.len` bytes from reader, where `opts.len` could potentially be malicious.
///
/// This function relies on reader being bound in amount of data
/// it returns for OOM protection. See [`Decodable::consensus_decode_from_finite_reader`].
#[inline]
#[cfg(feature = "alloc")]
fn read_bytes_from_finite_reader<D: Read + ?Sized>(
    d: &mut D,
    mut opts: ReadBytesFromFiniteReaderOpts,
) -> Result<Vec<u8>, Error> {
    let mut ret = vec![];

    assert_ne!(opts.chunk_size, 0);

    while opts.len > 0 {
        let chunk_start = ret.len();
        let chunk_size = core::cmp::min(opts.len, opts.chunk_size);
        let chunk_end = chunk_start + chunk_size;
        ret.resize(chunk_end, 0u8);
        d.read_slice(&mut ret[chunk_start..chunk_end])?;
        opts.len -= chunk_size;
    }

    Ok(ret)
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;

    #[test]
    fn test_read_bytes_from_finite_reader() {
        let data: Vec<u8> = (0..10).collect();

        for chunk_size in 1..20 {
            assert_eq!(
                read_bytes_from_finite_reader(
                    &mut io::Cursor::new(&data),
                    ReadBytesFromFiniteReaderOpts { len: data.len(), chunk_size }
                )
                .unwrap(),
                data
            );
        }
    }
}
