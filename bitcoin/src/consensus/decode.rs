// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus decoding.

use core::convert::From;
use core::fmt;

use internals::write_err;

use crate::io::{self, Read};
use crate::prelude::*;

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
    /// ### Rules for trait implementations
    ///
    /// * Simple types that that have a fixed size (own and member fields), don't have to overwrite
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
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
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
    /// in [`crate::io::Take`] to limit the input size to [`MAX_VEC_SIZE`], and forwards the call to
    /// [`Self::consensus_decode_from_finite_reader`], which is convenient
    /// for types that override [`Self::consensus_decode_from_finite_reader`]
    /// instead.
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, Error> {
        Self::consensus_decode_from_finite_reader(reader.take(MAX_VEC_SIZE as u64).by_ref())
    }
}

/// Extensions of `Read` to decode data as per Bitcoin consensus.
pub trait ReadExt: io::Read {
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

    /// Reads a boolean.
    fn read_bool(&mut self) -> Result<bool, Error>;

    /// Reads a byte slice.
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), Error>;
}

macro_rules! decoder_fn {
    ($name:ident, $val_type:ty, $byte_len: expr) => {
        #[inline]
        fn $name(&mut self) -> Result<$val_type, Error> {
            let mut val = [0; $byte_len];
            self.read_exact(&mut val[..]).map_err(Error::Io)?;
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
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), Error> {
        self.read_exact(slice).map_err(Error::Io)
    }
}

/// A decoding error.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// And I/O error.
    Io(io::Error),
    /// Tried to allocate an oversized vector.
    OversizedVectorAllocation {
        /// The capacity requested.
        requested: usize,
        /// The maximum capacity.
        max: usize,
    },
    /// Checksum was invalid.
    InvalidChecksum {
        /// The expected checksum.
        expected: [u8; 4],
        /// The invalid checksum.
        actual: [u8; 4],
    },
    /// VarInt was encoded in a non-minimal way.
    NonMinimalVarInt,
    /// Parsing error.
    ParseFailed(&'static str),
    /// Unsupported Segwit flag.
    UnsupportedSegwitFlag(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => write_err!(f, "IO error"; e),
            Error::OversizedVectorAllocation { requested: ref r, max: ref m } =>
                write!(f, "allocation of oversized vector: requested {}, maximum {}", r, m),
            Error::InvalidChecksum { expected: ref e, actual: ref a } =>
                write!(f, "invalid checksum: expected {:x}, actual {:x}", e.as_hex(), a.as_hex()),
            Error::NonMinimalVarInt => write!(f, "non-minimal varint"),
            Error::ParseFailed(ref s) => write!(f, "parse failed: {}", s),
            Error::UnsupportedSegwitFlag(ref swflag) =>
                write!(f, "unsupported segwit version: {}", swflag),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            Io(e) => Some(e),
            OversizedVectorAllocation { .. }
            | InvalidChecksum { .. }
            | NonMinimalVarInt
            | ParseFailed(_)
            | UnsupportedSegwitFlag(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self { Error::Io(error) }
}
