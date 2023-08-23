// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus types.
//!
//! Types provided solely for the purpose of consensus encoding/decoding.

use core::convert::TryFrom;

use hashes::{sha256d, Hash};

use crate::consensus::decode::{
    self, Decodable, ReadBytesFromFiniteReaderOpts, ReadExt, MAX_VEC_SIZE,
};
use crate::consensus::encode::{Encodable, WriteExt};
use crate::io;
use crate::prelude::*;

/// A variable-length unsigned integer.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct VarInt(pub u64);

#[allow(clippy::len_without_is_empty)] // VarInt has on concept of 'is_empty'.
impl VarInt {
    /// Returns the number of bytes this varint contributes to a transaction size.
    ///
    /// Returns 1 for 0..=0xFC, 3 for 0xFD..=(2^16-1), 5 for 0x10000..=(2^32-1), and 9 otherwise.
    #[inline]
    pub const fn size(&self) -> usize {
        match self.0 {
            0..=0xFC => 1,
            0xFD..=0xFFFF => 3,
            0x10000..=0xFFFFFFFF => 5,
            _ => 9,
        }
    }
}

/// Implements `From<T> for VarInt`.
///
/// `VarInt`s are consensus encoded as `u64`s so we store them as such. Casting from any integer size smaller than or equal to `u64` is always safe and the cast value is correctly handled by `consensus_encode`.
macro_rules! impl_var_int_from {
    ($($ty:tt),*) => {
        $(
            /// Creates a `VarInt` from a `usize` by casting the to a `u64`.
            impl From<$ty> for VarInt {
                fn from(x: $ty) -> Self { VarInt(x as u64) }
            }
        )*
    }
}
impl_var_int_from!(u8, u16, u32, u64, usize);

impl Encodable for VarInt {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        match self.0 {
            0..=0xFC => {
                (self.0 as u8).consensus_encode(w)?;
                Ok(1)
            }
            0xFD..=0xFFFF => {
                w.emit_u8(0xFD)?;
                (self.0 as u16).consensus_encode(w)?;
                Ok(3)
            }
            0x10000..=0xFFFFFFFF => {
                w.emit_u8(0xFE)?;
                (self.0 as u32).consensus_encode(w)?;
                Ok(5)
            }
            _ => {
                w.emit_u8(0xFF)?;
                self.0.consensus_encode(w)?;
                Ok(9)
            }
        }
    }
}

impl Decodable for VarInt {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, decode::Error> {
        let n = ReadExt::read_u8(r)?;
        match n {
            0xFF => {
                let x = ReadExt::read_u64(r)?;
                if x < 0x100000000 {
                    Err(decode::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt(x))
                }
            }
            0xFE => {
                let x = ReadExt::read_u32(r)?;
                if x < 0x10000 {
                    Err(decode::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt(x as u64))
                }
            }
            0xFD => {
                let x = ReadExt::read_u16(r)?;
                if x < 0xFD {
                    Err(decode::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt(x as u64))
                }
            }
            n => Ok(VarInt(n as u64)),
        }
    }
}

/// Data and a 4-byte checksum.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CheckedData {
    data: Vec<u8>,
    checksum: [u8; 4],
}

impl CheckedData {
    /// Creates a new `CheckedData` computing the checksum of given data.
    pub fn new(data: Vec<u8>) -> Self {
        let checksum = sha2_checksum(&data);
        Self { data, checksum }
    }

    /// Returns a reference to the raw data without the checksum.
    pub fn data(&self) -> &[u8] { &self.data }

    /// Returns the raw data without the checksum.
    pub fn into_data(self) -> Vec<u8> { self.data }

    /// Returns the checksum of the data.
    pub fn checksum(&self) -> [u8; 4] { self.checksum }
}

impl Encodable for CheckedData {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        u32::try_from(self.data.len())
            .expect("network message use u32 as length")
            .consensus_encode(w)?;
        self.checksum().consensus_encode(w)?;
        w.emit_slice(&self.data)?;
        Ok(8 + self.data.len())
    }
}

impl Decodable for CheckedData {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, decode::Error> {
        let len = u32::consensus_decode_from_finite_reader(r)? as usize;

        let checksum = <[u8; 4]>::consensus_decode_from_finite_reader(r)?;
        let opts = ReadBytesFromFiniteReaderOpts { len, chunk_size: MAX_VEC_SIZE };
        let data = decode::read_bytes_from_finite_reader(r, opts)?;
        let expected_checksum = sha2_checksum(&data);
        if expected_checksum != checksum {
            Err(decode::Error::InvalidChecksum { expected: expected_checksum, actual: checksum })
        } else {
            Ok(CheckedData { data, checksum })
        }
    }
}

/// Does a double-SHA256 on `data` and returns the first 4 bytes.
fn sha2_checksum(data: &[u8]) -> [u8; 4] {
    let checksum = <sha256d::Hash as Hash>::hash(data);
    [checksum[0], checksum[1], checksum[2], checksum[3]]
}
