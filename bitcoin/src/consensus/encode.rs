// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus-encodable types.
//!
//! This is basically a replacement of the `Encodable` trait which does
//! normalization of endianness etc., to ensure that the encoding matches
//! the network consensus encoding.
//!
//! Essentially, anything that must go on the _disk_ or _network_ must be
//! encoded using the `Encodable` trait, since this data must be the same for
//! all systems. Any data going to the _user_ e.g., over JSONRPC, should use the
//! ordinary `Encodable` trait. (This should also be the same across systems, of
//! course, but has some critical differences from the network format e.g.,
//! scripts come with an opcode decode, hashes are big-endian, numbers are
//! typically big-endian decimals, etc.)
//!

// TODO(Tobin): Remove this re-export once consensus refactor is done.
pub use crate::consensus::decode::{Decodable, Error, ReadExt, MAX_VEC_SIZE};
// TODO(Tobin): Remove this re-export once consensus refactor is done.
pub use crate::consensus::types::{CheckedData, VarInt};
// TODO(Tobin): Remove this re-export once consensus refactor is done.
pub use crate::consensus::{deserialize, deserialize_partial, serialize, serialize_hex};
use crate::io;

/// Data which can be encoded in a consensus-consistent way.
pub trait Encodable {
    /// Encodes an object with a well-defined format.
    ///
    /// # Returns
    ///
    /// The number of bytes written on success. The only errors returned are errors propagated from
    /// the writer.
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error>;
}

/// Extensions of `Write` to encode data as per Bitcoin consensus.
pub trait WriteExt: io::Write {
    /// Outputs a 64-bit unsigned integer.
    fn emit_u64(&mut self, v: u64) -> Result<(), io::Error>;
    /// Outputs a 32-bit unsigned integer.
    fn emit_u32(&mut self, v: u32) -> Result<(), io::Error>;
    /// Outputs a 16-bit unsigned integer.
    fn emit_u16(&mut self, v: u16) -> Result<(), io::Error>;
    /// Outputs an 8-bit unsigned integer.
    fn emit_u8(&mut self, v: u8) -> Result<(), io::Error>;

    /// Outputs a 64-bit signed integer.
    fn emit_i64(&mut self, v: i64) -> Result<(), io::Error>;
    /// Outputs a 32-bit signed integer.
    fn emit_i32(&mut self, v: i32) -> Result<(), io::Error>;
    /// Outputs a 16-bit signed integer.
    fn emit_i16(&mut self, v: i16) -> Result<(), io::Error>;
    /// Outputs an 8-bit signed integer.
    fn emit_i8(&mut self, v: i8) -> Result<(), io::Error>;

    /// Outputs a boolean.
    fn emit_bool(&mut self, v: bool) -> Result<(), io::Error>;

    /// Outputs a byte slice.
    fn emit_slice(&mut self, v: &[u8]) -> Result<(), io::Error>;
}

macro_rules! encoder_fn {
    ($name:ident, $val_type:ty) => {
        #[inline]
        fn $name(&mut self, v: $val_type) -> Result<(), io::Error> {
            self.write_all(&v.to_le_bytes())
        }
    };
}

impl<W: io::Write + ?Sized> WriteExt for W {
    encoder_fn!(emit_u64, u64);
    encoder_fn!(emit_u32, u32);
    encoder_fn!(emit_u16, u16);
    encoder_fn!(emit_i64, i64);
    encoder_fn!(emit_i32, i32);
    encoder_fn!(emit_i16, i16);

    #[inline]
    fn emit_i8(&mut self, v: i8) -> Result<(), io::Error> { self.write_all(&[v as u8]) }
    #[inline]
    fn emit_u8(&mut self, v: u8) -> Result<(), io::Error> { self.write_all(&[v]) }
    #[inline]
    fn emit_bool(&mut self, v: bool) -> Result<(), io::Error> { self.write_all(&[v as u8]) }
    #[inline]
    fn emit_slice(&mut self, v: &[u8]) -> Result<(), io::Error> { self.write_all(v) }
}

pub(crate) fn consensus_encode_with_size<W: io::Write>(
    data: &[u8],
    mut w: W,
) -> Result<usize, io::Error> {
    let vi_len = VarInt(data.len() as u64).consensus_encode(&mut w)?;
    w.emit_slice(data)?;
    Ok(vi_len + data.len())
}
