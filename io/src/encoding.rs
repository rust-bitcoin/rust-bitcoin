// SPDX-License-Identifier: CC0-1.0

//! Consensus encoding support for I/O readers and writers.

use encoding::{Encodable, Encoder as _};
use internals::{compact_size, ToU64};

use super::{Error, Read, Result, Write};

/// Consensus encodes an object to an I/O writer.
///
/// # Performance
///
/// This method writes data in potentially small chunks based on the encoder's
/// internal chunking strategy. For optimal performance with unbuffered writers
/// (like [`std::fs::File`] or [`std::net::TcpStream`]), consider wrapping your
/// writer with [`std::io::BufWriter`].
///
/// # Errors
///
/// Returns any I/O error encountered while writing to the writer.
pub fn consensus_encode_to_writer<T, W>(object: &T, writer: &mut W) -> Result<()>
where
    T: Encodable + ?Sized,
    W: Write + ?Sized,
{
    let mut encoder = object.encoder();
    loop {
        writer.write_all(encoder.current_chunk())?;
        if !encoder.advance() {
            break;
        }
    }
    Ok(())
}

/// Extensions of `Write` to encode data as per Bitcoin consensus.
pub trait WriteExt: Write {
    /// Outputs a 64-bit unsigned integer.
    fn emit_u64(&mut self, v: u64) -> Result<()>;
    /// Outputs a 32-bit unsigned integer.
    fn emit_u32(&mut self, v: u32) -> Result<()>;
    /// Outputs a 16-bit unsigned integer.
    fn emit_u16(&mut self, v: u16) -> Result<()>;
    /// Outputs an 8-bit unsigned integer.
    fn emit_u8(&mut self, v: u8) -> Result<()>;

    /// Outputs a 64-bit signed integer.
    fn emit_i64(&mut self, v: i64) -> Result<()>;
    /// Outputs a 32-bit signed integer.
    fn emit_i32(&mut self, v: i32) -> Result<()>;
    /// Outputs a 16-bit signed integer.
    fn emit_i16(&mut self, v: i16) -> Result<()>;
    /// Outputs an 8-bit signed integer.
    fn emit_i8(&mut self, v: i8) -> Result<()>;

    /// Outputs a variable sized integer ([`CompactSize`]).
    ///
    /// [`CompactSize`]: <https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer>
    fn emit_compact_size(&mut self, v: impl ToU64) -> Result<usize>;

    /// Outputs a boolean.
    fn emit_bool(&mut self, v: bool) -> Result<()>;

    /// Outputs a byte slice.
    fn emit_slice(&mut self, v: &[u8]) -> Result<usize>;
}

/// Extensions of `Read` to decode data as per Bitcoin consensus.
pub trait ReadExt: Read {
    /// Reads a 64-bit unsigned integer.
    fn read_u64(&mut self) -> Result<u64>;
    /// Reads a 32-bit unsigned integer.
    fn read_u32(&mut self) -> Result<u32>;
    /// Reads a 16-bit unsigned integer.
    fn read_u16(&mut self) -> Result<u16>;
    /// Reads an 8-bit unsigned integer.
    fn read_u8(&mut self) -> Result<u8>;

    /// Reads a 64-bit signed integer.
    fn read_i64(&mut self) -> Result<i64>;
    /// Reads a 32-bit signed integer.
    fn read_i32(&mut self) -> Result<i32>;
    /// Reads a 16-bit signed integer.
    fn read_i16(&mut self) -> Result<i16>;
    /// Reads an 8-bit signed integer.
    fn read_i8(&mut self) -> Result<i8>;

    /// Reads a variable sized integer ([`CompactSize`]).
    ///
    /// [`CompactSize`]: <https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer>
    fn read_compact_size(&mut self) -> Result<u64>;

    /// Reads a boolean.
    fn read_bool(&mut self) -> Result<bool>;

    /// Reads a byte slice.
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<()>;
}

macro_rules! encoder_fn {
    ($name:ident, $val_type:ty) => {
        #[inline]
        fn $name(&mut self, v: $val_type) -> Result<()> {
            self.write_all(&v.to_le_bytes())
        }
    };
}

macro_rules! decoder_fn {
    ($name:ident, $val_type:ty, $byte_len: expr) => {
        #[inline]
        fn $name(&mut self) -> Result<$val_type> {
            let mut val = [0; $byte_len];
            self.read_exact(&mut val[..])?;
            Ok(<$val_type>::from_le_bytes(val))
        }
    };
}

impl<W: Write + ?Sized> WriteExt for W {
    encoder_fn!(emit_u64, u64);
    encoder_fn!(emit_u32, u32);
    encoder_fn!(emit_u16, u16);
    encoder_fn!(emit_i64, i64);
    encoder_fn!(emit_i32, i32);
    encoder_fn!(emit_i16, i16);

    #[inline]
    fn emit_i8(&mut self, v: i8) -> Result<()> { self.write_all(&[v as u8]) }
    #[inline]
    fn emit_u8(&mut self, v: u8) -> Result<()> { self.write_all(&[v]) }
    #[inline]
    fn emit_bool(&mut self, v: bool) -> Result<()> { self.write_all(&[v as u8]) }
    #[inline]
    fn emit_slice(&mut self, v: &[u8]) -> Result<usize> {
        self.write_all(v)?;
        Ok(v.len())
    }
    #[inline]
    fn emit_compact_size(&mut self, v: impl ToU64) -> Result<usize> {
        let encoded = compact_size::encode(v.to_u64());
        self.emit_slice(&encoded)?;
        Ok(encoded.len())
    }
}

impl<R: Read + ?Sized> ReadExt for R {
    decoder_fn!(read_u64, u64, 8);
    decoder_fn!(read_u32, u32, 4);
    decoder_fn!(read_u16, u16, 2);
    decoder_fn!(read_i64, i64, 8);
    decoder_fn!(read_i32, i32, 4);
    decoder_fn!(read_i16, i16, 2);

    #[inline]
    fn read_u8(&mut self) -> Result<u8> {
        let mut slice = [0u8; 1];
        self.read_exact(&mut slice)?;
        Ok(slice[0])
    }
    #[inline]
    fn read_i8(&mut self) -> Result<i8> {
        let mut slice = [0u8; 1];
        self.read_exact(&mut slice)?;
        Ok(slice[0] as i8)
    }
    #[inline]
    fn read_bool(&mut self) -> Result<bool> { ReadExt::read_i8(self).map(|bit| bit != 0) }
    #[inline]
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<()> { Ok(self.read_exact(slice)?) }
    #[inline]
    #[rustfmt::skip] // Formatter munges code comments below.
    fn read_compact_size(&mut self) -> Result<u64> {
        match self.read_u8()? {
            0xFF => {
                let x = self.read_u64()?;
                if x < 0x1_0000_0000 { // I.e., would have fit in a `u32`.
                    Err(NonMinimalCompactSize.into())
                } else {
                    Ok(x)
                }
            }
            0xFE => {
                let x = self.read_u32()?;
                if x < 0x1_0000 { // I.e., would have fit in a `u16`.
                    Err(NonMinimalCompactSize.into())
                } else {
                    Ok(x as u64)
                }
            }
            0xFD => {
                let x = self.read_u16()?;
                if x < 0xFD {   // Could have been encoded as a `u8`.
                    Err(NonMinimalCompactSize.into())
                } else {
                    Ok(x as u64)
                }
            }
            n => Ok(n as u64),
        }
    }
}
