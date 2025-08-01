// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus encoding (encoding only, not decoding).

#[cfg(feature = "alloc")]
use core::any::TypeId;
#[cfg(feature = "alloc")]
use core::mem;

use internals::{compact_size, ToU64};
use io::{self, Write};

#[cfg(feature = "alloc")]
use crate::prelude::{rc, sync, Box, Cow, String, Vec};

/// Data which can be encoded in a consensus-consistent way.
pub trait Encodable {
    /// Encodes an object with a well-defined format.
    ///
    /// # Returns
    ///
    /// The number of bytes written on success. The only errors returned are errors propagated from
    /// the writer.
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error>;
}

/// Extensions of `Write` to encode data as per Bitcoin consensus.
pub trait WriteExt: Write {
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

    /// Outputs a variable sized integer ([`CompactSize`]).
    ///
    /// [`CompactSize`]: <https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer>
    fn emit_compact_size(&mut self, v: impl ToU64) -> Result<usize, io::Error>;

    /// Outputs a boolean.
    fn emit_bool(&mut self, v: bool) -> Result<(), io::Error>;

    /// Outputs a byte slice.
    fn emit_slice(&mut self, v: &[u8]) -> Result<usize, io::Error>;
}

macro_rules! encoder_fn {
    ($name:ident, $val_type:ty) => {
        #[inline]
        fn $name(&mut self, v: $val_type) -> core::result::Result<(), io::Error> {
            self.write_all(&v.to_le_bytes())
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
    fn emit_i8(&mut self, v: i8) -> Result<(), io::Error> { self.write_all(&[v as u8]) }
    #[inline]
    fn emit_u8(&mut self, v: u8) -> Result<(), io::Error> { self.write_all(&[v]) }
    #[inline]
    fn emit_bool(&mut self, v: bool) -> Result<(), io::Error> { self.write_all(&[v as u8]) }
    #[inline]
    fn emit_slice(&mut self, v: &[u8]) -> Result<usize, io::Error> {
        self.write_all(v)?;
        Ok(v.len())
    }
    #[inline]
    fn emit_compact_size(&mut self, v: impl ToU64) -> Result<usize, io::Error> {
        let encoded = compact_size::encode(v.to_u64());
        self.emit_slice(&encoded)?;
        Ok(encoded.len())
    }
}

impl Encodable for bool {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        w.emit_bool(*self)?;
        Ok(1)
    }
}

#[cfg(feature = "alloc")]
impl Encodable for String {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        consensus_encode_with_size(self.as_bytes(), w)
    }
}

#[cfg(feature = "alloc")]
impl Encodable for Cow<'static, str> {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        consensus_encode_with_size(self.as_bytes(), w)
    }
}

impl Encodable for [u16; 8] {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        for c in self.iter() {
            c.consensus_encode(w)?;
        }
        Ok(16)
    }
}

#[cfg(feature = "alloc")]
impl<T: Encodable + 'static> Encodable for Vec<T> {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        if TypeId::of::<T>() == TypeId::of::<u8>() {
            let len = self.len();
            let capacity = self.capacity();
            let ptr = self.as_ptr();

            // Safe because `T` is a `u8`.
            let v = unsafe { Vec::from_raw_parts(ptr as *mut u8, len, capacity) };

            let ret = consensus_encode_with_size(&v, w);
            mem::forget(v); // Prevent self from being dropped.
            ret
        } else {
            let mut len = 0;
            len += w.emit_compact_size(self.len())?;
            for c in self.iter() {
                len += c.consensus_encode(w)?;
            }
            Ok(len)
        }
    }
}

#[cfg(feature = "alloc")]
impl Encodable for Box<[u8]> {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        consensus_encode_with_size(self, w)
    }
}

impl<T: Encodable> Encodable for &'_ T {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (**self).consensus_encode(w)
    }
}

impl<T: Encodable> Encodable for &'_ mut T {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (**self).consensus_encode(w)
    }
}

#[cfg(feature = "alloc")]
impl<T: Encodable> Encodable for rc::Rc<T> {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (**self).consensus_encode(w)
    }
}

/// Note: This will fail to compile on old Rust for targets that don't support atomics
#[cfg(target_has_atomic = "ptr")]
#[cfg(feature = "alloc")]
impl<T: Encodable> Encodable for sync::Arc<T> {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (**self).consensus_encode(w)
    }
}

#[cfg(feature = "alloc")]
pub(crate) fn consensus_encode_with_size<W: Write + ?Sized>(
    data: &[u8],
    w: &mut W,
) -> Result<usize, io::Error> {
    Ok(w.emit_compact_size(data.len())? + w.emit_slice(data)?)
}
