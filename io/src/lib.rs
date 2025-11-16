// SPDX-License-Identifier: CC0-1.0

//! Rust Bitcoin I/O Library
//!
//! The [`std::io`] module is not exposed in `no-std` Rust so building `no-std` applications which
//! require reading and writing objects via standard traits is not generally possible. Thus, this
//! library exists to export a minimal version of `std::io`'s traits which we use in `rust-bitcoin`
//! so that we can support `no-std` applications.
//!
//! These traits are not one-for-one drop-ins, but are as close as possible while still implementing
//! `std::io`'s traits without unnecessary complexity.
//!
//! For examples of how to use and implement the types and traits in this crate see `io.rs` in the
//! `github.com/rust-bitcoin/rust-bitcoin/bitcoin/examples/` directory.

#![cfg_attr(not(feature = "std"), no_std)]
// Coding conventions.
#![warn(missing_docs)]
#![doc(test(attr(warn(unused))))]
// Pedantic lints that we enforce.
#![warn(clippy::return_self_not_must_use)]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)` instead of enforcing `format!("{x}")`

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "hashes")]
pub extern crate hashes;

#[cfg(feature = "std")]
mod bridge;
mod error;

#[cfg(feature = "hashes")]
mod hash;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
use core::cmp;

use encoding::Encoder;

#[rustfmt::skip]                // Keep public re-exports separate.
pub use self::error::{Error, ErrorKind};
#[cfg(feature = "std")]
pub use self::bridge::{FromStd, ToStd};
#[cfg(feature = "hashes")]
pub use self::hash::hash_reader;

/// Result type returned by functions in this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A generic trait describing an input stream.
///
/// See [`std::io::Read`] for more information.
pub trait Read {
    /// Reads bytes from source into `buf`.
    ///
    /// # Returns
    ///
    /// The number of bytes read if successful or an [`Error`] if reading fails.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Reads bytes from source until `buf` is full.
    ///
    /// # Errors
    ///
    /// If the exact number of bytes required to fill `buf` cannot be read.
    #[inline]
    fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.read(buf) {
                Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
                Ok(len) => buf = &mut buf[len..],
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Constructs a new adapter which will read at most `limit` bytes.
    #[inline]
    fn take(&mut self, limit: u64) -> Take<'_, Self> { Take { reader: self, remaining: limit } }

    /// Attempts to read up to limit bytes from the reader, allocating space in `buf` as needed.
    ///
    /// `limit` is used to prevent a denial of service attack vector since an unbounded reader will
    /// exhaust all memory.
    ///
    /// Similar to [`std::io::Read::read_to_end`] but with the DOS protection.
    ///
    /// # Returns
    ///
    /// The number of bytes read if successful or an [`Error`] if reading fails.
    #[doc(alias = "read_to_end")]
    #[cfg(feature = "alloc")]
    #[inline]
    fn read_to_limit(&mut self, buf: &mut Vec<u8>, limit: u64) -> Result<usize> {
        self.take(limit).read_to_end(buf)
    }
}

/// A trait describing an input stream that uses an internal buffer when reading.
pub trait BufRead: Read {
    /// Returns data read from this reader, filling the internal buffer if needed.
    ///
    /// # Errors
    ///
    /// May error if reading fails.
    fn fill_buf(&mut self) -> Result<&[u8]>;

    /// Marks the buffered data up to amount as consumed.
    ///
    /// # Panics
    ///
    /// May panic if `amount` is greater than amount of data read by `fill_buf`.
    fn consume(&mut self, amount: usize);
}

/// Reader adapter which limits the bytes read from an underlying reader.
///
/// Created by calling `[Read::take]`.
#[derive(Debug)]
pub struct Take<'a, R: Read + ?Sized> {
    reader: &'a mut R,
    remaining: u64,
}

impl<R: Read + ?Sized> Take<'_, R> {
    /// Reads all bytes until EOF from the underlying reader into `buf`.
    ///
    /// Allocates space in `buf` as needed.
    ///
    /// # Returns
    ///
    /// The number of bytes read if successful or an [`Error`] if reading fails.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        let mut read: usize = 0;
        let mut chunk = [0u8; 64];
        loop {
            match self.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[0..n]);
                    read += n;
                }
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            };
        }
        Ok(read)
    }
}

impl<R: Read + ?Sized> Read for Take<'_, R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let len = cmp::min(buf.len(), self.remaining.try_into().unwrap_or(buf.len()));
        let read = self.reader.read(&mut buf[..len])?;
        self.remaining -= read.try_into().unwrap_or(self.remaining);
        Ok(read)
    }
}

// Impl copied from Rust stdlib.
impl<R: BufRead + ?Sized> BufRead for Take<'_, R> {
    #[inline]
    fn fill_buf(&mut self) -> Result<&[u8]> {
        // Don't call into inner reader at all at EOF because it may still block
        if self.remaining == 0 {
            return Ok(&[]);
        }

        let buf = self.reader.fill_buf()?;
        // Cast length to a u64 instead of casting `remaining` to a `usize`
        // (in case `remaining > u32::MAX` and we are on a 32 bit machine).
        let cap = cmp::min(buf.len() as u64, self.remaining) as usize;
        Ok(&buf[..cap])
    }

    #[inline]
    fn consume(&mut self, amount: usize) {
        assert!(amount as u64 <= self.remaining);
        self.remaining -= amount as u64;
        self.reader.consume(amount);
    }
}

impl<T: Read> Read for &'_ mut T {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> { (**self).read(buf) }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> { (**self).read_exact(buf) }
}

impl<T: BufRead> BufRead for &'_ mut T {
    #[inline]
    fn fill_buf(&mut self) -> Result<&[u8]> { (**self).fill_buf() }

    #[inline]
    fn consume(&mut self, amount: usize) { (**self).consume(amount) }
}

impl Read for &[u8] {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let cnt = cmp::min(self.len(), buf.len());
        buf[..cnt].copy_from_slice(&self[..cnt]);
        *self = &self[cnt..];
        Ok(cnt)
    }
}

impl BufRead for &[u8] {
    #[inline]
    fn fill_buf(&mut self) -> Result<&[u8]> { Ok(self) }

    // This panics if amount is out of bounds, same as the std version.
    #[inline]
    fn consume(&mut self, amount: usize) { *self = &self[amount..] }
}

/// Wraps an in memory buffer providing `position` functionality for read and write.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Cursor<T> {
    inner: T,
    pos: u64,
}

impl<T: AsRef<[u8]>> Cursor<T> {
    /// Constructs a new `Cursor` by wrapping `inner`.
    #[inline]
    pub const fn new(inner: T) -> Self { Self { inner, pos: 0 } }

    /// Returns the position read or written up to thus far.
    #[inline]
    pub const fn position(&self) -> u64 { self.pos }

    /// Sets the internal position.
    ///
    /// This method allows seeking within the wrapped memory by setting the position.
    ///
    /// Note that setting a position that is larger than the buffer length will cause reads to
    /// succeed by reading zero bytes. Further, writes will be no-op zero length writes.
    #[inline]
    pub fn set_position(&mut self, position: u64) { self.pos = position; }

    /// Returns the inner buffer.
    ///
    /// This is the whole wrapped buffer, including the bytes already read.
    #[inline]
    pub fn into_inner(self) -> T { self.inner }

    /// Returns a reference to the inner buffer.
    ///
    /// This is the whole wrapped buffer, including the bytes already read.
    #[inline]
    pub const fn get_ref(&self) -> &T { &self.inner }

    /// Returns a mutable reference to the inner buffer.
    ///
    /// This is the whole wrapped buffer, including the bytes already read.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T { &mut self.inner }

    /// Returns a reference to the inner buffer.
    ///
    /// This is the whole wrapped buffer, including the bytes already read.
    #[inline]
    #[deprecated(since = "TBD", note = "use `get_ref()` instead")]
    pub fn inner(&self) -> &T { &self.inner }
}

impl<T: AsRef<[u8]>> Read for Cursor<T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let inner: &[u8] = self.inner.as_ref();
        let start_pos = self.pos.try_into().unwrap_or(inner.len());
        if start_pos >= self.inner.as_ref().len() {
            return Ok(0);
        }

        let read = core::cmp::min(inner.len().saturating_sub(start_pos), buf.len());
        buf[..read].copy_from_slice(&inner[start_pos..start_pos + read]);
        self.pos = self.pos.saturating_add(read.try_into().unwrap_or(u64::MAX /* unreachable */));
        Ok(read)
    }
}

impl<T: AsRef<[u8]>> BufRead for Cursor<T> {
    #[inline]
    fn fill_buf(&mut self) -> Result<&[u8]> {
        let inner: &[u8] = self.inner.as_ref();
        let pos = self.pos.min(inner.len() as u64) as usize;
        Ok(&inner[pos..])
    }

    #[inline]
    fn consume(&mut self, amount: usize) { self.pos = self.pos.saturating_add(amount as u64); }
}

impl<T: AsMut<[u8]>> Write for Cursor<T> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let write_slice = self.inner.as_mut();
        let pos = cmp::min(self.pos, write_slice.len() as u64);
        let amt = (&mut write_slice[(pos as usize)..]).write(buf)?;
        self.pos += amt as u64;
        Ok(amt)
    }

    #[inline]
    fn flush(&mut self) -> Result<()> { Ok(()) }
}

/// A generic trait describing an output stream.
///
/// See [`std::io::Write`] for more information.
pub trait Write {
    /// Writes `buf` into this writer, returning how many bytes were written.
    fn write(&mut self, buf: &[u8]) -> Result<usize>;

    /// Flushes this output stream, ensuring that all intermediately buffered contents
    /// reach their destination.
    fn flush(&mut self) -> Result<()>;

    /// Attempts to write an entire buffer into this writer.
    #[inline]
    fn write_all(&mut self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
                Ok(len) => buf = &buf[len..],
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

impl<T: Write> Write for &'_ mut T {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> { (**self).write(buf) }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> Result<()> { (**self).write_all(buf) }

    #[inline]
    fn flush(&mut self) -> Result<()> { (**self).flush() }
}

#[cfg(feature = "alloc")]
impl Write for alloc::vec::Vec<u8> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> Result<()> { Ok(()) }
}

impl Write for &mut [u8] {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let cnt = core::cmp::min(self.len(), buf.len());
        self[..cnt].copy_from_slice(&buf[..cnt]);
        *self = &mut core::mem::take(self)[cnt..];
        Ok(cnt)
    }

    #[inline]
    fn flush(&mut self) -> Result<()> { Ok(()) }
}

/// A sink to which all writes succeed.
///
/// Created using [`sink()`]. See [`std::io::Sink`] for more information.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sink;

impl Write for Sink {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> { Ok(buf.len()) }

    #[inline]
    fn write_all(&mut self, _: &[u8]) -> Result<()> { Ok(()) }

    #[inline]
    fn flush(&mut self) -> Result<()> { Ok(()) }
}

/// Returns a sink to which all writes succeed.
///
/// See [`std::io::sink`] for more information.
#[inline]
pub fn sink() -> Sink { Sink }

/// Wraps a `std` I/O type to implement the traits from this crate.
///
/// All methods are passed through converting the errors.
#[cfg(feature = "std")]
#[inline]
pub const fn from_std<T>(std_io: T) -> FromStd<T> { FromStd::new(std_io) }

/// Wraps a mutable reference to `std` I/O type to implement the traits from this crate.
///
/// All methods are passed through converting the errors.
#[cfg(feature = "std")]
#[inline]
pub fn from_std_mut<T>(std_io: &mut T) -> &mut FromStd<T> { FromStd::new_mut(std_io) }

/// Encodes a consensus_encoding object to an I/O writer.
pub fn encode_to_writer<T, W>(object: &T, mut writer: W) -> Result<()>
where
    T: encoding::Encodable + ?Sized,
    W: Write,
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

#[cfg(test)]
mod tests {
    #[cfg(all(not(feature = "std"), feature = "alloc"))]
    use alloc::{string::ToString, vec};

    use encoding::ArrayEncoder;

    use super::*;

    #[test]
    fn buf_read_fill_and_consume_slice() {
        let data = [0_u8, 1, 2];

        let mut slice = &data[..];

        let fill = BufRead::fill_buf(&mut slice).unwrap();
        assert_eq!(fill.len(), 3);
        assert_eq!(fill, &[0_u8, 1, 2]);
        slice.consume(2);

        let fill = BufRead::fill_buf(&mut slice).unwrap();
        assert_eq!(fill.len(), 1);
        assert_eq!(fill, &[2_u8]);
        slice.consume(1);

        // checks we can attempt to read from a now-empty reader.
        let fill = BufRead::fill_buf(&mut slice).unwrap();
        assert!(fill.is_empty());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn read_to_limit_greater_than_total_length() {
        let s = "16-byte-string!!".to_string();
        let mut reader = Cursor::new(&s);
        let mut buf = vec![];

        // 32 is greater than the reader length.
        let read = reader.read_to_limit(&mut buf, 32).expect("failed to read to limit");
        assert_eq!(read, s.len());
        assert_eq!(&buf, s.as_bytes())
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn read_to_limit_less_than_total_length() {
        let s = "16-byte-string!!".to_string();
        let mut reader = Cursor::new(&s);
        let mut buf = vec![];

        let read = reader.read_to_limit(&mut buf, 2).expect("failed to read to limit");
        assert_eq!(read, 2);
        assert_eq!(&buf, "16".as_bytes())
    }

    #[test]
    #[cfg(feature = "std")]
    fn set_position_past_end_read_returns_eof() {
        const BUF_LEN: usize = 64; // Just a small buffer.
        let mut buf = [0_u8; BUF_LEN]; // We never actually write to this buffer.

        let v = [1_u8; BUF_LEN];

        // Sanity check the stdlib Cursor's behaviour.
        let mut c = std::io::Cursor::new(v);
        for pos in [BUF_LEN, BUF_LEN + 1, BUF_LEN * 2] {
            c.set_position(pos as u64);
            let read = c.read(&mut buf).unwrap();
            assert_eq!(read, 0);
            assert_eq!(buf[0], 0x00); // Double check that buffer state is sane.
        }

        let mut c = Cursor::new(v);
        for pos in [BUF_LEN, BUF_LEN + 1, BUF_LEN * 2] {
            c.set_position(pos as u64);
            let read = c.read(&mut buf).unwrap();
            assert_eq!(read, 0);
            assert_eq!(buf[0], 0x00); // Double check that buffer state is sane.
        }
    }

    #[test]
    fn read_into_zero_length_buffer() {
        use crate::Read as _;

        const BUF_LEN: usize = 64;
        let data = [1_u8; BUF_LEN];
        let mut buf = [0_u8; BUF_LEN];

        let mut slice = data.as_ref();
        let mut take = Read::take(&mut slice, 32);

        let read = take.read(&mut buf[0..0]).unwrap();
        assert_eq!(read, 0);
        assert_eq!(buf[0], 0x00); // Check the buffer didn't get touched.
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn take_and_read_to_end() {
        const BUF_LEN: usize = 64;
        let data = [1_u8; BUF_LEN];

        let mut slice = data.as_ref();
        let mut take = Read::take(&mut slice, 32);

        let mut v = Vec::new();
        let read = take.read_to_end(&mut v).unwrap();
        assert_eq!(read, 32);
        assert_eq!(data[0..32], v[0..32]);
    }

    #[test]
    fn cursor_fill_buf_past_end() {
        let data = [1, 2, 3];
        let mut cursor = Cursor::new(&data);
        cursor.set_position(10);

        let buf = cursor.fill_buf().unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn cursor_write() {
        let data = [0x78, 0x56, 0x34, 0x12];

        let mut buf = [0_u8; 4];
        let mut cursor = Cursor::new(&mut buf);
        let amt = cursor.write(&data).unwrap();

        assert_eq!(buf, data);
        assert_eq!(amt, 4);
    }

    #[test]
    fn cursor_offset_write() {
        let data = [0x78, 0x56, 0x34, 0x12];

        let mut buf = [0_u8; 4];
        let mut cursor = Cursor::new(&mut buf);
        cursor.set_position(2);
        let amt = cursor.write(&data).unwrap();

        assert_eq!(buf, [0, 0, 0x78, 0x56]);
        assert_eq!(amt, 2);
    }

    #[test]
    fn cursor_consume_past_end() {
        let data = [1, 2, 3];
        let mut cursor = Cursor::new(&data);
        cursor.set_position(10);

        cursor.consume(5);
        assert_eq!(cursor.position(), 15);
    }

    // Simple test type that implements Encodable.
    struct TestData(u32);

    impl encoding::Encodable for TestData {
        type Encoder<'s>
            = ArrayEncoder<4>
        where
            Self: 's;

        fn encoder(&self) -> Self::Encoder<'_> {
            ArrayEncoder::without_length_prefix(self.0.to_le_bytes())
        }
    }

    #[test]
    fn encode_io_writer() {
        let data = TestData(0x1234_5678);

        let mut buf = [0_u8; 4];
        encode_to_writer(&data, buf.as_mut_slice()).unwrap();

        assert_eq!(buf, [0x78, 0x56, 0x34, 0x12]);
    }
}
