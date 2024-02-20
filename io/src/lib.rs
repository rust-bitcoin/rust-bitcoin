//! Rust-Bitcoin IO Library
//!
//! The `std::io` module is not exposed in `no-std` Rust so building `no-std` applications which
//! require reading and writing objects via standard traits is not generally possible. Thus, this
//! library exists to export a minmal version of `std::io`'s traits which we use in `rust-bitcoin`
//! so that we can support `no-std` applications.
//!
//! These traits are not one-for-one drop-ins, but are as close as possible while still implementing
//! `std::io`'s traits without unnecessary complexity.

#![cfg_attr(not(feature = "std"), no_std)]

// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

// Coding conventions.
#![warn(missing_docs)]

// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.

#[cfg(feature = "alloc")]
extern crate alloc;

mod error;
mod macros;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
use core::cmp;

#[rustfmt::skip]                // Keep public re-exports separate.
pub use self::error::{Error, ErrorKind};

/// Result type returned by functions in this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A generic trait describing an input stream. See [`std::io::Read`] for more info.
pub trait Read {
    /// Reads bytes from source into `buf`.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Reads bytes from source until `buf` is full.
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

    /// Creates an adapter which will read at most `limit` bytes.
    #[inline]
    fn take(&mut self, limit: u64) -> Take<Self> { Take { reader: self, remaining: limit } }

    /// Attempts to read up to limit bytes from the reader, allocating space in `buf` as needed.
    ///
    /// `limit` is used to prevent a denial of service attack vector since an unbounded reader will
    /// exhaust all memory.
    ///
    /// Similar to `std::io::Read::read_to_end` but with the DOS protection.
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
pub struct Take<'a, R: Read + ?Sized> {
    reader: &'a mut R,
    remaining: u64,
}

impl<'a, R: Read + ?Sized> Take<'a, R> {
    /// Reads all bytes until EOF from the underlying reader into `buf`.
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

impl<'a, R: Read + ?Sized> Read for Take<'a, R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let len = cmp::min(buf.len(), self.remaining.try_into().unwrap_or(buf.len()));
        let read = self.reader.read(&mut buf[..len])?;
        self.remaining -= read.try_into().unwrap_or(self.remaining);
        Ok(read)
    }
}

// Impl copied from Rust stdlib.
impl<'a, R: BufRead + ?Sized> BufRead for Take<'a, R> {
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

impl Read for &[u8] {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let cnt = cmp::min(self.len(), buf.len());
        buf[..cnt].copy_from_slice(&self[..cnt]);
        *self = &self[cnt..];
        Ok(cnt)
    }
}

#[cfg(feature = "std")]
impl<R: std::io::Read> Read for std::io::BufReader<R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> { Ok(std::io::Read::read(self, buf)?) }
}

impl BufRead for &[u8] {
    #[inline]
    fn fill_buf(&mut self) -> Result<&[u8]> { Ok(self) }

    // This panics if amount is out of bounds, same as the std version.
    #[inline]
    fn consume(&mut self, amount: usize) { *self = &self[amount..] }
}

#[cfg(feature = "std")]
impl<R: std::io::Read> BufRead for std::io::BufReader<R> {
    #[inline]
    fn fill_buf(&mut self) -> Result<&[u8]> { Ok(std::io::BufRead::fill_buf(self)?) }

    #[inline]
    fn consume(&mut self, amount: usize) { std::io::BufRead::consume(self, amount) }
}

/// Wraps an in memory reader providing the `position` function.
pub struct Cursor<T> {
    inner: T,
    pos: u64,
}

impl<T: AsRef<[u8]>> Cursor<T> {
    /// Creates a `Cursor` by wrapping `inner`.
    #[inline]
    pub fn new(inner: T) -> Self { Cursor { inner, pos: 0 } }

    /// Returns the position read up to thus far.
    #[inline]
    pub fn position(&self) -> u64 { self.pos }

    /// Returns the inner buffer.
    ///
    /// This is the whole wrapped buffer, including the bytes already read.
    #[inline]
    pub fn into_inner(self) -> T { self.inner }
}

impl<T: AsRef<[u8]>> Read for Cursor<T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let inner: &[u8] = self.inner.as_ref();
        let start_pos = self.pos.try_into().unwrap_or(inner.len());
        let read = core::cmp::min(inner.len().saturating_sub(start_pos), buf.len());
        buf[..read].copy_from_slice(&inner[start_pos..start_pos + read]);
        self.pos =
            self.pos.saturating_add(read.try_into().unwrap_or(u64::max_value() /* unreachable */));
        Ok(read)
    }
}

impl<T: AsRef<[u8]>> BufRead for Cursor<T> {
    #[inline]
    fn fill_buf(&mut self) -> Result<&[u8]> {
        let inner: &[u8] = self.inner.as_ref();
        Ok(&inner[self.pos as usize..])
    }

    #[inline]
    fn consume(&mut self, amount: usize) {
        assert!(amount <= self.inner.as_ref().len());
        self.pos += amount as u64;
    }
}

/// A generic trait describing an output stream. See [`std::io::Write`] for more info.
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

impl<'a> Write for &'a mut [u8] {
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

#[cfg(feature = "std")]
impl<W: std::io::Write> Write for std::io::BufWriter<W> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> { Ok(std::io::Write::write(self, buf)?) }

    #[inline]
    fn flush(&mut self) -> Result<()> { Ok(std::io::Write::flush(self)?) }
}

/// A sink to which all writes succeed. See [`std::io::Sink`] for more info.
///
/// Created using `io::sink()`.
pub struct Sink;

impl Write for Sink {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> { Ok(buf.len()) }

    #[inline]
    fn write_all(&mut self, _: &[u8]) -> Result<()> { Ok(()) }

    #[inline]
    fn flush(&mut self) -> Result<()> { Ok(()) }
}

#[cfg(feature = "std")]
impl std::io::Write for Sink {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { Ok(buf.len()) }

    #[inline]
    fn write_all(&mut self, _: &[u8]) -> std::io::Result<()> { Ok(()) }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

/// Returns a sink to which all writes succeed. See [`std::io::sink`] for more info.
#[inline]
pub fn sink() -> Sink { Sink }

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(not(feature = "std"), feature = "alloc"))]
    use alloc::{string::ToString, vec};

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
        assert_eq!(fill.len(), 0);
        assert_eq!(fill, &[]);
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
}
