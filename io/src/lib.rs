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

// Coding conventions.
#![warn(missing_docs)]

// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "encoding")]
pub extern crate encoding;

mod error;
mod macros;
#[cfg(feature = "std")]
mod bridge;

#[cfg(feature = "std")]
pub use bridge::{FromStd, ToStd};

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
use core::cmp;

#[cfg(feature = "encoding")]
use encoding::Decoder;

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
    fn take(&mut self, limit: u64) -> Take<'_, Self> { Take { reader: self, remaining: limit } }

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

impl BufRead for &[u8] {
    #[inline]
    fn fill_buf(&mut self) -> Result<&[u8]> { Ok(self) }

    // This panics if amount is out of bounds, same as the std version.
    #[inline]
    fn consume(&mut self, amount: usize) { *self = &self[amount..] }
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

    /// Sets the internal position.
    ///
    /// This method allows seeking within the wrapped memory by setting the position.
    ///
    /// Note that setting a position that is larger than the buffer length will cause reads to
    /// return no bytes (EOF).
    #[inline]
    pub fn set_position(&mut self, position: u64) {
        self.pos = position;
    }

    /// Returns the inner buffer.
    ///
    /// This is the whole wrapped buffer, including the bytes already read.
    #[inline]
    pub fn into_inner(self) -> T { self.inner }

    /// Returns a reference to the inner buffer.
    ///
    /// This is the whole wrapped buffer, including the bytes already read.
    #[inline]
    pub fn inner(&self) -> &T { &self.inner }
}

impl<T: AsRef<[u8]>> Read for Cursor<T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let inner: &[u8] = self.inner.as_ref();
        let start_pos = self.pos.try_into().unwrap_or(inner.len());
        let read = core::cmp::min(inner.len().saturating_sub(start_pos), buf.len());
        buf[..read].copy_from_slice(&inner[start_pos..start_pos + read]);
        self.pos =
            self.pos.saturating_add(read.try_into().unwrap_or(u64::MAX /* unreachable */));
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

impl Write for &'_ mut [u8] {
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

/// Returns a sink to which all writes succeed. See [`std::io::sink`] for more info.
#[inline]
pub fn sink() -> Sink { Sink }

/// Wraps a `std` IO type to implement the traits from this crate.
///
/// All methods are passed through converting the errors.
#[cfg(feature = "std")]
#[inline]
pub const fn from_std<T>(std_io: T) -> FromStd<T> {
    FromStd::new(std_io)
}

/// Wraps a mutable reference to `std` IO type to implement the traits from this crate.
///
/// All methods are passed through converting the errors.
#[cfg(feature = "std")]
#[inline]
pub fn from_std_mut<T>(std_io: &mut T) -> &mut FromStd<T> {
    FromStd::new_mut(std_io)
}

/// Encodes an object that implements [`encoding::Encode`] to a writer.
///
/// This is a convenience function that takes care of the boilerplate of calling
/// [`encoding::Encode::encoder`], repeatedly calling [`Encoder::current_chunk`](encoding::Encoder::current_chunk),
/// writing to the writer, and calling [`Encoder::advance`](encoding::Encoder::advance).
///
/// # Errors
///
/// Returns any I/O error encountered while writing to the writer.
///
/// # Features
///
/// Requires the `encoding` feature.
#[cfg(feature = "encoding")]
#[inline]
pub fn encode_to_writer<T, W>(object: &T, writer: W) -> Result<()>
where
    T: encoding::Encode + ?Sized,
    W: Write,
{
    let mut encoder = object.encoder();
    drain_to_writer(&mut encoder, writer)
}

/// Drains the output of an [`Encoder`](encoding::Encoder) to an I/O writer.
///
/// See [`encode_to_writer`] for more information.
///
/// # Errors
///
/// Returns any I/O error encountered while writing to the writer.
///
/// # Features
///
/// Requires the `encoding` feature.
#[cfg(feature = "encoding")]
#[inline]
pub fn drain_to_writer<T, W>(encoder: &mut T, mut writer: W) -> Result<()>
where
    T: encoding::Encoder + ?Sized,
    W: Write,
{
    loop {
        writer.write_all(encoder.current_chunk())?;
        if encoder.advance().has_finished() {
            break;
        }
    }
    Ok(())
}

/// Decodes an object from a buffered reader.
///
/// # Errors
///
/// Returns [`ReadError::Decode`] if the decoder encounters an error while parsing
/// the data, or [`ReadError::Io`] if an I/O error occurs while reading.
#[cfg(feature = "encoding")]
pub fn decode_from_read<T, R>(
    reader: R,
) -> core::result::Result<T, encoding::ReadError<<T::Decoder as encoding::Decoder>::Error>>
where
    T: encoding::Decode,
    R: BufRead,
{
    decode_from_read_internal(reader, T::decoder())
}

/// Decodes an object from a buffered reader using a [`Decoder`](encoding::Decoder) type.
///
/// Unlike [`decode_from_read`], this takes a generic [`Decoder`](encoding::Decoder) parameter, allowing use with
/// decoders which don't have a dedicated [`Decode`](encoding::Decode) implementer.
///
/// # Performance
///
/// For unbuffered readers (like [`std::fs::File`] or [`std::net::TcpStream`]), consider wrapping
/// your reader with [`std::io::BufReader`] in order to use this function. This avoids frequent
/// small reads, which can significantly impact performance.
///
/// # Errors
///
/// Returns [`ReadError::Decode`] if the decoder encounters an error while parsing
/// the data, or [`ReadError::Io`] if an I/O error occurs while reading.
#[cfg(feature = "encoding")]
pub fn decode_from_read_with<D, R>(
    reader: R,
) -> core::result::Result<D::Output, encoding::ReadError<D::Error>>
where
    D: encoding::Decoder + Default,
    R: BufRead,
{
    decode_from_read_internal(reader, D::default())
}

#[cfg(feature = "encoding")]
fn decode_from_read_internal<D, R>(
    mut reader: R,
    mut decoder: D,
) -> core::result::Result<D::Output, encoding::ReadError<D::Error>>
where
    D: encoding::Decoder + Default,
    R: BufRead,
{
    loop {
        let mut buffer = match reader.fill_buf() {
            Ok(buffer) => buffer,
            // Auto retry read for non-fatal error.
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(encoding::ReadError::Io(std::io::Error::other(error.to_string()))),
        };

        if buffer.is_empty() {
            // EOF, but still try to finalize the decoder.
            return decoder.end().map_err(encoding::ReadError::Decode);
        }

        let original_len = buffer.len();
        let status = decoder.push_bytes(&mut buffer).map_err(encoding::ReadError::Decode)?;
        let consumed = original_len - buffer.len();
        reader.consume(consumed);

        if status.is_ready() {
            return decoder.end().map_err(encoding::ReadError::Decode);
        }
    }

}

/// Decodes an object from an unbuffered reader using a fixed-size buffer.
///
/// For most use cases, prefer [`decode_from_read`] with a [`std::io::BufReader`].
/// This function is only needed when you have an unbuffered reader which you
/// cannot wrap. It will probably have worse performance.
///
/// # Buffer
///
/// Uses a fixed 4KB (4096 bytes) stack-allocated buffer that is reused across
/// read operations. This size is a good balance between memory usage and
/// system call efficiency for most use cases.
///
/// For different buffer sizes, use [`decode_from_read_unbuffered_with`].
///
/// # Errors
///
/// Returns [`ReadError::Decode`] if the decoder encounters an error while parsing
/// the data, or [`ReadError::Io`] if an I/O error occurs while reading.
#[cfg(feature = "encoding")]
pub fn decode_from_read_unbuffered<T, R>(
    reader: R,
) -> core::result::Result<T, encoding::ReadError<<T::Decoder as encoding::Decoder>::Error>>
where
    T: encoding::Decode,
    R: Read,
{
    decode_from_read_unbuffered_with::<T, R, 4096>(reader)
}

/// Decodes an object from an unbuffered reader using a custom-sized buffer.
///
/// For most use cases, prefer [`decode_from_read`] with a [`std::io::BufReader`].
/// This function is only needed when you have an unbuffered reader which you
/// cannot wrap. It will probably have worse performance.
///
/// # Buffer
///
/// The `BUFFER_SIZE` parameter controls the intermediate buffer size used for
/// reading. The buffer is allocated on the stack (not heap) and reused across
/// read operations. Larger buffers reduce the number of system calls, but use
/// more memory.
///
/// # Errors
///
/// Returns [`ReadError::Decode`] if the decoder encounters an error while parsing
/// the data, or [`ReadError::Io`] if an I/O error occurs while reading.
#[cfg(feature = "encoding")]
pub fn decode_from_read_unbuffered_with<T, R, const BUFFER_SIZE: usize>(
    mut reader: R,
) -> core::result::Result<T, encoding::ReadError<<T::Decoder as encoding::Decoder>::Error>>
where
    T: encoding::Decode,
    R: Read,
{
    let mut decoder = T::decoder();
    let mut buffer = [0u8; BUFFER_SIZE];

    while decoder.read_limit() > 0 {
        // Only read what we need, up to buffer size.
        let clamped_buffer = &mut buffer[..decoder.read_limit().min(BUFFER_SIZE)];
        match reader.read(clamped_buffer) {
            Ok(0) => {
                // EOF, but still try to finalize the decoder.
                return decoder.end().map_err(encoding::ReadError::Decode);
            }
            Ok(bytes_read) => {
                if decoder
                    .push_bytes(&mut &clamped_buffer[..bytes_read])
                    .map_err(encoding::ReadError::Decode)?
                    .is_ready()
                {
                    return decoder.end().map_err(encoding::ReadError::Decode);
                }
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => {
                // Auto retry read for non-fatal error.
            }
            Err(e) => return Err(encoding::ReadError::Io(std::io::Error::other(e.to_string()))),
        }
    }

    decoder.end().map_err(encoding::ReadError::Decode)
}

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

    #[cfg(feature = "encoding")]
    mod encoding_tests {
        use super::*;

        struct TestData(u32);

        impl encoding::Encode for TestData {
            type Encoder<'s>
                = encoding::ArrayEncoder<4>
            where
                Self: 's;

            fn encoder(&self) -> Self::Encoder<'_> {
                encoding::ArrayEncoder::without_length_prefix(self.0.to_le_bytes())
            }
        }

        struct TestArray([u8; 4]);

        impl encoding::Decode for TestArray {
            type Decoder = TestArrayDecoder;
        }

        #[derive(Default)]
        struct TestArrayDecoder {
            inner: encoding::ArrayDecoder<4>,
        }

        impl encoding::Decoder for TestArrayDecoder {
            type Output = TestArray;
            type Error = encoding::UnexpectedEofError;

            fn push_bytes(
                &mut self,
                bytes: &mut &[u8],
            ) -> core::result::Result<encoding::DecoderStatus, Self::Error> {
                self.inner.push_bytes(bytes)
            }

            fn end(self) -> core::result::Result<Self::Output, Self::Error> {
                self.inner.end().map(TestArray)
            }

            fn read_limit(&self) -> usize {
                self.inner.read_limit()
            }
        }

        #[test]
        fn encode_to_writer() {
            let data = TestData(0x1234_5678);

            let mut buf = [0_u8; 4];
            super::encode_to_writer(&data, buf.as_mut_slice()).unwrap();

            assert_eq!(buf, [0x78, 0x56, 0x34, 0x12]);
        }

        #[test]
        fn decode_from_read_success() {
            let data = [1, 2, 3, 4];
            let cursor = Cursor::new(&data);
            let result: core::result::Result<TestArray, _> = super::decode_from_read(cursor);
            assert!(result.is_ok());
            let decoded = result.unwrap();
            assert_eq!(decoded.0, [1, 2, 3, 4]);
        }

        #[test]
        fn decode_from_read_unexpected_eof() {
            let data = [1, 2, 3];
            let cursor = Cursor::new(&data);
            let result: core::result::Result<TestArray, _> = super::decode_from_read(cursor);
            assert!(matches!(result, Err(encoding::ReadError::Decode(_))));
        }

        #[test]
        fn decode_from_read_unbuffered_success() {
            let data = [1, 2, 3, 4];
            let cursor = Cursor::new(&data);
            let result: core::result::Result<TestArray, _> =
                super::decode_from_read_unbuffered(cursor);
            assert!(result.is_ok());
            let decoded = result.unwrap();
            assert_eq!(decoded.0, [1, 2, 3, 4]);
        }

        #[test]
        fn decode_from_read_unbuffered_unexpected_eof() {
            let data = [1, 2, 3];
            let cursor = Cursor::new(&data);
            let result: core::result::Result<TestArray, _> =
                super::decode_from_read_unbuffered(cursor);
            assert!(matches!(result, Err(encoding::ReadError::Decode(_))));
        }

        #[test]
        fn decode_from_read_unbuffered_empty() {
            let data = [];
            let cursor = Cursor::new(&data);
            let result: core::result::Result<TestArray, _> =
                super::decode_from_read_unbuffered(cursor);
            assert!(matches!(result, Err(encoding::ReadError::Decode(_))));
        }

        #[test]
        fn decode_from_read_unbuffered_extra_data() {
            let data = [1, 2, 3, 4, 5, 6];
            let cursor = Cursor::new(&data);
            let result: core::result::Result<TestArray, _> =
                super::decode_from_read_unbuffered(cursor);
            assert!(result.is_ok());
            let decoded = result.unwrap();
            assert_eq!(decoded.0, [1, 2, 3, 4]);
        }
    }
}
