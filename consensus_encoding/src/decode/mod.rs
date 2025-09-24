// SPDX-License-Identifier: CC0-1.0

//! Consensus Decoding Traits

pub mod decoders;

/// A Bitcoin object which can be consensus-decoded using a push decoder.
///
/// To decode something, create a [`Self::Decoder`] and push byte slices
/// into it with [`Decoder::push_bytes`], then call [`Decoder::end`] to get the result.
pub trait Decodable {
    /// Associated decoder for the type.
    type Decoder: Decoder<Output = Self>;
    /// Constructs a "default decoder" for the type.
    fn decoder() -> Self::Decoder;
}

/// A push decoder for a consensus-decodable object.
pub trait Decoder: Sized {
    /// The type that this decoder produces when decoding is complete.
    type Output;
    /// The error type that this decoder can produce.
    type Error;

    /// Push bytes into the decoder, consuming as much as possible.
    ///
    /// The slice reference will be advanced to point to the unconsumed portion.
    /// Returns `Ok(true)` if more bytes are needed to complete decoding,
    /// `Ok(false)` if the decoder is ready to finalize with [`Self::end`],
    /// or `Err(error)` if parsing failed.
    ///
    /// # Errors
    ///
    /// Returns an error if the provided bytes are invalid or malformed according
    /// to the decoder's validation rules. Insufficient data (needing more
    /// bytes) is *not* an error for this method, the decoder will simply consume
    /// what it can and return `true` to indicate more data is needed.
    ///
    /// # Panics
    ///
    /// May panic if called after a previous call to [`Self::push_bytes`] errored.
    #[must_use = "must check result to avoid panics on subsequent calls"]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error>;

    /// Complete the decoding process and return the final result.
    ///
    /// This consumes the decoder and should be called when no more input
    /// data is available.
    ///
    /// # Errors
    ///
    /// Returns an error if the decoder has not received sufficient data to
    /// complete decoding, or if the accumulated data is invalid when considered
    /// as a complete object.
    ///
    /// # Panics
    ///
    /// May panic if called after a previous call to [`Self::push_bytes`] errored.
    #[must_use = "must check result to avoid panics on subsequent calls"]
    fn end(self) -> Result<Self::Output, Self::Error>;
}

/// Decodes an object from a byte slice.
///
/// # Errors
///
/// Returns an error if the decoder encounters an error while
/// parsing the data, including insufficient data.
pub fn decode_from_slice<T>(bytes: &[u8]) -> Result<T, <T::Decoder as Decoder>::Error>
where
    T: Decodable,
{
    let mut decoder = T::decoder();
    let mut remaining = bytes;

    while !remaining.is_empty() {
        if !decoder.push_bytes(&mut remaining)? {
            break;
        }
    }

    decoder.end()
}

/// Decodes an object from a buffered reader.
///
/// # Performance
///
/// For unbuffered readers (like [`std::fs::File`] or [`std::net::TcpStream`]),
/// consider wrapping your reader with [`std::io::BufReader`] in order to use
/// this function. This avoids frequent small reads, which can significantly
/// impact performance.
///
/// # Errors
///
/// Returns [`ReadError::Decode`] if the decoder encounters an error while parsing
/// the data, or [`ReadError::Io`] if an I/O error occurs while reading.
#[cfg(feature = "std")]
pub fn decode_from_read<T, R>(mut reader: R) -> Result<T, ReadError<<T::Decoder as Decoder>::Error>>
where
    T: Decodable,
    R: std::io::BufRead,
{
    let mut decoder = T::decoder();

    loop {
        let mut buffer = match reader.fill_buf() {
            Ok(buffer) => buffer,
            // Auto retry read for non-fatal error.
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(ReadError::Io(error)),
        };

        if buffer.is_empty() {
            // EOF, but still try to finalize the decoder.
            return decoder.end().map_err(ReadError::Decode);
        }

        let original_len = buffer.len();
        let need_more = decoder.push_bytes(&mut buffer).map_err(ReadError::Decode)?;
        let consumed = original_len - buffer.len();
        reader.consume(consumed);

        if !need_more {
            return decoder.end().map_err(ReadError::Decode);
        }
    }
}

/// An error that can occur when reading and decoding from a buffered reader.
#[cfg(feature = "std")]
#[derive(Debug)]
pub enum ReadError<D> {
    /// An I/O error occurred while reading from the reader.
    Io(std::io::Error),
    /// The decoder encountered an error while parsing the data.
    Decode(D),
}

#[cfg(feature = "std")]
impl<D: core::fmt::Display> core::fmt::Display for ReadError<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ReadError::Io(e) => write!(f, "I/O error: {}", e),
            ReadError::Decode(e) => write!(f, "decode error: {}", e),
        }
    }
}

#[cfg(feature = "std")]
impl<D> std::error::Error for ReadError<D>
where
    D: core::fmt::Debug + core::fmt::Display + std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReadError::Io(e) => Some(e),
            ReadError::Decode(e) => Some(e),
        }
    }
}

#[cfg(feature = "std")]
impl<D> From<std::io::Error> for ReadError<D> {
    fn from(e: std::io::Error) -> Self { ReadError::Io(e) }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;
    #[cfg(feature = "std")]
    use std::io::{Cursor, Read};

    use super::*;
    use crate::decode::decoders::{ArrayDecoder, UnexpectedEofError};

    #[derive(Debug, PartialEq)]
    struct TestArray([u8; 4]);

    impl Decodable for TestArray {
        type Decoder = TestArrayDecoder;
        fn decoder() -> Self::Decoder { TestArrayDecoder { inner: ArrayDecoder::new() } }
    }

    struct TestArrayDecoder {
        inner: ArrayDecoder<4>,
    }

    impl Decoder for TestArrayDecoder {
        type Output = TestArray;
        type Error = UnexpectedEofError;

        fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
            self.inner.push_bytes(bytes)
        }

        fn end(self) -> Result<Self::Output, Self::Error> { self.inner.end().map(TestArray) }
    }

    #[test]
    fn decode_from_slice_success() {
        let data = [1, 2, 3, 4];
        let result: Result<TestArray, _> = decode_from_slice(&data);
        assert!(result.is_ok());
        let decoded = result.unwrap();
        assert_eq!(decoded.0, [1, 2, 3, 4]);
    }

    #[test]
    fn decode_from_slice_unexpected_eof() {
        let data = [1, 2, 3];
        let result: Result<TestArray, _> = decode_from_slice(&data);
        assert!(result.is_err());
    }

    #[test]
    fn decode_from_slice_extra_data() {
        let data = [1, 2, 3, 4, 5];
        let result: Result<TestArray, _> = decode_from_slice(&data);
        assert!(result.is_ok());
        let decoded = result.unwrap();
        assert_eq!(decoded.0, [1, 2, 3, 4]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn decode_from_read_success() {
        let data = [1, 2, 3, 4];
        let cursor = Cursor::new(&data);
        let result: Result<TestArray, _> = decode_from_read(cursor);
        assert!(result.is_ok());
        let decoded = result.unwrap();
        assert_eq!(decoded.0, [1, 2, 3, 4]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn decode_from_read_unexpected_eof() {
        let data = [1, 2, 3];
        let cursor = Cursor::new(&data);
        let result: Result<TestArray, _> = decode_from_read(cursor);
        assert!(matches!(result, Err(ReadError::Decode(_))));
    }

    #[cfg(feature = "std")]
    #[test]
    fn decode_from_read_trait_object() {
        let data = [1, 2, 3, 4];
        let mut cursor = Cursor::new(&data);
        // Test that we can pass a trait object (&mut dyn BufRead implements BufRead).
        let reader: &mut dyn std::io::BufRead = &mut cursor;
        let result: Result<TestArray, _> = decode_from_read(reader);
        assert!(result.is_ok());
        let decoded = result.unwrap();
        assert_eq!(decoded.0, [1, 2, 3, 4]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn decode_from_read_by_reference() {
        let data = [1, 2, 3, 4];
        let mut cursor = Cursor::new(&data);
        // Test that we can pass by reference (&mut T implements BufRead when T: BufRead).
        let result: Result<TestArray, _> = decode_from_read(&mut cursor);
        assert!(result.is_ok());
        let decoded = result.unwrap();
        assert_eq!(decoded.0, [1, 2, 3, 4]);

        let mut buf = Vec::new();
        let _ = cursor.read_to_end(&mut buf);
    }
}
