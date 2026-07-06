// SPDX-License-Identifier: CC0-1.0

//! Consensus Decoding Traits

pub mod decoders;

#[cfg(feature = "hex")]
use crate::error::{FromHexError, FromHexErrorInner};
#[cfg(feature = "std")]
use crate::ReadError;
use crate::{DecodeError, UnconsumedError};

/// A Bitcoin object which can be consensus-decoded using a push decoder.
///
/// To decode something, create a [`Self::Decoder`] and push byte slices into it with
/// [`Decoder::push_bytes`], then call [`Decoder::end`] to get the result.
///
/// # Examples
///
/// ```
/// use bitcoin_consensus_encoding::{decode_from_slice, Decode, Decoder, DecoderStatus, ArrayDecoder, UnexpectedEofError};
///
/// struct Foo([u8; 4]);
///
/// #[derive(Default)]
/// struct FooDecoder(ArrayDecoder<4>);
///
/// impl Decoder for FooDecoder {
///     type Output = Foo;
///     type Error = UnexpectedEofError;
///
///     fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
///         self.0.push_bytes(bytes)
///     }
///     fn end(self) -> Result<Self::Output, Self::Error> { self.0.end().map(Foo) }
///     fn read_limit(&self) -> usize { self.0.read_limit() }
/// }
///
/// impl Decode for Foo {
///     type Decoder = FooDecoder;
/// }
///
/// let foo: Foo = decode_from_slice(&[0xde, 0xad, 0xbe, 0xef]).unwrap();
/// assert_eq!(foo.0, [0xde, 0xad, 0xbe, 0xef]);
/// ```
pub trait Decode {
    /// Associated decoder for the type.
    type Decoder: Decoder<Output = Self> + Default;

    /// Constructs a "default decoder" for the type.
    fn decoder() -> Self::Decoder { Self::Decoder::default() }
}

/// A push decoder for a consensus-decodable object.
pub trait Decoder: Sized {
    /// The type that this decoder produces when decoding is complete.
    type Output;
    /// The error type that this decoder can produce.
    type Error;

    /// Pushes bytes into the decoder, consuming as much as possible.
    ///
    /// The slice reference will be advanced to point to the unconsumed portion. Returns
    /// `Ok(DecoderStatus::NeedsMore)` if more bytes are needed to complete decoding,
    /// `Ok(DecoderStatus::Ready)` if the decoder is ready to finalize with [`Self::end`], or
    /// `Err(error)` if parsing failed.
    ///
    /// Once the decoder returns `Ok(DecoderStatus::Ready)`, subsequent calls to this method will
    /// continue to return `Ok(DecoderStatus::Ready)` without consuming additional bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the provided bytes are invalid or malformed according to the decoder's
    /// validation rules. Insufficient data (needing more bytes) is *not* an error for this method,
    /// the decoder will simply consume what it can and return `DecoderStatus::NeedsMore` to
    /// indicate more data is needed.
    ///
    /// # Panics
    ///
    /// May panic if called after a previous call to [`Self::push_bytes`] errored.
    #[must_use = "must check result to avoid panics on subsequent calls"]
    #[track_caller]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error>;

    /// Completes the decoding process and returns the final result.
    ///
    /// This consumes the decoder and should be called when no more input data is available.
    ///
    /// # Errors
    ///
    /// Returns an error if the decoder has not received sufficient data to complete decoding, or if
    /// the accumulated data is invalid when considered as a complete object.
    ///
    /// # Panics
    ///
    /// May panic if called after a previous call to [`Self::push_bytes`] errored.
    #[must_use = "must check result to avoid panics on subsequent calls"]
    #[track_caller]
    fn end(self) -> Result<Self::Output, Self::Error>;

    /// Returns the maximum number of bytes this decoder can consume without over-reading.
    ///
    /// Returns 0 if the decoder is complete and ready to finalize with [`Self::end`]. This is used
    /// by [`decode_from_read_unbuffered`] to optimize read sizes, avoiding both inefficient
    /// under-reads and unnecessary over-reads.
    fn read_limit(&self) -> usize;
}

/// Indicates whether a decoder needs more data or is ready to finalize.
///
/// This is returned from the [`Decoder::push_bytes`] method to indicate whether the decoder
/// should continue accumulating data or is ready to produce the decoded value with [`Decoder::end`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DecoderStatus {
    /// The decoder needs more data to complete decoding.
    ///
    /// Continue pushing byte slices with [`Decoder::push_bytes`] until this status changes to
    /// [`Ready`](DecoderStatus::Ready).
    NeedsMore,

    /// The decoder has accumulated sufficient data and is ready to finalize.
    ///
    /// Call [`Decoder::end`] to complete the decoding process and obtain the final result.
    Ready,
}

impl DecoderStatus {
    /// Returns `true` if the decoder needs more data to continue.
    pub fn needs_more(&self) -> bool { matches!(self, Self::NeedsMore) }

    /// Returns `true` if ready to produce decoded value with [`Decoder::end`].
    pub fn is_ready(&self) -> bool { matches!(self, Self::Ready) }
}

/// Decodes an object from a hex string without heap allocations.
///
/// # Errors
///
/// [`FromHexError`] if the string has an odd number of characters, any character is not a
/// valid hex digit, or if decoding the type fails, including if bytes remain unconsumed
/// after the decoder completes.
#[cfg(feature = "hex")]
pub fn decode_from_hex<T: Decode>(
    hex: &str,
) -> Result<T, FromHexError<<T::Decoder as Decoder>::Error>> {
    decode_from_hex_internal(hex, T::decoder())
}

/// Decodes an object from a hex string without heap allocations using a [`Decoder`] type.
///
/// Unlike [`decode_from_hex`], this takes a generic [`Decoder`] parameter, allowing use with
/// decoders which don't have a dedicated [`Decode`] implementer (e.g. [`CompactSizeDecoder`]).
///
/// # Errors
///
/// [`FromHexError`] if the string has an odd number of characters, any character is not a
/// valid hex digit, or if decoding the type fails, including if bytes remain unconsumed
/// after the decoder completes.
///
/// [`CompactSizeDecoder`]: crate::CompactSizeDecoder
#[cfg(feature = "hex")]
pub fn decode_from_hex_with_decoder<D: Decoder + Default>(
    hex: &str,
) -> Result<D::Output, FromHexError<D::Error>> {
    decode_from_hex_internal(hex, D::default())
}

#[cfg(feature = "hex")]
fn decode_from_hex_internal<D: Decoder>(
    hex: &str,
    mut decoder: D,
) -> Result<D::Output, FromHexError<D::Error>> {
    let iter = hex::HexSliceToBytesIter::new(hex)
        .map_err(FromHexErrorInner::OddLength)
        .map_err(FromHexError)?;

    let mut buffer = [0u8; 4096];
    let mut index = 0;

    for item in iter {
        let byte = item.map_err(FromHexErrorInner::InvalidChar).map_err(FromHexError)?;

        if index == buffer.len() {
            let mut to_flush = buffer.as_slice();
            // There is at least a single byte left after flushing the buffer. Error if the decoder
            // is ready after flush.
            while !to_flush.is_empty() {
                if decoder
                    .push_bytes(&mut to_flush)
                    .map_err(|e| FromHexError(FromHexErrorInner::Decode(DecodeError::Parse(e))))?
                    .is_ready()
                {
                    return Err(FromHexError(FromHexErrorInner::Decode(DecodeError::Unconsumed(
                        UnconsumedError(),
                    ))));
                }
            }
            index = 0;
        }
        buffer[index] = byte;
        index += 1;
    }

    let mut to_flush = &buffer[..index];
    while !to_flush.is_empty() {
        if decoder
            .push_bytes(&mut to_flush)
            .map_err(|e| FromHexError(FromHexErrorInner::Decode(DecodeError::Parse(e))))?
            .is_ready()
        {
            break;
        }
    }

    if to_flush.is_empty() {
        decoder.end().map_err(|e| FromHexError(FromHexErrorInner::Decode(DecodeError::Parse(e))))
    } else {
        Err(FromHexError(FromHexErrorInner::Decode(DecodeError::Unconsumed(UnconsumedError()))))
    }
}

/// Decodes an object from a byte slice.
///
/// # Errors
///
/// Returns an error if the decoder encounters an error while parsing the data, including
/// insufficient data. This function also errors if the provided slice is not completely consumed
/// during decode.
pub fn decode_from_slice<T: Decode>(
    bytes: &[u8],
) -> Result<T, DecodeError<<T::Decoder as Decoder>::Error>> {
    decode_from_slice_internal(bytes, T::decoder())
}

/// Decodes an object from a byte slice using a [`Decoder`] type.
///
/// Unlike [`decode_from_slice`], this takes a generic [`Decoder`] parameter, allowing use with
/// decoders which don't have a dedicated [`Decode`] implementer (e.g. [`CompactSizeDecoder`]).
///
/// # Errors
///
/// Returns an error if the decoder encounters an error while parsing the data, including
/// insufficient data. This function also errors if the provided slice is not completely consumed
/// during decode.
///
/// [`CompactSizeDecoder`]: crate::CompactSizeDecoder
pub fn decode_from_slice_with_decoder<D: Decoder + Default>(
    bytes: &[u8],
) -> Result<D::Output, DecodeError<D::Error>> {
    decode_from_slice_internal(bytes, D::default())
}

fn decode_from_slice_internal<D: Decoder>(
    bytes: &[u8],
    decoder: D,
) -> Result<D::Output, DecodeError<D::Error>> {
    let mut remaining = bytes;
    let data = decode_from_slice_unbounded_internal(&mut remaining, decoder)
        .map_err(DecodeError::Parse)?;

    if remaining.is_empty() {
        Ok(data)
    } else {
        Err(DecodeError::Unconsumed(UnconsumedError()))
    }
}

/// Decodes an object from an unbounded byte slice.
///
/// Unlike [`decode_from_slice`], this function will not error if the slice contains additional
/// bytes that are not required to decode. Furthermore, the byte slice reference provided to this
/// function will be updated based on the consumed data, returning the unconsumed bytes.
///
/// # Errors
///
/// Returns an error if the decoder encounters an error while parsing the data, including
/// insufficient data.
pub fn decode_from_slice_unbounded<T>(
    bytes: &mut &[u8],
) -> Result<T, <T::Decoder as Decoder>::Error>
where
    T: Decode,
{
    decode_from_slice_unbounded_internal(bytes, T::decoder())
}

/// Decodes an object from an unbounded byte slice using a [`Decoder`] type.
///
/// Unlike [`decode_from_slice_unbounded`], this takes a generic [`Decoder`] parameter, allowing
/// use with decoders which don't have a dedicated [`Decode`] implementer
/// (e.g. [`CompactSizeDecoder`]).
///
/// Unlike [`decode_from_slice_with_decoder`], this function will not error if the slice contains
/// additional bytes that are not required to decode. Furthermore, the byte slice reference provided
/// to this function will be updated based on the consumed data, returning the unconsumed bytes.
///
/// # Errors
///
/// Returns an error if the decoder encounters an error while parsing the data, including
/// insufficient data.
///
/// [`CompactSizeDecoder`]: crate::CompactSizeDecoder
pub fn decode_from_slice_unbounded_with_decoder<D: Decoder + Default>(
    bytes: &mut &[u8],
) -> Result<D::Output, D::Error> {
    decode_from_slice_unbounded_internal(bytes, D::default())
}

fn decode_from_slice_unbounded_internal<D: Decoder>(
    bytes: &mut &[u8],
    mut decoder: D,
) -> Result<D::Output, D::Error> {
    while !bytes.is_empty() {
        if decoder.push_bytes(bytes)?.is_ready() {
            break;
        }
    }

    decoder.end()
}

/// Decodes an object from a buffered reader.
///
/// # Performance
///
/// For unbuffered readers (like [`std::fs::File`] or [`std::net::TcpStream`]), consider wrapping
/// your reader with [`std::io::BufReader`] in order to use this function. This avoids frequent
/// small reads, which can significantly impact performance.
///
/// # Errors
///
/// Returns [`ReadError::Decode`] if the decoder encounters an error while parsing the data, or
/// [`ReadError::Io`] if an I/O error occurs while reading.
#[cfg(feature = "std")]
pub fn decode_from_read<T, R>(reader: R) -> Result<T, ReadError<<T::Decoder as Decoder>::Error>>
where
    T: Decode,
    R: std::io::BufRead,
{
    decode_from_read_internal::<T::Decoder, R>(reader, T::decoder())
}

/// Decodes an object from a buffered reader using a [`Decoder`] type.
///
/// Unlike [`decode_from_read`], this takes a generic [`Decoder`] parameter, allowing use with
/// decoders which don't have a dedicated [`Decode`] implementer (e.g. [`CompactSizeDecoder`]).
///
/// # Performance
///
/// For unbuffered readers (like [`std::fs::File`] or [`std::net::TcpStream`]), consider wrapping
/// your reader with [`std::io::BufReader`] in order to use this function. This avoids frequent
/// small reads, which can significantly impact performance.
///
/// # Errors
///
/// Returns [`ReadError::Decode`] if the decoder encounters an error while parsing the data, or
/// [`ReadError::Io`] if an I/O error occurs while reading.
///
/// [`CompactSizeDecoder`]: crate::CompactSizeDecoder
#[cfg(feature = "std")]
pub fn decode_from_read_with_decoder<D, R>(reader: R) -> Result<D::Output, ReadError<D::Error>>
where
    D: Decoder + Default,
    R: std::io::BufRead,
{
    decode_from_read_internal(reader, D::default())
}

#[cfg(feature = "std")]
fn decode_from_read_internal<D, R>(
    mut reader: R,
    mut decoder: D,
) -> Result<D::Output, ReadError<D::Error>>
where
    D: Decoder,
    R: std::io::BufRead,
{
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
        let status = decoder.push_bytes(&mut buffer).map_err(ReadError::Decode)?;
        let consumed = original_len - buffer.len();
        reader.consume(consumed);

        if status.is_ready() {
            return decoder.end().map_err(ReadError::Decode);
        }
    }
}

/// Decodes an object from an unbuffered reader using a fixed-size buffer.
///
/// For most use cases, prefer [`decode_from_read`] with a [`std::io::BufReader`]. This function is
/// only needed when you have an unbuffered reader which you cannot wrap. It will probably have
/// worse performance.
///
/// # Buffer
///
/// Uses a fixed 4KB (4096 bytes) stack-allocated buffer that is reused across read operations. This
/// size is a good balance between memory usage and system call efficiency for most use cases.
///
/// For different buffer sizes, use [`decode_from_read_unbuffered_with`].
///
/// # Errors
///
/// Returns [`ReadError::Decode`] if the decoder encounters an error while parsing the data, or
/// [`ReadError::Io`] if an I/O error occurs while reading.
#[cfg(feature = "std")]
pub fn decode_from_read_unbuffered<T, R>(
    reader: R,
) -> Result<T, ReadError<<T::Decoder as Decoder>::Error>>
where
    T: Decode,
    R: std::io::Read,
{
    decode_from_read_unbuffered_with::<T, R, 4096>(reader)
}

/// Decodes an object from an unbuffered reader using a custom-sized buffer.
///
/// For most use cases, prefer [`decode_from_read`] with a [`std::io::BufReader`]. This function is
/// only needed when you have an unbuffered reader which you cannot wrap. It will probably have
/// worse performance.
///
/// # Buffer
///
/// The `BUFFER_SIZE` parameter controls the intermediate buffer size used for reading. The buffer
/// is allocated on the stack (not heap) and reused across read operations. Larger buffers reduce
/// the number of system calls, but use more memory.
///
/// # Errors
///
/// Returns [`ReadError::Decode`] if the decoder encounters an error while parsing the data, or
/// [`ReadError::Io`] if an I/O error occurs while reading.
#[cfg(feature = "std")]
pub fn decode_from_read_unbuffered_with<T, R, const BUFFER_SIZE: usize>(
    mut reader: R,
) -> Result<T, ReadError<<T::Decoder as Decoder>::Error>>
where
    T: Decode,
    R: std::io::Read,
{
    let mut decoder = T::decoder();
    let mut buffer = [0u8; BUFFER_SIZE];

    while decoder.read_limit() > 0 {
        // Only read what we need, up to buffer size.
        let clamped_buffer = &mut buffer[..decoder.read_limit().min(BUFFER_SIZE)];
        match reader.read(clamped_buffer) {
            Ok(0) => {
                // EOF, but still try to finalize the decoder.
                return decoder.end().map_err(ReadError::Decode);
            }
            Ok(bytes_read) => {
                let mut to_push = &clamped_buffer[..bytes_read];
                while !to_push.is_empty() {
                    if decoder.push_bytes(&mut to_push).map_err(ReadError::Decode)?.is_ready() {
                        return decoder.end().map_err(ReadError::Decode);
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                // Auto retry read for non-fatal error.
            }
            Err(e) => return Err(ReadError::Io(e)),
        }
    }

    decoder.end().map_err(ReadError::Decode)
}

/// Checks that the given bytes decode to the expected value, panicking if they don't.
///
/// This is intended for tests only.
///
/// # Panics
///
/// If the decoded value doesn't match the expected value, or if decoding fails.
#[track_caller]
pub fn check_decode<T: Decode + Eq + core::fmt::Debug>(bytes: &[u8], expected: &T)
where
    <T::Decoder as Decoder>::Error: core::fmt::Debug,
{
    let decoder = T::decoder();
    check_decoder(decoder, bytes, expected);
}

/// Checks that the given `decoder` produces the expected value, panicking if it doesn't.
///
/// This is intended for tests only.
///
/// # Panics
///
/// If the decoder doesn't produce the expected value or if decoding fails.
#[track_caller]
pub fn check_decoder<D: Decoder>(mut decoder: D, mut bytes: &[u8], expected: &D::Output)
where
    D::Output: Eq + core::fmt::Debug,
    D::Error: core::fmt::Debug,
{
    loop {
        match decoder.push_bytes(&mut bytes) {
            Ok(status) => {
                if status.is_ready() {
                    break;
                }
                assert!(!bytes.is_empty(), "decoder needs more data but no bytes remaining");
            }
            Err(e) => panic!("decoder failed with error: {e:?}"),
        }
    }

    match decoder.end() {
        Ok(result) => {
            assert_eq!(&result, expected, "decoded value doesn't match expected value");
        }
        Err(e) => panic!("decoder finalization failed with error: {e:?}"),
    }
}
