// SPDX-License-Identifier: CC0-1.0

//! Primitive decoders.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use core::convert::Infallible;
use core::{fmt, mem};

use internals::write_err;

#[cfg(feature = "alloc")]
use super::Decodable;
use super::Decoder;

/// Maximum size, in bytes, of a vector we are allowed to decode.
#[cfg(feature = "alloc")]
const MAX_VEC_SIZE: u64 = 4_000_000;

/// A decoder that decodes a byte vector.
///
/// The encoding is expected to start with the number of encoded bytes (length prefix).
#[cfg(feature = "alloc")]
pub struct ByteVecDecoder {
    prefix_decoder: Option<CompactSizeDecoder>,
    buffer: Vec<u8>,
    bytes_expected: usize,
    bytes_written: usize,
}

#[cfg(feature = "alloc")]
impl ByteVecDecoder {
    /// Constructs a new byte decoder.
    pub const fn new() -> Self {
        Self {
            prefix_decoder: Some(CompactSizeDecoder::new()),
            buffer: Vec::new(),
            bytes_expected: 0,
            bytes_written: 0,
        }
    }
}

#[cfg(feature = "alloc")]
impl Default for ByteVecDecoder {
    fn default() -> Self { Self::new() }
}

#[cfg(feature = "alloc")]
impl Decoder for ByteVecDecoder {
    type Output = Vec<u8>;
    type Error = ByteVecDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        use {ByteVecDecoderError as E, ByteVecDecoderErrorInner as Inner};

        if let Some(mut decoder) = self.prefix_decoder.take() {
            if decoder.push_bytes(bytes).map_err(|e| E(Inner::LengthPrefixDecode(e)))? {
                self.prefix_decoder = Some(decoder);
                return Ok(true);
            }
            let length = decoder.end().map_err(|e| E(Inner::LengthPrefixDecode(e)))?;

            self.prefix_decoder = None;
            self.bytes_expected =
                cast_to_usize_if_valid(length).map_err(|e| E(Inner::LengthPrefixInvalid(e)))?;

            // `cast_to_usize_if_valid` asserts length < 4,000,000, so no DoS vector here.
            self.buffer = Vec::with_capacity(self.bytes_expected);
        }

        let remaining = self.bytes_expected - self.bytes_written;
        let copy_len = bytes.len().min(remaining);

        self.buffer.extend_from_slice(&bytes[..copy_len]);
        self.bytes_written += copy_len;
        *bytes = &bytes[copy_len..];

        // Return true if we still need more data.
        Ok(self.bytes_written < self.bytes_expected)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        use {ByteVecDecoderError as E, ByteVecDecoderErrorInner as Inner};

        if self.bytes_written == self.bytes_expected {
            Ok(self.buffer)
        } else {
            Err(E(Inner::UnexpectedEof(UnexpectedEofError {
                missing: self.bytes_expected - self.bytes_written,
            })))
        }
    }

    fn read_limit(&self) -> usize {
        if let Some(prefix_decoder) = &self.prefix_decoder {
            prefix_decoder.read_limit()
        } else {
            self.bytes_expected - self.bytes_written
        }
    }
}

/// A decoder that decodes a vector of `T`s.
///
/// The decoding is expected to start with expected number of items in the vector.
#[cfg(feature = "alloc")]
pub struct VecDecoder<T: Decodable> {
    prefix_decoder: Option<CompactSizeDecoder>,
    length: usize,
    buffer: Vec<T>,
    decoder: Option<<T as Decodable>::Decoder>,
}

#[cfg(feature = "alloc")]
impl<T: Decodable> VecDecoder<T> {
    /// Constructs a new byte decoder.
    pub const fn new() -> Self {
        Self {
            prefix_decoder: Some(CompactSizeDecoder::new()),
            length: 0,
            buffer: Vec::new(),
            decoder: None,
        }
    }
}

#[cfg(feature = "alloc")]
impl<T: Decodable> Default for VecDecoder<T> {
    fn default() -> Self { Self::new() }
}

#[cfg(feature = "alloc")]
impl<T: Decodable> Decoder for VecDecoder<T> {
    type Output = Vec<T>;
    type Error = VecDecoderError<<<T as Decodable>::Decoder as Decoder>::Error>;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        use {VecDecoderError as E, VecDecoderErrorInner as Inner};

        if let Some(mut decoder) = self.prefix_decoder.take() {
            if decoder.push_bytes(bytes).map_err(|e| E(Inner::LengthPrefixDecode(e)))? {
                self.prefix_decoder = Some(decoder);
                return Ok(true);
            }
            let length = decoder.end().map_err(|e| E(Inner::LengthPrefixDecode(e)))?;
            if length == 0 {
                return Ok(false);
            }

            self.prefix_decoder = None;
            self.length =
                cast_to_usize_if_valid(length).map_err(|e| E(Inner::LengthPrefixInvalid(e)))?;

            // `cast_to_usize_if_valid` asserts length < 4,000,000, so no DoS vector here.
            self.buffer = Vec::with_capacity(self.length);
        }

        while !bytes.is_empty() {
            let mut decoder = self.decoder.take().unwrap_or_else(T::decoder);

            if decoder.push_bytes(bytes).map_err(|e| E(Inner::Item(e)))? {
                self.decoder = Some(decoder);
                return Ok(true);
            }
            let item = decoder.end().map_err(|e| E(Inner::Item(e)))?;
            self.buffer.push(item);

            if self.buffer.len() == self.length {
                return Ok(false);
            }
        }

        if self.buffer.len() == self.length {
            Ok(false)
        } else {
            Ok(true)
        }
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        use VecDecoderErrorInner as E;

        if self.buffer.len() == self.length {
            Ok(self.buffer)
        } else {
            Err(VecDecoderError(E::UnexpectedEof(UnexpectedEofError {
                missing: self.length - self.buffer.len(),
            })))
        }
    }

    fn read_limit(&self) -> usize {
        if let Some(prefix_decoder) = &self.prefix_decoder {
            prefix_decoder.read_limit()
        } else if let Some(decoder) = &self.decoder {
            decoder.read_limit()
        } else if self.buffer.len() == self.length {
            // Totally done.
            0
        } else {
            let items_left_to_decode = self.length - self.buffer.len();
            let decoder = T::decoder();
            // This could be inaccurate (eg 1 for a `ByteVecDecoder`) but its the best we can do.
            let limit_per_decoder = decoder.read_limit();
            items_left_to_decode * limit_per_decoder
        }
    }
}

/// Cast a decoded length prefix to a `usize`.
///
/// Consensus encoded vectors can be up to 4,000,000 bytes long.
///
/// This is a theoretical max since block size is 4 meg wu and minimum vector element is one byte.
///
/// # Errors
///
/// Errors if `n` is greater than 4,000,000 or won't fit in a `usize`.
#[cfg(feature = "alloc")]
pub fn cast_to_usize_if_valid(n: u64) -> Result<usize, LengthPrefixExceedsMaxError> {
    if n > MAX_VEC_SIZE {
        return Err(LengthPrefixExceedsMaxError { value: n });
    }

    usize::try_from(n).map_err(|_| LengthPrefixExceedsMaxError { value: n })
}

/// A decoder that expects exactly N bytes and returns them as an array.
pub struct ArrayDecoder<const N: usize> {
    buffer: [u8; N],
    bytes_written: usize,
}

impl<const N: usize> ArrayDecoder<N> {
    /// Constructs a new array decoder that expects exactly N bytes.
    pub const fn new() -> Self { Self { buffer: [0; N], bytes_written: 0 } }
}

impl<const N: usize> Default for ArrayDecoder<N> {
    fn default() -> Self { Self::new() }
}

impl<const N: usize> Decoder for ArrayDecoder<N> {
    type Output = [u8; N];
    type Error = UnexpectedEofError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        let remaining_space = N - self.bytes_written;
        let copy_len = bytes.len().min(remaining_space);

        if copy_len > 0 {
            self.buffer[self.bytes_written..self.bytes_written + copy_len]
                .copy_from_slice(&bytes[..copy_len]);
            self.bytes_written += copy_len;
            // Advance the slice reference to consume the bytes.
            *bytes = &bytes[copy_len..];
        }

        // Return true if we still need more data.
        Ok(self.bytes_written < N)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        if self.bytes_written == N {
            Ok(self.buffer)
        } else {
            Err(UnexpectedEofError { missing: N - self.bytes_written })
        }
    }

    #[inline]
    fn read_limit(&self) -> usize { N - self.bytes_written }
}

/// A decoder which wraps two inner decoders and returns the output of both.
pub struct Decoder2<A, B>
where
    A: Decoder,
    B: Decoder,
{
    state: Decoder2State<A, B>,
}

enum Decoder2State<A: Decoder, B: Decoder> {
    /// Decoding the first decoder, with second decoder waiting.
    First(A, B),
    /// Decoding the second decoder, with the first result stored.
    Second(A::Output, B),
    /// Decoder has failed and cannot be used again.
    Errored,
}

impl<A, B> Decoder2<A, B>
where
    A: Decoder,
    B: Decoder,
{
    /// Constructs a new composite decoder.
    pub const fn new(first: A, second: B) -> Self {
        Self { state: Decoder2State::First(first, second) }
    }
}

impl<A, B> Decoder for Decoder2<A, B>
where
    A: Decoder,
    B: Decoder,
{
    type Output = (A::Output, B::Output);
    type Error = Decoder2Error<A::Error, B::Error>;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        loop {
            match &mut self.state {
                Decoder2State::First(first_decoder, _) => {
                    if first_decoder.push_bytes(bytes).map_err(Decoder2Error::First)? {
                        // First decoder wants more data.
                        return Ok(true);
                    }

                    // First decoder is complete, transition to second.
                    // If the first decoder fails, the composite decoder
                    // remains in an Errored state.
                    match mem::replace(&mut self.state, Decoder2State::Errored) {
                        Decoder2State::First(first, second) => {
                            let first_result = first.end().map_err(Decoder2Error::First)?;
                            self.state = Decoder2State::Second(first_result, second);
                        }
                        _ => unreachable!("we know we're in First state"),
                    }
                }
                Decoder2State::Second(_, second_decoder) => {
                    return second_decoder.push_bytes(bytes).map_err(|error| {
                        self.state = Decoder2State::Errored;
                        Decoder2Error::Second(error)
                    });
                }
                Decoder2State::Errored => {
                    panic!("use of failed decoder");
                }
            }
        }
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        match self.state {
            Decoder2State::First(first_decoder, second_decoder) => {
                // This branch is most likely an error since the decoder
                // never got to the second one. But letting the error bubble
                // up naturally from the child decoders.
                let first_result = first_decoder.end().map_err(Decoder2Error::First)?;
                let second_result = second_decoder.end().map_err(Decoder2Error::Second)?;
                Ok((first_result, second_result))
            }
            Decoder2State::Second(first_result, second_decoder) => {
                let second_result = second_decoder.end().map_err(Decoder2Error::Second)?;
                Ok((first_result, second_result))
            }
            Decoder2State::Errored => {
                panic!("use of failed decoder");
            }
        }
    }

    #[inline]
    fn read_limit(&self) -> usize {
        match &self.state {
            Decoder2State::First(first_decoder, second_decoder) =>
                first_decoder.read_limit() + second_decoder.read_limit(),
            Decoder2State::Second(_, second_decoder) => second_decoder.read_limit(),
            Decoder2State::Errored => 0,
        }
    }
}

/// A decoder which decodes three objects, one after the other.
pub struct Decoder3<A, B, C>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
{
    inner: Decoder2<Decoder2<A, B>, C>,
}

impl<A, B, C> Decoder3<A, B, C>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
{
    /// Constructs a new composite decoder.
    pub const fn new(dec_1: A, dec_2: B, dec_3: C) -> Self {
        Self { inner: Decoder2::new(Decoder2::new(dec_1, dec_2), dec_3) }
    }
}

impl<A, B, C> Decoder for Decoder3<A, B, C>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
{
    type Output = (A::Output, B::Output, C::Output);
    type Error = Decoder3Error<A::Error, B::Error, C::Error>;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.inner.push_bytes(bytes).map_err(|error| match error {
            Decoder2Error::First(Decoder2Error::First(a)) => Decoder3Error::First(a),
            Decoder2Error::First(Decoder2Error::Second(b)) => Decoder3Error::Second(b),
            Decoder2Error::Second(c) => Decoder3Error::Third(c),
        })
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let result = self.inner.end().map_err(|error| match error {
            Decoder2Error::First(Decoder2Error::First(a)) => Decoder3Error::First(a),
            Decoder2Error::First(Decoder2Error::Second(b)) => Decoder3Error::Second(b),
            Decoder2Error::Second(c) => Decoder3Error::Third(c),
        })?;

        let ((first, second), third) = result;
        Ok((first, second, third))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

/// A decoder which decodes four objects, one after the other.
pub struct Decoder4<A, B, C, D>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
    D: Decoder,
{
    inner: Decoder2<Decoder2<A, B>, Decoder2<C, D>>,
}

impl<A, B, C, D> Decoder4<A, B, C, D>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
    D: Decoder,
{
    /// Constructs a new composite decoder.
    pub const fn new(dec_1: A, dec_2: B, dec_3: C, dec_4: D) -> Self {
        Self { inner: Decoder2::new(Decoder2::new(dec_1, dec_2), Decoder2::new(dec_3, dec_4)) }
    }
}

impl<A, B, C, D> Decoder for Decoder4<A, B, C, D>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
    D: Decoder,
{
    type Output = (A::Output, B::Output, C::Output, D::Output);
    type Error = Decoder4Error<A::Error, B::Error, C::Error, D::Error>;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.inner.push_bytes(bytes).map_err(|error| match error {
            Decoder2Error::First(Decoder2Error::First(a)) => Decoder4Error::First(a),
            Decoder2Error::First(Decoder2Error::Second(b)) => Decoder4Error::Second(b),
            Decoder2Error::Second(Decoder2Error::First(c)) => Decoder4Error::Third(c),
            Decoder2Error::Second(Decoder2Error::Second(d)) => Decoder4Error::Fourth(d),
        })
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let result = self.inner.end().map_err(|error| match error {
            Decoder2Error::First(Decoder2Error::First(a)) => Decoder4Error::First(a),
            Decoder2Error::First(Decoder2Error::Second(b)) => Decoder4Error::Second(b),
            Decoder2Error::Second(Decoder2Error::First(c)) => Decoder4Error::Third(c),
            Decoder2Error::Second(Decoder2Error::Second(d)) => Decoder4Error::Fourth(d),
        })?;

        let ((first, second), (third, fourth)) = result;
        Ok((first, second, third, fourth))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

/// A decoder which decodes six objects, one after the other.
#[allow(clippy::type_complexity)] // Nested composition is easier than flattened alternatives.
pub struct Decoder6<A, B, C, D, E, F>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
    D: Decoder,
    E: Decoder,
    F: Decoder,
{
    inner: Decoder2<Decoder3<A, B, C>, Decoder3<D, E, F>>,
}

impl<A, B, C, D, E, F> Decoder6<A, B, C, D, E, F>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
    D: Decoder,
    E: Decoder,
    F: Decoder,
{
    /// Constructs a new composite decoder.
    pub const fn new(dec_1: A, dec_2: B, dec_3: C, dec_4: D, dec_5: E, dec_6: F) -> Self {
        Self {
            inner: Decoder2::new(
                Decoder3::new(dec_1, dec_2, dec_3),
                Decoder3::new(dec_4, dec_5, dec_6),
            ),
        }
    }
}

impl<A, B, C, D, E, F> Decoder for Decoder6<A, B, C, D, E, F>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
    D: Decoder,
    E: Decoder,
    F: Decoder,
{
    type Output = (A::Output, B::Output, C::Output, D::Output, E::Output, F::Output);
    type Error = Decoder6Error<A::Error, B::Error, C::Error, D::Error, E::Error, F::Error>;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.inner.push_bytes(bytes).map_err(|error| match error {
            Decoder2Error::First(Decoder3Error::First(a)) => Decoder6Error::First(a),
            Decoder2Error::First(Decoder3Error::Second(b)) => Decoder6Error::Second(b),
            Decoder2Error::First(Decoder3Error::Third(c)) => Decoder6Error::Third(c),
            Decoder2Error::Second(Decoder3Error::First(d)) => Decoder6Error::Fourth(d),
            Decoder2Error::Second(Decoder3Error::Second(e)) => Decoder6Error::Fifth(e),
            Decoder2Error::Second(Decoder3Error::Third(f)) => Decoder6Error::Sixth(f),
        })
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let result = self.inner.end().map_err(|error| match error {
            Decoder2Error::First(Decoder3Error::First(a)) => Decoder6Error::First(a),
            Decoder2Error::First(Decoder3Error::Second(b)) => Decoder6Error::Second(b),
            Decoder2Error::First(Decoder3Error::Third(c)) => Decoder6Error::Third(c),
            Decoder2Error::Second(Decoder3Error::First(d)) => Decoder6Error::Fourth(d),
            Decoder2Error::Second(Decoder3Error::Second(e)) => Decoder6Error::Fifth(e),
            Decoder2Error::Second(Decoder3Error::Third(f)) => Decoder6Error::Sixth(f),
        })?;

        let ((first, second, third), (fourth, fifth, sixth)) = result;
        Ok((first, second, third, fourth, fifth, sixth))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

/// Decodes a compact size encoded integer.
///
/// For more information about decoder see the documentation of the [`Decoder`] trait.
#[derive(Debug, Clone)]
pub struct CompactSizeDecoder {
    buf: internals::array_vec::ArrayVec<u8, 9>,
}

impl CompactSizeDecoder {
    /// Constructs a new compact size decoder.
    pub const fn new() -> Self { Self { buf: internals::array_vec::ArrayVec::new() } }
}

impl Default for CompactSizeDecoder {
    fn default() -> Self { Self::new() }
}

impl Decoder for CompactSizeDecoder {
    type Output = u64;
    type Error = CompactSizeDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        if bytes.is_empty() {
            return Ok(true);
        }

        if self.buf.is_empty() {
            self.buf.push(bytes[0]);
            *bytes = &bytes[1..];
        }
        let len = match self.buf[0] {
            0xFF => 9,
            0xFE => 5,
            0xFD => 3,
            _ => 1,
        };
        let to_copy = bytes.len().min(len - self.buf.len());
        self.buf.extend_from_slice(&bytes[..to_copy]);
        *bytes = &bytes[to_copy..];

        Ok(self.buf.len() != len)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        use CompactSizeDecoderErrorInner as E;

        fn arr<const N: usize>(slice: &[u8]) -> Result<[u8; N], CompactSizeDecoderError> {
            slice.try_into().map_err(|_| {
                CompactSizeDecoderError(E::UnexpectedEof { required: N, received: slice.len() })
            })
        }

        let (first, payload) = self
            .buf
            .split_first()
            .ok_or(CompactSizeDecoderError(E::UnexpectedEof { required: 1, received: 0 }))?;

        match *first {
            0xFF => {
                let x = u64::from_le_bytes(arr(payload)?);
                if x < 0x100_000_000 {
                    Err(CompactSizeDecoderError(E::NonMinimal { value: x }))
                } else {
                    Ok(x)
                }
            }
            0xFE => {
                let x = u32::from_le_bytes(arr(payload)?);
                if x < 0x10000 {
                    Err(CompactSizeDecoderError(E::NonMinimal { value: x.into() }))
                } else {
                    Ok(x.into())
                }
            }
            0xFD => {
                let x = u16::from_le_bytes(arr(payload)?);
                if x < 0xFD {
                    Err(CompactSizeDecoderError(E::NonMinimal { value: x.into() }))
                } else {
                    Ok(x.into())
                }
            }
            n => Ok(n.into()),
        }
    }

    fn read_limit(&self) -> usize {
        match self.buf.len() {
            0 => 1,
            already_read => match self.buf[0] {
                0xFF => 9_usize.saturating_sub(already_read),
                0xFE => 5_usize.saturating_sub(already_read),
                0xFD => 3_usize.saturating_sub(already_read),
                _ => 0,
            },
        }
    }
}

/// An error consensus decoding a compact size encoded integer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactSizeDecoderError(CompactSizeDecoderErrorInner);

#[derive(Debug, Clone, PartialEq, Eq)]
enum CompactSizeDecoderErrorInner {
    /// Returned when the decoder reaches end of stream (EOF).
    UnexpectedEof {
        /// How many bytes were required.
        required: usize,
        /// How many bytes were received.
        received: usize,
    },
    /// Returned when the encoding is not minimal
    NonMinimal {
        /// The encoded value.
        value: u64,
    },
}

impl fmt::Display for CompactSizeDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use CompactSizeDecoderErrorInner as E;

        match self.0 {
            E::UnexpectedEof { required: 1, received: 0 } => {
                write!(f, "required at least one byte but the input is empty")
            }
            E::UnexpectedEof { required, received: 0 } => {
                write!(f, "required at least {} bytes but the input is empty", required)
            }
            E::UnexpectedEof { required, received } => write!(
                f,
                "required at least {} bytes but only {} bytes were received",
                required, received
            ),
            E::NonMinimal { value } => write!(f, "the value {} was not encoded minimally", value),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CompactSizeDecoderError {}

/// The error returned by the [`ByteVecDecoder`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteVecDecoderError(ByteVecDecoderErrorInner);

#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum ByteVecDecoderErrorInner {
    /// Error decoding the byte vector length prefix.
    LengthPrefixDecode(CompactSizeDecoderError),
    /// Length prefix exceeds 4,000,000.
    LengthPrefixInvalid(LengthPrefixExceedsMaxError),
    /// Not enough bytes given to decoder.
    UnexpectedEof(UnexpectedEofError),
}

#[cfg(feature = "alloc")]
impl From<Infallible> for ByteVecDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
impl fmt::Display for ByteVecDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ByteVecDecoderErrorInner as E;

        match self.0 {
            E::LengthPrefixDecode(ref e) => write_err!(f, "byte vec decoder error"; e),
            E::LengthPrefixInvalid(ref e) => write_err!(f, "byte vec decoder error"; e),
            E::UnexpectedEof(ref e) => write_err!(f, "byte vec decoder error"; e),
        }
    }
}

#[cfg(all(feature = "std", feature = "alloc"))]
impl std::error::Error for ByteVecDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ByteVecDecoderErrorInner as E;

        match self.0 {
            E::LengthPrefixDecode(ref e) => Some(e),
            E::LengthPrefixInvalid(ref e) => Some(e),
            E::UnexpectedEof(ref e) => Some(e),
        }
    }
}

/// The error returned by the [`VecDecoder`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VecDecoderError<Err>(VecDecoderErrorInner<Err>);

#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum VecDecoderErrorInner<Err> {
    /// Error decoding the vector length prefix.
    LengthPrefixDecode(CompactSizeDecoderError),
    /// Length prefix exceeds 4,000,000.
    LengthPrefixInvalid(LengthPrefixExceedsMaxError),
    /// Error while decoding an item.
    Item(Err),
    /// Not enough bytes given to decoder.
    UnexpectedEof(UnexpectedEofError),
}

#[cfg(feature = "alloc")]
impl<Err> From<Infallible> for VecDecoderError<Err> {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
impl<Err> fmt::Display for VecDecoderError<Err>
where
    Err: fmt::Display + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use VecDecoderErrorInner as E;

        match self.0 {
            E::LengthPrefixDecode(ref e) => write_err!(f, "vec decoder error"; e),
            E::LengthPrefixInvalid(ref e) => write_err!(f, "vec decoder error"; e),
            E::Item(ref e) => write_err!(f, "vec decoder error"; e),
            E::UnexpectedEof(ref e) => write_err!(f, "vec decoder error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl<Err> std::error::Error for VecDecoderError<Err>
where
    Err: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use VecDecoderErrorInner as E;

        match self.0 {
            E::LengthPrefixDecode(ref e) => Some(e),
            E::LengthPrefixInvalid(ref e) => Some(e),
            E::Item(ref e) => Some(e),
            E::UnexpectedEof(ref e) => Some(e),
        }
    }
}

/// Length prefix exceeds max value (4,000,000).
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LengthPrefixExceedsMaxError {
    /// Decoded value of the compact encoded length prefix.
    value: u64,
}

#[cfg(feature = "alloc")]
impl core::fmt::Display for LengthPrefixExceedsMaxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let max = match mem::size_of::<usize>() {
            1 => u32::from(u8::MAX),
            2 => u32::from(u16::MAX),
            _ => 4_000_000,
        };

        write!(f, "length prefix {} exceeds max value {}", self.value, max)
    }
}

#[cfg(all(feature = "std", feature = "alloc"))]
impl std::error::Error for LengthPrefixExceedsMaxError {}

/// Not enough bytes given to decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnexpectedEofError {
    /// Number of bytes missing to complete decoder.
    missing: usize,
}

impl fmt::Display for UnexpectedEofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not enough bytes for decoder, {} more bytes required", self.missing)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnexpectedEofError {}

/// Error type for [`Decoder2`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoder2Error<A, B> {
    /// Error from the first decoder.
    First(A),
    /// Error from the second decoder.
    Second(B),
}

impl<A, B> fmt::Display for Decoder2Error<A, B>
where
    A: fmt::Display,
    B: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::First(ref e) => write_err!(f, "first decoder error"; e),
            Self::Second(ref e) => write_err!(f, "second decoder error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl<A, B> std::error::Error for Decoder2Error<A, B>
where
    A: std::error::Error + 'static,
    B: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::First(ref e) => Some(e),
            Self::Second(ref e) => Some(e),
        }
    }
}

/// Error type for [`Decoder3`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoder3Error<A, B, C> {
    /// Error from the first decoder.
    First(A),
    /// Error from the second decoder.
    Second(B),
    /// Error from the third decoder.
    Third(C),
}

impl<A, B, C> fmt::Display for Decoder3Error<A, B, C>
where
    A: fmt::Display,
    B: fmt::Display,
    C: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::First(ref e) => write_err!(f, "first decoder error"; e),
            Self::Second(ref e) => write_err!(f, "second decoder error"; e),
            Self::Third(ref e) => write_err!(f, "third decoder error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl<A, B, C> std::error::Error for Decoder3Error<A, B, C>
where
    A: std::error::Error + 'static,
    B: std::error::Error + 'static,
    C: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::First(ref e) => Some(e),
            Self::Second(ref e) => Some(e),
            Self::Third(ref e) => Some(e),
        }
    }
}

/// Error type for [`Decoder4`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoder4Error<A, B, C, D> {
    /// Error from the first decoder.
    First(A),
    /// Error from the second decoder.
    Second(B),
    /// Error from the third decoder.
    Third(C),
    /// Error from the fourth decoder.
    Fourth(D),
}

impl<A, B, C, D> fmt::Display for Decoder4Error<A, B, C, D>
where
    A: fmt::Display,
    B: fmt::Display,
    C: fmt::Display,
    D: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::First(ref e) => write_err!(f, "first decoder error"; e),
            Self::Second(ref e) => write_err!(f, "second decoder error"; e),
            Self::Third(ref e) => write_err!(f, "third decoder error"; e),
            Self::Fourth(ref e) => write_err!(f, "fourth decoder error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl<A, B, C, D> std::error::Error for Decoder4Error<A, B, C, D>
where
    A: std::error::Error + 'static,
    B: std::error::Error + 'static,
    C: std::error::Error + 'static,
    D: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::First(ref e) => Some(e),
            Self::Second(ref e) => Some(e),
            Self::Third(ref e) => Some(e),
            Self::Fourth(ref e) => Some(e),
        }
    }
}

/// Error type for [`Decoder6`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoder6Error<A, B, C, D, E, F> {
    /// Error from the first decoder.
    First(A),
    /// Error from the second decoder.
    Second(B),
    /// Error from the third decoder.
    Third(C),
    /// Error from the fourth decoder.
    Fourth(D),
    /// Error from the fifth decoder.
    Fifth(E),
    /// Error from the sixth decoder.
    Sixth(F),
}

impl<A, B, C, D, E, F> fmt::Display for Decoder6Error<A, B, C, D, E, F>
where
    A: fmt::Display,
    B: fmt::Display,
    C: fmt::Display,
    D: fmt::Display,
    E: fmt::Display,
    F: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::First(ref e) => write_err!(f, "first decoder error"; e),
            Self::Second(ref e) => write_err!(f, "second decoder error"; e),
            Self::Third(ref e) => write_err!(f, "third decoder error"; e),
            Self::Fourth(ref e) => write_err!(f, "fourth decoder error"; e),
            Self::Fifth(ref e) => write_err!(f, "fifth decoder error"; e),
            Self::Sixth(ref e) => write_err!(f, "sixth decoder error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl<A, B, C, D, E, F> std::error::Error for Decoder6Error<A, B, C, D, E, F>
where
    A: std::error::Error + 'static,
    B: std::error::Error + 'static,
    C: std::error::Error + 'static,
    D: std::error::Error + 'static,
    E: std::error::Error + 'static,
    F: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::First(ref e) => Some(e),
            Self::Second(ref e) => Some(e),
            Self::Third(ref e) => Some(e),
            Self::Fourth(ref e) => Some(e),
            Self::Fifth(ref e) => Some(e),
            Self::Sixth(ref e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::vec;
    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;
    #[cfg(feature = "alloc")]
    use core::iter;
    #[cfg(feature = "std")]
    use std::io::Cursor;

    use super::*;

    // Stress test the push_bytes impl by passing in a single byte slice repeatedly.
    macro_rules! check_decode_one_byte_at_a_time {
        ($decoder:ident $($test_name:ident, $want:expr, $array:expr);* $(;)?) => {
            $(
                #[test]
                #[allow(non_snake_case)]
                fn $test_name() {
                    let mut decoder = $decoder::default();

                    for (i, _) in $array.iter().enumerate() {
                        if i < $array.len() - 1 {
                            let mut p = &$array[i..i+1];
                            assert!(decoder.push_bytes(&mut p).unwrap());
                        } else {
                            // last byte: `push_bytes` should return false since no more bytes required.
                            let mut p = &$array[i..];
                            assert!(!decoder.push_bytes(&mut p).unwrap());
                        }
                    }

                    let got = decoder.end().unwrap();
                    assert_eq!(got, $want);
                }
            )*

        }
    }

    check_decode_one_byte_at_a_time! {
        CompactSizeDecoder
        decode_compact_size_0x10, 0x10, [0x10];
        decode_compact_size_0xFC, 0xFC, [0xFC];
        decode_compact_size_0xFD, 0xFD, [0xFD, 0xFD, 0x00];
        decode_compact_size_0x100, 0x100, [0xFD, 0x00, 0x01];
        decode_compact_size_0xFFF, 0x0FFF, [0xFD, 0xFF, 0x0F];
        decode_compact_size_0x0F0F_0F0F, 0x0F0F_0F0F, [0xFE, 0xF, 0xF, 0xF, 0xF];
        decode_compact_size_0xF0F0_F0F0_F0E0, 0xF0F0_F0F0_F0E0, [0xFF, 0xE0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0, 0];
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn compact_size_zero() {
        // Zero (eg for an empty vector) with a couple of arbitrary extra bytes.
        let encoded = alloc::vec![0x00, 0xFF, 0xFF];

        let mut slice = encoded.as_slice();
        let mut decoder = CompactSizeDecoder::new();
        assert!(!decoder.push_bytes(&mut slice).unwrap());

        let got = decoder.end().unwrap();
        assert_eq!(got, 0);
    }

    #[cfg(feature = "alloc")]
    fn two_fifty_six_bytes_encoded() -> Vec<u8> {
        let data = [0xff; 256];
        let mut v = Vec::with_capacity(259);

        v.extend_from_slice(&[0xFD, 0x00, 0x01]); // 256 encoded as a  compact size.
        v.extend_from_slice(&data);
        v
    }

    #[cfg(feature = "alloc")]
    check_decode_one_byte_at_a_time! {
        ByteVecDecoder
            decode_byte_vec, alloc::vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        [0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
            decode_byte_vec_multi_byte_length_prefix, [0xff; 256], two_fifty_six_bytes_encoded();
    }

    #[cfg(feature = "alloc")]
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Inner(u32);

    /// The decoder for the [`Inner`] type.
    #[cfg(feature = "alloc")]
    pub struct InnerDecoder(ArrayDecoder<4>);

    #[cfg(feature = "alloc")]
    impl Decoder for InnerDecoder {
        type Output = Inner;
        type Error = UnexpectedEofError;

        fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
            self.0.push_bytes(bytes)
        }

        fn end(self) -> Result<Self::Output, Self::Error> {
            let n = u32::from_le_bytes(self.0.end()?);
            Ok(Inner(n))
        }

        fn read_limit(&self) -> usize { self.0.read_limit() }
    }

    #[cfg(feature = "alloc")]
    impl Decodable for Inner {
        type Decoder = InnerDecoder;
        fn decoder() -> Self::Decoder { InnerDecoder(ArrayDecoder::<4>::new()) }
    }

    #[cfg(feature = "alloc")]
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Test(Vec<Inner>);

    /// The decoder for the [`Test`] type.
    #[cfg(feature = "alloc")]
    #[derive(Default)]
    pub struct TestDecoder(VecDecoder<Inner>);

    #[cfg(feature = "alloc")]
    impl Decoder for TestDecoder {
        type Output = Test;
        type Error = VecDecoderError<UnexpectedEofError>;

        fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
            self.0.push_bytes(bytes)
        }

        fn end(self) -> Result<Self::Output, Self::Error> {
            let v = self.0.end()?;
            Ok(Test(v))
        }

        fn read_limit(&self) -> usize { self.0.read_limit() }
    }

    #[cfg(feature = "alloc")]
    impl Decodable for Test {
        type Decoder = TestDecoder;
        fn decoder() -> Self::Decoder { TestDecoder(VecDecoder::new()) }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn vec_decoder_empty() {
        // Empty with a couple of arbitrary extra bytes.
        let encoded = vec![0x00, 0xFF, 0xFF];

        let mut slice = encoded.as_slice();
        let mut decoder = Test::decoder();
        assert!(!decoder.push_bytes(&mut slice).unwrap());

        let got = decoder.end().unwrap();
        let want = Test(vec![]);

        assert_eq!(got, want);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn vec_decoder_one_item() {
        let encoded = vec![0x01, 0xEF, 0xBE, 0xAD, 0xDE];

        let mut slice = encoded.as_slice();
        let mut decoder = Test::decoder();
        decoder.push_bytes(&mut slice).unwrap();

        let got = decoder.end().unwrap();
        let want = Test(vec![Inner(0xDEAD_BEEF)]);

        assert_eq!(got, want);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn vec_decoder_two_items() {
        let encoded = vec![0x02, 0xEF, 0xBE, 0xAD, 0xDE, 0xBE, 0xBA, 0xFE, 0xCA];

        let mut slice = encoded.as_slice();
        let mut decoder = Test::decoder();
        decoder.push_bytes(&mut slice).unwrap();

        let got = decoder.end().unwrap();
        let want = Test(vec![Inner(0xDEAD_BEEF), Inner(0xCAFE_BABE)]);

        assert_eq!(got, want);
    }

    #[cfg(feature = "alloc")]
    fn two_fifty_six_elements() -> Test {
        Test(iter::repeat(Inner(0xDEAD_BEEF)).take(256).collect())
    }

    #[cfg(feature = "alloc")]
    fn two_fifty_six_elements_encoded() -> Vec<u8> {
        [0xFD, 0x00, 0x01] // 256 encoded as a  compact size.
            .into_iter()
            .chain(iter::repeat(0xDEAD_BEEF_u32.to_le_bytes()).take(256).flatten())
            .collect()
    }

    #[cfg(feature = "alloc")]
    check_decode_one_byte_at_a_time! {
        TestDecoder
            decode_vec, Test(vec![Inner(0xDEAD_BEEF), Inner(0xCAFE_BABE)]),
        vec![0x02, 0xEF, 0xBE, 0xAD, 0xDE, 0xBE, 0xBA, 0xFE, 0xCA];
            decode_vec_multi_byte_length_prefix, two_fifty_six_elements(), two_fifty_six_elements_encoded();
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn vec_decoder_one_item_plus_more_data() {
        // One u32 plus some other bytes.
        let encoded = vec![0x01, 0xEF, 0xBE, 0xAD, 0xDE, 0xff, 0xff, 0xff, 0xff];

        let mut slice = encoded.as_slice();

        let mut decoder = Test::decoder();
        decoder.push_bytes(&mut slice).unwrap();

        let got = decoder.end().unwrap();
        let want = Test(vec![Inner(0xDEAD_BEEF)]);

        assert_eq!(got, want);
    }

    #[cfg(feature = "std")]
    #[test]
    fn decode_vec_from_read_unbuffered_success() {
        let encoded = [0x01, 0xEF, 0xBE, 0xAD, 0xDE, 0xff, 0xff, 0xff, 0xff];
        let mut cursor = Cursor::new(&encoded);

        let got = crate::decode_from_read_unbuffered::<Test, _>(&mut cursor).unwrap();
        assert_eq!(cursor.position(), 5);

        let want = Test(vec![Inner(0xDEAD_BEEF)]);
        assert_eq!(got, want);
    }
}
