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
#[cfg(feature = "alloc")]
use crate::compact_size::{CompactSizeDecoder, CompactSizeDecoderError};

/// Maximum amount of memory (in bytes) to allocate at once when deserializing vectors.
#[cfg(feature = "alloc")]
const MAX_VECTOR_ALLOCATE: usize = 1_000_000;

/// A decoder that decodes a byte vector.
///
/// The encoding is expected to start with the number of encoded bytes (length prefix).
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
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

    /// Reserves capacity for byte vectors in batches.
    ///
    /// Reserves up to `MAX_VECTOR_ALLOCATE` bytes when the buffer has no remaining capacity.
    ///
    /// Documentation adapted from Bitcoin Core:
    ///
    /// > For `DoS` prevention, do not blindly allocate as much as the stream claims to contain.
    /// > Instead, allocate in ~1 MB batches, so that an attacker actually needs to provide X MB of
    /// > data to make us allocate X+1 MB of memory.
    ///
    /// ref: <https://github.com/bitcoin/bitcoin/blob/72511fd02e72b74be11273e97bd7911786a82e54/src/serialize.h#L669C2-L672C1>
    fn reserve(&mut self) {
        if self.buffer.len() == self.buffer.capacity() {
            let bytes_remaining = self.bytes_expected - self.bytes_written;
            let batch_size = bytes_remaining.min(MAX_VECTOR_ALLOCATE);
            self.buffer.reserve_exact(batch_size);
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
        use ByteVecDecoderError as E;
        use ByteVecDecoderErrorInner as Inner;

        if let Some(mut decoder) = self.prefix_decoder.take() {
            if decoder.push_bytes(bytes).map_err(|e| E(Inner::LengthPrefixDecode(e)))? {
                self.prefix_decoder = Some(decoder);
                return Ok(true);
            }
            self.bytes_expected = decoder.end().map_err(|e| E(Inner::LengthPrefixDecode(e)))?;
            self.prefix_decoder = None;

            // For DoS prevention, let's not allocate all memory upfront.
        }

        self.reserve();

        let remaining = self.bytes_expected - self.bytes_written;
        let available_capacity = self.buffer.capacity() - self.buffer.len();
        let copy_len = bytes.len().min(remaining).min(available_capacity);

        self.buffer.extend_from_slice(&bytes[..copy_len]);
        self.bytes_written += copy_len;
        *bytes = &bytes[copy_len..];

        // Return true if we still need more data.
        Ok(self.bytes_written < self.bytes_expected)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        use ByteVecDecoderError as E;
        use ByteVecDecoderErrorInner as Inner;

        if let Some(ref prefix_decoder) = self.prefix_decoder {
            return Err(E(Inner::UnexpectedEof(UnexpectedEofError {
                missing: prefix_decoder.read_limit(),
            })));
        }

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
impl<T: Decodable> fmt::Debug for VecDecoder<T>
where
    T::Decoder: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VecDecoder")
            .field("prefix_decoder", &self.prefix_decoder)
            .field("length", &self.length)
            // Print the count rather than contents to avoid requiring `T: Debug`.
            .field("buffer_len", &self.buffer.len())
            .field("decoder", &self.decoder)
            .finish()
    }
}

#[cfg(feature = "alloc")]
impl<T: Decodable> Clone for VecDecoder<T>
where
    T: Clone,
    T::Decoder: Clone,
{
    fn clone(&self) -> Self {
        Self {
            prefix_decoder: self.prefix_decoder.clone(),
            length: self.length,
            buffer: self.buffer.clone(),
            decoder: self.decoder.clone(),
        }
    }
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

    /// Reserves capacity for typed vectors in batches.
    ///
    /// Calculates how many elements of type `T` fit within `MAX_VECTOR_ALLOCATE` bytes and reserves
    /// up to that amount when the buffer reaches capacity.
    ///
    /// Documentation adapted from Bitcoin Core:
    ///
    /// > For `DoS` prevention, do not blindly allocate as much as the stream claims to contain.
    /// > Instead, allocate in ~1 MB batches, so that an attacker actually needs to provide X MB of
    /// > data to make us allocate X+1 MB of memory.
    ///
    /// ref: <https://github.com/bitcoin/bitcoin/blob/72511fd02e72b74be11273e97bd7911786a82e54/src/serialize.h#L669C2-L672C1>
    fn reserve(&mut self) {
        if self.buffer.len() == self.buffer.capacity() {
            let elements_remaining = self.length - self.buffer.len();
            let element_size = mem::size_of::<T>().max(1);
            let batch_elements = MAX_VECTOR_ALLOCATE / element_size;
            let elements_to_reserve = elements_remaining.min(batch_elements);
            self.buffer.reserve_exact(elements_to_reserve);
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
        use VecDecoderError as E;
        use VecDecoderErrorInner as Inner;

        if let Some(mut decoder) = self.prefix_decoder.take() {
            if decoder.push_bytes(bytes).map_err(|e| E(Inner::LengthPrefixDecode(e)))? {
                self.prefix_decoder = Some(decoder);
                return Ok(true);
            }
            self.length = decoder.end().map_err(|e| E(Inner::LengthPrefixDecode(e)))?;
            if self.length == 0 {
                return Ok(false);
            }

            self.prefix_decoder = None;

            // For DoS prevention, let's not allocate all memory upfront.
        }

        while !bytes.is_empty() {
            self.reserve();

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

/// A decoder that expects exactly N bytes and returns them as an array.
#[derive(Debug, Clone)]
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

impl<A, B> fmt::Debug for Decoder2<A, B>
where
    A: Decoder + fmt::Debug,
    B: Decoder + fmt::Debug,
    A::Output: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.state {
            Decoder2State::First(a, b) => f.debug_tuple("First").field(a).field(b).finish(),
            Decoder2State::Second(out, b) => f.debug_tuple("Second").field(out).field(b).finish(),
            Decoder2State::Errored => write!(f, "Errored"),
        }
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

impl<A, B, C> fmt::Debug for Decoder3<A, B, C>
where
    A: Decoder + fmt::Debug,
    B: Decoder + fmt::Debug,
    C: Decoder + fmt::Debug,
    A::Output: fmt::Debug,
    B::Output: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.inner.fmt(f) }
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

impl<A, B, C, D> fmt::Debug for Decoder4<A, B, C, D>
where
    A: Decoder + fmt::Debug,
    B: Decoder + fmt::Debug,
    C: Decoder + fmt::Debug,
    D: Decoder + fmt::Debug,
    A::Output: fmt::Debug,
    B::Output: fmt::Debug,
    C::Output: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.inner.fmt(f) }
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

/// The error returned by the [`ByteVecDecoder`].
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteVecDecoderError(ByteVecDecoderErrorInner);

#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum ByteVecDecoderErrorInner {
    /// Error decoding the byte vector length prefix.
    LengthPrefixDecode(CompactSizeDecoderError),
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
            E::Item(ref e) => Some(e),
            E::UnexpectedEof(ref e) => Some(e),
        }
    }
}

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

/// Helper macro to define an error type for a `DecoderN`.
macro_rules! define_decoder_n_error {
    (
        $(#[$attr:meta])*
        $name:ident;
        $(
            $(#[$err_attr:meta])*
            ($err_wrap:ident, $err_type:ident, $err_msg:literal),
        )*
    ) => {
        $(#[$attr])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $name<$($err_type,)*> {
            $(
                $(#[$err_attr])*
                $err_wrap($err_type),
            )*
        }

        impl<$($err_type,)*> fmt::Display for $name<$($err_type,)*>
        where
            $($err_type: fmt::Display,)*
        {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match self {
                    $(Self::$err_wrap(ref e) => write_err!(f, $err_msg; e),)*
                }
            }
        }

        #[cfg(feature = "std")]
        impl<$($err_type,)*> std::error::Error for $name<$($err_type,)*>
        where
            $($err_type: std::error::Error + 'static,)*
        {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    $(Self::$err_wrap(ref e) => Some(e),)*
                }
            }
        }
    };
}

define_decoder_n_error! {
    /// Error type for [`Decoder2`].
    Decoder2Error;
    /// Error from the first decoder.
    (First, A, "first decoder error."),
    /// Error from the second decoder.
    (Second, B, "second decoder error."),
}

define_decoder_n_error! {
    /// Error type for [`Decoder3`].
    Decoder3Error;
    /// Error from the first decoder.
    (First, A, "first decoder error."),
    /// Error from the second decoder.
    (Second, B, "second decoder error."),
    /// Error from the third decoder.
    (Third, C, "third decoder error."),
}

define_decoder_n_error! {
    /// Error type for [`Decoder4`].
    Decoder4Error;
    /// Error from the first decoder.
    (First, A, "first decoder error."),
    /// Error from the second decoder.
    (Second, B, "second decoder error."),
    /// Error from the third decoder.
    (Third, C, "third decoder error."),
    /// Error from the fourth decoder.
    (Fourth, D, "fourth decoder error."),
}

define_decoder_n_error! {
    /// Error type for [`Decoder6`].
    Decoder6Error;
    /// Error from the first decoder.
    (First, A, "first decoder error."),
    /// Error from the second decoder.
    (Second, B, "second decoder error."),
    /// Error from the third decoder.
    (Third, C, "third decoder error."),
    /// Error from the fourth decoder.
    (Fourth, D, "fourth decoder error."),
    /// Error from the fifth decoder.
    (Fifth, E, "fifth decoder error."),
    /// Error from the sixth decoder.
    (Sixth, F, "sixth decoder error."),
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::vec;
    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;

    #[cfg(feature = "alloc")]
    use super::*;

    #[test]
    #[cfg(feature = "alloc")]
    fn byte_vec_decoder_decode_empty_slice() {
        let mut decoder = ByteVecDecoder::new();
        let data = [];
        let _ = decoder.push_bytes(&mut data.as_slice());
        let err = decoder.end().unwrap_err();

        if let ByteVecDecoderErrorInner::UnexpectedEof(e) = err.0 {
            assert_eq!(e.missing, 1);
        } else {
            panic!("Expected UnexpectedEof error");
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn byte_vec_decoder_incomplete_0xfd_prefix() {
        let mut decoder = ByteVecDecoder::new();
        let data = [0xFD];
        let _ = decoder.push_bytes(&mut data.as_slice());
        let err = decoder.end().unwrap_err();

        if let ByteVecDecoderErrorInner::UnexpectedEof(e) = err.0 {
            assert_eq!(e.missing, 2);
        } else {
            panic!("Expected UnexpectedEof error");
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn byte_vec_decoder_incomplete_0xfe_prefix() {
        let mut decoder = ByteVecDecoder::new();
        let data = [0xFE];
        let _ = decoder.push_bytes(&mut data.as_slice());
        let err = decoder.end().unwrap_err();

        if let ByteVecDecoderErrorInner::UnexpectedEof(e) = err.0 {
            assert_eq!(e.missing, 4);
        } else {
            panic!("Expected UnexpectedEof error");
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn byte_vec_decoder_incomplete_0xff_prefix() {
        let mut decoder = ByteVecDecoder::new();
        let data = [0xFF];
        let _ = decoder.push_bytes(&mut data.as_slice());
        let err = decoder.end().unwrap_err();

        if let ByteVecDecoderErrorInner::UnexpectedEof(e) = err.0 {
            assert_eq!(e.missing, 8);
        } else {
            panic!("Expected UnexpectedEof error");
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn byte_vec_decoder_reserves_in_batches() {
        // A small number of extra bytes so we extend exactly by the remainder
        // instead of another full batch.
        let tail_length: usize = 11;

        let total_len = MAX_VECTOR_ALLOCATE + tail_length;
        let total_len_le = u32::try_from(total_len).expect("total_len fits u32").to_le_bytes();
        let mut decoder = ByteVecDecoder::new();

        let mut prefix = vec![0xFE]; // total_len_le is a compact size of four bytes.
        prefix.extend_from_slice(&total_len_le);
        prefix.push(0xAA);
        let mut prefix_slice = prefix.as_slice();
        decoder.push_bytes(&mut prefix_slice).expect("length plus first element");
        assert!(prefix_slice.is_empty());

        assert_eq!(decoder.buffer.capacity(), MAX_VECTOR_ALLOCATE);
        assert_eq!(decoder.buffer.len(), 1);
        assert_eq!(decoder.buffer[0], 0xAA);

        let fill = vec![0xBB; MAX_VECTOR_ALLOCATE - 1];
        let mut fill_slice = fill.as_slice();
        decoder.push_bytes(&mut fill_slice).expect("fills to batch boundary, full capacity");
        assert!(fill_slice.is_empty());

        assert_eq!(decoder.buffer.capacity(), MAX_VECTOR_ALLOCATE);
        assert_eq!(decoder.buffer.len(), MAX_VECTOR_ALLOCATE);
        assert_eq!(decoder.buffer[MAX_VECTOR_ALLOCATE - 1], 0xBB);

        let mut tail = vec![0xCC];
        tail.extend([0xDD].repeat(tail_length - 1));
        let mut tail_slice = tail.as_slice();
        decoder.push_bytes(&mut tail_slice).expect("fills the remaining bytes");
        assert!(tail_slice.is_empty());

        assert_eq!(decoder.buffer.capacity(), MAX_VECTOR_ALLOCATE + tail_length);
        assert_eq!(decoder.buffer.len(), total_len);
        assert_eq!(decoder.buffer[MAX_VECTOR_ALLOCATE], 0xCC);

        let result = decoder.end().unwrap();
        assert_eq!(result.len(), total_len);
        assert_eq!(result[total_len - 1], 0xDD);
    }

    #[cfg(feature = "alloc")]
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Inner(u32);

    /// The decoder for the [`Inner`] type.
    #[cfg(feature = "alloc")]
    #[derive(Clone)]
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
    #[derive(Clone, Default)]
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

    #[test]
    #[cfg(feature = "alloc")]
    fn vec_decoder_reserves_in_batches() {
        // A small number of extra elements so we extend exactly by the remainder
        // instead of another full batch.
        let tail_length: usize = 11;

        let element_size = core::mem::size_of::<Inner>();
        let batch_length = MAX_VECTOR_ALLOCATE / element_size;
        assert!(batch_length > 1);
        let total_len = batch_length + tail_length;
        let total_len_le = u32::try_from(total_len).expect("total_len fits u32").to_le_bytes();
        let mut decoder = Test::decoder();

        let mut prefix = vec![0xFE]; // total_len_le is a compact size of four bytes.
        prefix.extend_from_slice(&total_len_le);
        prefix.extend_from_slice(&0xAA_u32.to_le_bytes());
        let mut prefix_slice = prefix.as_slice();
        decoder.push_bytes(&mut prefix_slice).expect("length plus first element");
        assert!(prefix_slice.is_empty());

        assert_eq!(decoder.0.buffer.capacity(), batch_length);
        assert_eq!(decoder.0.buffer.len(), 1);
        assert_eq!(decoder.0.buffer[0], Inner(0xAA));

        let fill = 0xBB_u32.to_le_bytes().repeat(batch_length - 1);
        let mut fill_slice = fill.as_slice();
        decoder.push_bytes(&mut fill_slice).expect("fills to batch boundary, full capacity");
        assert!(fill_slice.is_empty());

        assert_eq!(decoder.0.buffer.capacity(), batch_length);
        assert_eq!(decoder.0.buffer.len(), batch_length);
        assert_eq!(decoder.0.buffer[batch_length - 1], Inner(0xBB));

        let mut tail = 0xCC_u32.to_le_bytes().to_vec();
        tail.extend(0xDD_u32.to_le_bytes().repeat(tail_length - 1));
        let mut tail_slice = tail.as_slice();
        decoder.push_bytes(&mut tail_slice).expect("fills the remaining bytes");
        assert!(tail_slice.is_empty());

        assert_eq!(decoder.0.buffer.capacity(), batch_length + tail_length);
        assert_eq!(decoder.0.buffer.len(), total_len);
        assert_eq!(decoder.0.buffer[batch_length], Inner(0xCC));

        let Test(result) = decoder.end().unwrap();
        assert_eq!(result.len(), total_len);
        assert_eq!(result[total_len - 1], Inner(0xDD));
    }
}
