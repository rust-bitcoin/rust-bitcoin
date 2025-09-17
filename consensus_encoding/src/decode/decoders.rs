// SPDX-License-Identifier: CC0-1.0

//! Primitive decoders.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt;

use internals::write_err;

use super::Decoder;

/// A decoder that decodes a byte vector.
///
/// The decoding is expected to start with expected number of bytes (compact size encoded integer).
#[cfg(feature = "alloc")]
pub struct VecDecoder {
    buffer: Vec<u8>,
    length_read: bool, // true if the length prefix has been read.
    bytes_expected: usize,
    bytes_written: usize,
}

impl VecDecoder {
    /// Constructs a new byte decoder.
    pub fn new() -> Self {
        Self { buffer: Vec::new(), length_read: false, bytes_expected: 0, bytes_written: 0 }
    }
}

impl Default for VecDecoder {
    fn default() -> Self { Self::new() }
}

impl Decoder for VecDecoder {
    type Output = Vec<u8>;
    type Error = VecDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        // First call to `push_bytes`.
        if !self.length_read {
            let length =
                super::decode_compact_size(bytes).map_err(VecDecoderError::CompactSizeDecode)?;

            self.length_read = true;
            self.bytes_expected = cast_to_usize_if_valid(length)?;
            self.buffer = Vec::with_capacity(length as usize);
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
        if self.bytes_written == self.bytes_expected {
            Ok(self.buffer)
        } else {
            Err(UnexpectedEofError { missing: self.bytes_expected - self.bytes_written }.into())
        }
    }
}

// Minimum size of witness element is 1 byte, so if the count is
// greater than MAX_VEC_SIZE we must return an error.
fn cast_to_usize_if_valid(n: u64) -> Result<usize, VecDecoderError> {
    /// Maximum size, in bytes, of a vector we are allowed to decode.
    const MAX_VEC_SIZE: u64 = 4_000_000;

    if n > MAX_VEC_SIZE {
        return Err(VecDecoderError::InvalidCompactSize(n));
    }

    // Cast ok because within range for a 32-machine.
    Ok(n as usize)
}

/// A decoder that expects exactly N bytes and returns them as an array.
pub struct ArrayDecoder<const N: usize> {
    buffer: [u8; N],
    bytes_written: usize,
}

impl<const N: usize> ArrayDecoder<N> {
    /// Constructs a new array decoder that expects exactly N bytes.
    pub fn new() -> Self { Self { buffer: [0; N], bytes_written: 0 } }
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

    fn end(self) -> Result<Self::Output, Self::Error> {
        if self.bytes_written == N {
            Ok(self.buffer)
        } else {
            Err(UnexpectedEofError { missing: N - self.bytes_written })
        }
    }
}

/// A decoder which decodes two objects, one after the other.
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
    /// Temporary state during transitions from First to Second, should never be observed.
    Transitioning,
}

impl<A: Decoder, B: Decoder> Decoder2State<A, B> {
    /// Transitions from the first state to second by extracting both decoders.
    ///
    /// We use `mem::replace` to atomically swap the entire state, giving us
    /// ownership of the decoders so we can consume the first decoder while
    /// holding a mutable reference to the state.
    ///
    /// If this method is called when not in the `First` state, we panic
    /// with `#[track_caller]` to show where the bug occurred.
    #[track_caller]
    fn transition(&mut self) -> (A, B) {
        match core::mem::replace(self, Decoder2State::Transitioning) {
            Decoder2State::First(first, second) => (first, second),
            _ => panic!("transition called on invalid state"),
        }
    }
}

impl<A, B> Decoder2<A, B>
where
    A: Decoder,
    B: Decoder,
{
    /// Constructs a new composite decoder.
    pub fn new(first: A, second: B) -> Self { Self { state: Decoder2State::First(first, second) } }
}

impl<A, B> Decoder for Decoder2<A, B>
where
    A: Decoder,
    B: Decoder,
{
    type Output = (A::Output, B::Output);
    type Error = Either<A::Error, B::Error>;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        loop {
            match &mut self.state {
                Decoder2State::First(first_decoder, _) => {
                    if first_decoder.push_bytes(bytes).map_err(Either::First)? {
                        // First decoder wants more data.
                        return Ok(true);
                    }

                    // First decoder is complete, transition to second.
                    let (first, second) = self.state.transition();
                    let first_result = first.end().map_err(|error| {
                        self.state = Decoder2State::Errored;
                        Either::First(error)
                    })?;
                    self.state = Decoder2State::Second(first_result, second);
                }
                Decoder2State::Second(_, second_decoder) => {
                    return second_decoder.push_bytes(bytes).map_err(|error| {
                        self.state = Decoder2State::Errored;
                        Either::Second(error)
                    });
                }
                Decoder2State::Errored => {
                    panic!("use of failed decoder");
                }
                Decoder2State::Transitioning => {
                    panic!("use of decoder in transitioning state");
                }
            }
        }
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        match self.state {
            Decoder2State::First(first_decoder, second_decoder) => {
                // This branch is most likely an error since the decoder
                // never got to the second one. But letting the error bubble
                // up naturally from the child decoders.
                let first_result = first_decoder.end().map_err(Either::First)?;
                let second_result = second_decoder.end().map_err(Either::Second)?;
                Ok((first_result, second_result))
            }
            Decoder2State::Second(first_result, second_decoder) => {
                let second_result = second_decoder.end().map_err(Either::Second)?;
                Ok((first_result, second_result))
            }
            Decoder2State::Errored => {
                panic!("use of failed decoder");
            }
            Decoder2State::Transitioning => {
                panic!("use of decoder in transitioning state");
            }
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
    pub fn new(dec_1: A, dec_2: B, dec_3: C) -> Self {
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
    type Error = Either<Either<A::Error, B::Error>, C::Error>;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.inner.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let ((first, second), third) = self.inner.end()?;
        Ok((first, second, third))
    }
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
    pub fn new(dec_1: A, dec_2: B, dec_3: C, dec_4: D) -> Self {
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
    type Error = Either<Either<A::Error, B::Error>, Either<C::Error, D::Error>>;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.inner.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let ((first, second), (third, fourth)) = self.inner.end()?;
        Ok((first, second, third, fourth))
    }
}

/// A decoder which decodes six objects, one after the other.
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
    pub fn new(dec_1: A, dec_2: B, dec_3: C, dec_4: D, dec_5: E, dec_6: F) -> Self {
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
    type Error = Either<
        Either<Either<A::Error, B::Error>, C::Error>,
        Either<Either<D::Error, E::Error>, F::Error>,
    >;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.inner.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let ((first, second, third), (fourth, fifth, sixth)) = self.inner.end()?;
        Ok((first, second, third, fourth, fifth, sixth))
    }
}

/// A sum type representing one of two possible decoder errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Either<F, S> {
    /// The first variant.
    First(F),
    /// The second variant.
    Second(S),
}

impl<F, S> core::fmt::Display for Either<F, S>
where
    F: core::fmt::Display,
    S: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Either::First(first) => first.fmt(f),
            Either::Second(second) => second.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl<F, S> std::error::Error for Either<F, S>
where
    F: std::error::Error,
    S: std::error::Error,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Either::First(first) => first.source(),
            Either::Second(second) => second.source(),
        }
    }
}

/// The error returned by the [`VecDecoder`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VecDecoderError {
    /// Error decoding the byte vector length prefix.
    CompactSizeDecode(super::CompactSizeDecodeError),
    /// Length prefix exceeds 4,000,000.
    InvalidCompactSize(u64),
    /// Not enough bytes given to decoder.
    UnexpectedEof(UnexpectedEofError),
}

impl From<Infallible> for VecDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl From<UnexpectedEofError> for VecDecoderError {
    fn from(e: UnexpectedEofError) -> Self { Self::UnexpectedEof(e) }
}

impl fmt::Display for VecDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::CompactSizeDecode(ref e) => write_err!(f, "vec decoder error"; e),
            Self::InvalidCompactSize(n) =>
                write!(f, "Invalid length prefix (exceeds 4,000,000): {}", n),
            Self::UnexpectedEof(ref e) => write_err!(f, "vec decoder error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VecDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::CompactSizeDecode(ref e) => Some(e),
            Self::InvalidCompactSize(_) => None,
            Self::UnexpectedEof(ref e) => Some(e),
        }
    }
}

/// Not enough bytes given to decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnexpectedEofError {
    /// Number of bytes missing to complete decoder.
    missing: usize,
}

impl core::fmt::Display for UnexpectedEofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "not enough bytes for decoder, {} more bytes required", self.missing)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnexpectedEofError {}
