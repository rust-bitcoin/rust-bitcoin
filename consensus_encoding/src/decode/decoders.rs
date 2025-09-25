// SPDX-License-Identifier: CC0-1.0

//! Primitive decoders.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use core::convert::Infallible;
use core::marker::PhantomData;
use core::{fmt, mem};

#[cfg(feature = "alloc")]
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
    prefix_read: bool, // true if the length prefix has been read.
    buffer: Vec<u8>,
    bytes_expected: usize,
    bytes_written: usize,
}

#[cfg(feature = "alloc")]
impl ByteVecDecoder {
    /// Constructs a new byte decoder.
    pub fn new() -> Self {
        Self {
            prefix_decoder: None,
            prefix_read: false,
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

        if !self.prefix_read {
            let mut decoder = self.prefix_decoder.take().unwrap_or_default();

            if decoder.push_bytes(bytes).map_err(|e| E(Inner::LengthPrefixDecode(e)))? {
                self.prefix_decoder = Some(decoder);
                return Ok(true);
            }
            let length = decoder.end().map_err(|e| E(Inner::LengthPrefixDecode(e)))?;

            self.prefix_read = true;
            self.bytes_expected =
                cast_to_usize_if_valid(length).map_err(|e| E(Inner::LengthPrefixInvalid(e)))?;

            // `cast_to_usize_if_valid` asserts length < 4,000,000, so no DoS vector here.
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
        use {ByteVecDecoderError as E, ByteVecDecoderErrorInner as Inner};

        if self.bytes_written == self.bytes_expected {
            Ok(self.buffer)
        } else {
            Err(E(Inner::UnexpectedEof(UnexpectedEofError {
                missing: self.bytes_expected - self.bytes_written,
            })))
        }
    }
}

/// A decoder that decodes a vector of `T`s.
///
/// The decoding is expected to start with expected number of items in the vector.
#[cfg(feature = "alloc")]
pub struct VecDecoder<T: Decodable> {
    prefix_decoder: Option<CompactSizeDecoder>,
    prefix_read: bool, // true if the length prefix has been read.
    length: usize,
    buffer: Vec<T>,

    decoder: Option<<T as Decodable>::Decoder>,
    _marker: PhantomData<T>,
}

#[cfg(feature = "alloc")]
impl<T: Decodable> VecDecoder<T> {
    /// Constructs a new byte decoder.
    pub fn new() -> Self {
        Self {
            prefix_decoder: None,
            prefix_read: false,
            length: 0,
            buffer: Vec::new(),
            decoder: None,
            _marker: PhantomData,
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

        if !self.prefix_read {
            let mut decoder = self.prefix_decoder.take().unwrap_or_default();

            if decoder.push_bytes(bytes).map_err(|e| E(Inner::LengthPrefixDecode(e)))? {
                self.prefix_decoder = Some(decoder);
                return Ok(true);
            }
            let length = decoder.end().map_err(|e| E(Inner::LengthPrefixDecode(e)))?;

            self.prefix_read = true;
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
}

/// Cast a decoded length prefix to a `usize`.
///
/// Consensus encoded vectors can be up to 4,000,000 bytes long. On 32-bit and 64-bit machines we
/// can cast to a `usize` and move on with our lives. On a 16-bit machine however one cannot address
/// that much memory so it is not possible to decode all consensus valid encoded objects.
///
/// # Errors
///
/// Errors if `n` is greater than 4,000,000.
// FIXME: Are we ok with this being public?
#[cfg(feature = "alloc")]
pub fn cast_to_usize_if_valid(n: u64) -> Result<usize, LengthPrefixExceedsMaxError> {
    if n > MAX_VEC_SIZE {
        return Err(LengthPrefixExceedsMaxError { value: n });
    }

    // 4,000,000 needs more than 16 bits.
    if mem::size_of::<usize>() <= 2 {
        return Err(LengthPrefixExceedsMaxError { value: n });
    }

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

/// A decoder which wraps two inner decoders and returns the output of both.
/// The error types of the inner decoders are mapped to a common type.
pub struct Decoder2<A, B, Err>
where
    A: Decoder,
    B: Decoder,
{
    state: Decoder2State<A, B>,
    _error: core::marker::PhantomData<Err>,
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

impl<A, B, Err> Decoder2<A, B, Err>
where
    A: Decoder,
    B: Decoder,
{
    /// Constructs a new composite decoder.
    pub fn new(first: A, second: B) -> Self {
        Self { state: Decoder2State::First(first, second), _error: core::marker::PhantomData }
    }
}

impl<A, B, Err> Decoder for Decoder2<A, B, Err>
where
    A: Decoder,
    B: Decoder,
    Err: From<A::Error> + From<B::Error>,
{
    type Output = (A::Output, B::Output);
    type Error = Err;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        loop {
            match &mut self.state {
                Decoder2State::First(first_decoder, _) => {
                    if first_decoder.push_bytes(bytes).map_err(Err::from)? {
                        // First decoder wants more data.
                        return Ok(true);
                    }

                    // First decoder is complete, transition to second.
                    let (first, second) = self.state.transition();
                    let first_result = first.end().map_err(|error| {
                        self.state = Decoder2State::Errored;
                        Err::from(error)
                    })?;
                    self.state = Decoder2State::Second(first_result, second);
                }
                Decoder2State::Second(_, second_decoder) => {
                    return second_decoder.push_bytes(bytes).map_err(|error| {
                        self.state = Decoder2State::Errored;
                        Err::from(error)
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
                let first_result = first_decoder.end().map_err(Err::from)?;
                let second_result = second_decoder.end().map_err(Err::from)?;
                Ok((first_result, second_result))
            }
            Decoder2State::Second(first_result, second_decoder) => {
                let second_result = second_decoder.end().map_err(Err::from)?;
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
pub struct Decoder3<A, B, C, Err>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
    Err: From<A::Error> + From<B::Error> + From<C::Error>,
{
    inner: Decoder2<Decoder2<A, B, Err>, C, Err>,
    _error: core::marker::PhantomData<Err>,
}

impl<A, B, C, Err> Decoder3<A, B, C, Err>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
    Err: From<A::Error> + From<B::Error> + From<C::Error>,
{
    /// Constructs a new composite decoder.
    pub fn new(dec_1: A, dec_2: B, dec_3: C) -> Self {
        Self {
            inner: Decoder2::new(Decoder2::new(dec_1, dec_2), dec_3),
            _error: core::marker::PhantomData,
        }
    }
}

impl<A, B, C, Err> Decoder for Decoder3<A, B, C, Err>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
    Err: From<A::Error> + From<B::Error> + From<C::Error>,
{
    type Output = (A::Output, B::Output, C::Output);
    type Error = Err;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.inner.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let ((first, second), third) = self.inner.end()?;
        Ok((first, second, third))
    }
}

/// A decoder which decodes four objects, one after the other.
pub struct Decoder4<A, B, C, D, Err>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
    D: Decoder,
    Err: From<A::Error> + From<B::Error> + From<C::Error> + From<D::Error>,
{
    inner: Decoder2<Decoder2<A, B, Err>, Decoder2<C, D, Err>, Err>,
    _error: core::marker::PhantomData<Err>,
}

impl<A, B, C, D, Err> Decoder4<A, B, C, D, Err>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
    D: Decoder,
    Err: From<A::Error> + From<B::Error> + From<C::Error> + From<D::Error>,
{
    /// Constructs a new composite decoder.
    pub fn new(dec_1: A, dec_2: B, dec_3: C, dec_4: D) -> Self {
        Self {
            inner: Decoder2::new(Decoder2::new(dec_1, dec_2), Decoder2::new(dec_3, dec_4)),
            _error: core::marker::PhantomData,
        }
    }
}

impl<A, B, C, D, Err> Decoder for Decoder4<A, B, C, D, Err>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
    D: Decoder,
    Err: From<A::Error> + From<B::Error> + From<C::Error> + From<D::Error>,
{
    type Output = (A::Output, B::Output, C::Output, D::Output);
    type Error = Err;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.inner.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let ((first, second), (third, fourth)) = self.inner.end()?;
        Ok((first, second, third, fourth))
    }
}

/// A decoder which decodes six objects, one after the other.
#[allow(clippy::type_complexity)] // Nested composition is easier than flattened alternatives.
pub struct Decoder6<A, B, C, D, E, F, Err>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
    D: Decoder,
    E: Decoder,
    F: Decoder,
    Err: From<A::Error>
        + From<B::Error>
        + From<C::Error>
        + From<D::Error>
        + From<E::Error>
        + From<F::Error>,
{
    inner: Decoder2<Decoder3<A, B, C, Err>, Decoder3<D, E, F, Err>, Err>,
    _error: core::marker::PhantomData<Err>,
}

impl<A, B, C, D, E, F, Err> Decoder6<A, B, C, D, E, F, Err>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
    D: Decoder,
    E: Decoder,
    F: Decoder,
    Err: From<A::Error>
        + From<B::Error>
        + From<C::Error>
        + From<D::Error>
        + From<E::Error>
        + From<F::Error>,
{
    /// Constructs a new composite decoder.
    pub fn new(dec_1: A, dec_2: B, dec_3: C, dec_4: D, dec_5: E, dec_6: F) -> Self {
        Self {
            inner: Decoder2::new(
                Decoder3::new(dec_1, dec_2, dec_3),
                Decoder3::new(dec_4, dec_5, dec_6),
            ),
            _error: core::marker::PhantomData,
        }
    }
}

impl<A, B, C, D, E, F, Err> Decoder for Decoder6<A, B, C, D, E, F, Err>
where
    A: Decoder,
    B: Decoder,
    C: Decoder,
    D: Decoder,
    E: Decoder,
    F: Decoder,
    Err: From<A::Error>
        + From<B::Error>
        + From<C::Error>
        + From<D::Error>
        + From<E::Error>
        + From<F::Error>,
{
    type Output = (A::Output, B::Output, C::Output, D::Output, E::Output, F::Output);
    type Error = Err;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.inner.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let ((first, second, third), (fourth, fifth, sixth)) = self.inner.end()?;
        Ok((first, second, third, fourth, fifth, sixth))
    }
}

/// Decodes a compact size encoded integer.
///
/// For more information about decoder see the documentation of the [`Decoder`] trait.
#[derive(Default, Debug, Clone)]
pub struct CompactSizeDecoder {
    buf: internals::array_vec::ArrayVec<u8, 9>,
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
            E::UnexpectedEof { required: 1, received: 0 } =>
                write!(f, "required at least one byte but the input is empty"),
            E::UnexpectedEof { required, received: 0 } =>
                write!(f, "required at least {} bytes but the input is empty", required),
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
            1 => u8::MAX as u32,
            2 => u16::MAX as u32,
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

impl core::fmt::Display for UnexpectedEofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "not enough bytes for decoder, {} more bytes required", self.missing)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnexpectedEofError {}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::vec;
    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn compact_size_multiple_pushes() {
        let want = u64::MAX;
        let encoded = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xAB, 0xBC];

        let mut a = &encoded[..1];
        let mut b = &encoded[1..3];
        let mut c = &encoded[3..];

        let mut decoder = CompactSizeDecoder::default();

        let more_required = decoder.push_bytes(&mut a).unwrap();
        assert!(more_required);

        let more_required = decoder.push_bytes(&mut b).unwrap();
        assert!(more_required);

        let more_required = decoder.push_bytes(&mut c).unwrap();
        assert!(!more_required);

        let got = decoder.end().unwrap();
        assert_eq!(got, want);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn byte_vec_decoder_multiple_pushes() {
        let encoded = [0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let want = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

        let mut a = &encoded[..1];
        let mut b = &encoded[1..5];
        let mut c = &encoded[5..];

        let mut decoder = ByteVecDecoder::default();

        decoder.push_bytes(&mut a).unwrap();
        decoder.push_bytes(&mut b).unwrap();
        decoder.push_bytes(&mut c).unwrap();

        let got = decoder.end().unwrap();
        assert_eq!(got, want);
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

        #[inline]
        fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
            self.0.push_bytes(bytes)
        }

        #[inline]
        fn end(self) -> Result<Self::Output, Self::Error> {
            let n = u32::from_le_bytes(self.0.end()?);
            Ok(Inner(n))
        }
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
    pub struct TestDecoder(VecDecoder<Inner>);

    #[cfg(feature = "alloc")]
    impl Decoder for TestDecoder {
        type Output = Test;
        type Error = VecDecoderError<UnexpectedEofError>;

        #[inline]
        fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
            self.0.push_bytes(bytes)
        }

        #[inline]
        fn end(self) -> Result<Self::Output, Self::Error> {
            let v = self.0.end()?;
            Ok(Test(v))
        }
    }

    #[cfg(feature = "alloc")]
    impl Decodable for Test {
        type Decoder = TestDecoder;
        fn decoder() -> Self::Decoder { TestDecoder(VecDecoder::new()) }
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
    fn vec_decoder_multiple_calls_to_push_bytes() {
        let encoded = vec![0x02, 0xEF, 0xBE, 0xAD, 0xDE, 0xBE, 0xBA, 0xFE, 0xCA];

        let mut a = &encoded.as_slice()[..2]; // 0x02, 0xEF
        let mut b = &encoded.as_slice()[2..5]; // 0xBE, 0xAD
        let mut c = &encoded.as_slice()[5..]; // 0xDE, 0xBE, 0xBA, 0xFE, 0xCA
        let mut decoder = Test::decoder();
        decoder.push_bytes(&mut a).unwrap();
        decoder.push_bytes(&mut b).unwrap();
        decoder.push_bytes(&mut c).unwrap();

        let got = decoder.end().unwrap();
        let want = Test(vec![Inner(0xDEAD_BEEF), Inner(0xCAFE_BABE)]);

        assert_eq!(got, want);
    }
}
