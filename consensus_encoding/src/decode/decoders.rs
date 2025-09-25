// SPDX-License-Identifier: CC0-1.0

//! Primitive decoders.

use core::fmt;

use super::Decoder;

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

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        if self.bytes_written == N {
            Ok(self.buffer)
        } else {
            Err(UnexpectedEofError { missing: N - self.bytes_written })
        }
    }

    #[inline]
    fn min_bytes_needed(&self) -> usize { N - self.bytes_written }
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

    #[inline]
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

    #[inline]
    fn min_bytes_needed(&self) -> usize {
        match &self.state {
            Decoder2State::First(first_decoder, second_decoder) =>
                first_decoder.min_bytes_needed() + second_decoder.min_bytes_needed(),
            Decoder2State::Second(_, second_decoder) => second_decoder.min_bytes_needed(),
            Decoder2State::Errored => 0,
            Decoder2State::Transitioning => 0,
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

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.inner.push_bytes(bytes)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let ((first, second), third) = self.inner.end()?;
        Ok((first, second, third))
    }

    #[inline]
    fn min_bytes_needed(&self) -> usize { self.inner.min_bytes_needed() }
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

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.inner.push_bytes(bytes)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let ((first, second), (third, fourth)) = self.inner.end()?;
        Ok((first, second, third, fourth))
    }

    #[inline]
    fn min_bytes_needed(&self) -> usize { self.inner.min_bytes_needed() }
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

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.inner.push_bytes(bytes)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let ((first, second, third), (fourth, fifth, sixth)) = self.inner.end()?;
        Ok((first, second, third, fourth, fifth, sixth))
    }

    #[inline]
    fn min_bytes_needed(&self) -> usize { self.inner.min_bytes_needed() }
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

    fn min_bytes_needed(&self) -> usize {
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
        let mut decoder = CompactSizeDecoder::default();
        assert!(!decoder.push_bytes(&mut slice).unwrap());

        let got = decoder.end().unwrap();
        assert_eq!(got, 0);
    }
}
