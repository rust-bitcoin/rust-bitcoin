// SPDX-License-Identifier: CC0-1.0

//! Primitive decoders.

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
