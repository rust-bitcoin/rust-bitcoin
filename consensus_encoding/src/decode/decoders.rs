// SPDX-License-Identifier: CC0-1.0

//! Primitive decoders.

use super::Decoder;

/// Not enough bytes given to decoder.
#[derive(Debug, PartialEq, Eq)]
pub struct UnexpectedEof {
    /// Number of bytes missing to complete decoder.
    pub missing: usize,
}

impl core::fmt::Display for UnexpectedEof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "not enough bytes for decoder, {} more bytes required", self.missing)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnexpectedEof {}

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
    type Error = UnexpectedEof;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<(), Self::Error> {
        let remaining_space = N - self.bytes_written;
        let copy_len = bytes.len().min(remaining_space);

        if copy_len > 0 {
            self.buffer[self.bytes_written..self.bytes_written + copy_len]
                .copy_from_slice(&bytes[..copy_len]);
            self.bytes_written += copy_len;
            // Advance the slice reference to consume the bytes.
            *bytes = &bytes[copy_len..];
        }

        Ok(())
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        if self.bytes_written == N {
            Ok(self.buffer)
        } else {
            Err(UnexpectedEof { missing: N - self.bytes_written })
        }
    }
}

/// A decoder which decodes two objects, one after the other.
pub struct Decoder2<A: Decoder, B: Decoder> {
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

/// A sum type that can hold a value of either the first error or the second.
#[derive(Debug)]
pub enum Either<F, S> {
    /// The first error variant.
    First(F),
    /// The second error variant.
    Second(S),
}

impl<F: core::fmt::Display, S: core::fmt::Display> core::fmt::Display for Either<F, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Either::First(e) => write!(f, "first decoder error: {}", e),
            Either::Second(e) => write!(f, "second decoder error: {}", e),
        }
    }
}

#[cfg(feature = "std")]
impl<F: std::error::Error, S: std::error::Error> std::error::Error for Either<F, S> {}

impl<A, B> Decoder for Decoder2<A, B>
where
    A: Decoder,
    B: Decoder,
{
    type Output = (A::Output, B::Output);
    type Error = Either<A::Error, B::Error>;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<(), Self::Error> {
        // As long as there are un-consumed bytes, attempt to push into
        // the first or second decoder based on the state.
        while !bytes.is_empty() {
            match &mut self.state {
                Decoder2State::First(first_decoder, _) => {
                    first_decoder.push_bytes(bytes).map_err(Either::First)?;
                    // If there are remaining bytes, the first decoder has consumed
                    // as much as it needs and the rest need to be pushed
                    // to the second decoder.
                    if !bytes.is_empty() {
                        let (first, second) = self.state.transition();
                        let first_result = first.end().map_err(|error| {
                            self.state = Decoder2State::Errored;
                            Either::First(error)
                        })?;
                        self.state = Decoder2State::Second(first_result, second);
                    }
                }
                Decoder2State::Second(_, second_decoder) => {
                    second_decoder.push_bytes(bytes).map_err(|error| {
                        self.state = Decoder2State::Errored;
                        Either::Second(error)
                    })?;
                    // Second decoder consumed as many bytes as possible,
                    // break out of the feed loop.
                    break;
                }
                Decoder2State::Errored => {
                    panic!("use of failed decoder");
                }
                Decoder2State::Transitioning => {
                    panic!("use of decoder in transitioning state");
                }
            }
        }
        Ok(())
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
