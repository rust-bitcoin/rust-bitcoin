// SPDX-License-Identifier: CC0-1.0

//! Consensus Decoding Traits

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
    /// Returns `Ok(())` if the consumed bytes were valid, or `Err(error)`
    /// if parsing failed. If no bytes were consumed, the decoder cannot make
    /// progress and [`Self::end`] should be called to finalize.
    ///
    /// # Errors
    ///
    /// Returns an error if the provided bytes are invalid or malformed according
    /// to the decoder's validation rules. Insufficient data (needing more
    /// bytes) is *not* an error for this method, the decoder will simply consume
    /// what it can and wait for more data in subsequent calls.
    ///
    /// # Panics
    ///
    /// May panic if called after a previous call to [`Self::push_bytes`] errored.
    #[must_use]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<(), Self::Error>;

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
    #[must_use]
    fn end(self) -> Result<Self::Output, Self::Error>;
}
