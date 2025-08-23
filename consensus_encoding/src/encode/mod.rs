// SPDX-License-Identifier: CC0-1.0

//! Consensus Encoding Traits

pub mod encoders;

/// f trait for things that can be encoded
pub trait Encodable {
    /// The encoder associated with this type. Conceptually, the encoder is like
    /// an iterator which yields byte slices.
    type Encoder: Encoder;

    /// Constructs a "default encoder" for the type.
    fn encoder(&self) -> Self::Encoder;
}

/// f "encoder" object, similar to Iterator
pub trait Encoder {
    /// Yields the next byteslice to be encoded, updating the encoder state.
    ///
    /// Returns `None` if the encoder is exhausted. Once this method returns `None`,
    /// all subsequent calls will return `None`.
    fn advance(&mut self) -> Option<&[u8]>;

    /// Moves the encoder to its previous state (once).
    ///
    /// It is guaranteed that after calling this method once, the next call to
    /// [`Self::advance`] will return the most recent non-`None` value, if any, that
    /// it returned in previous calls.
    ///
    /// No behavior is specified if this method is called multiple times in a row.
    fn unadvance(&mut self);
}
