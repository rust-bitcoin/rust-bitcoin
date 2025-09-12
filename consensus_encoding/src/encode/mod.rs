// SPDX-License-Identifier: CC0-1.0

//! Consensus Encoding Traits

pub mod encoders;

/// A Bitcoin object which can be consensus-encoded.
///
/// To encode something, use the [`Self::encoder`] method to obtain a
/// [`Self::Encoder`], which will behave like an iterator yielding
/// byte slices.
pub trait Encodable {
    /// The encoder associated with this type. Conceptually, the encoder is like
    /// an iterator which yields byte slices.
    type Encoder<'s>: Encoder<'s>
    where
        Self: 's;

    /// Constructs a "default encoder" for the type.
    fn encoder(&self) -> Self::Encoder<'_>;
}

/// An encoder for a consensus-encodable object.
pub trait Encoder<'e> {
    /// Yields the current encoded byteslice.
    ///
    /// Will always return the same value until [`Self::advance`] is called.
    ///
    /// Returns `None` if the encoder is exhausted. Once this method returns `None`,
    /// all subsequent calls will return `None`.
    fn current_chunk(&self) -> Option<&[u8]>;

    /// Moves the encoder to its next state.
    ///
    /// Does not need to be called when the encoder is first created. (In fact, if it
    /// is called, this will discard the first chunk of encoded data.)
    ///
    /// Returns `true` if the the next call to [`Self::current_chunk`] will return data.
    /// Returns `false` otherwise. It is fine to ignore the return value of this method
    /// and just call `current_chunk` to see if it works.
    fn advance(&mut self) -> bool;
}

/// Implements a newtype around an encoder which implements the
/// [`Encoder`] trait by forwarding to the wrapped encoder.
#[macro_export]
macro_rules! encoder_newtype{
    (
        $(#[$($struct_attr:tt)*])*
        pub struct $name:ident$(<$lt:lifetime>)?($encoder:ty);
    ) => {
        $(#[$($struct_attr)*])*
        pub struct $name$(<$lt>)?($encoder);

        impl<'e $(, $lt)?> $crate::Encoder<'e> for $name$(<$lt>)? {
            #[inline]
            fn current_chunk(&self) -> Option<&[u8]> { self.0.current_chunk() }

            #[inline]
            fn advance(&mut self) -> bool { self.0.advance() }
        }
    }
}

/// Encodes an object into a hash engine.
///
/// Consumes and returns the hash engine to make it easier to call
/// [`hashes::HashEngine::finalize`] directly on the result.
pub fn encode_to_hash_engine<T: Encodable, H: hashes::HashEngine>(object: &T, mut engine: H) -> H {
    let mut encoder = object.encoder();
    while let Some(sl) = encoder.current_chunk() {
        engine.input(sl);
        encoder.advance();
    }
    engine
}
