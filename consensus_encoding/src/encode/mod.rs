// SPDX-License-Identifier: CC0-1.0

//! Consensus Encoding Traits

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

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
    /// Returns `true` if the next call to [`Self::current_chunk`] will return data.
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

/// Encode an object into a hash engine.
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

/// Encodes an object into a vector.
#[cfg(feature = "alloc")]
pub fn encode_to_vec<T: Encodable>(object: &T) -> Vec<u8> {
    let mut encoder = object.encoder();
    let mut vec = Vec::new();
    while let Some(chunk) = encoder.current_chunk() {
        vec.extend_from_slice(chunk);
        encoder.advance();
    }
    vec
}

/// Encodes an object to a standard I/O writer.
///
/// # Performance
///
/// This method writes data in potentially small chunks based on the encoder's
/// internal chunking strategy. For optimal performance with unbuffered writers
/// (like [`std::fs::File`] or [`std::net::TcpStream`]), consider wrapping your
/// writer with [`std::io::BufWriter`].
///
/// # Errors
///
/// Returns any I/O error encountered while writing to the writer.
#[cfg(feature = "std")]
pub fn encode_to_writer<T: Encodable, W: std::io::Write>(
    object: &T,
    mut writer: W,
) -> Result<(), std::io::Error> {
    let mut encoder = object.encoder();
    while let Some(chunk) = encoder.current_chunk() {
        writer.write_all(chunk)?;
        encoder.advance();
    }
    Ok(())
}
