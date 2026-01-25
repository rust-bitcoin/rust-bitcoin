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
    type Encoder<'s>: Encoder
    where
        Self: 's;

    /// Constructs a "default encoder" for the type.
    fn encoder(&self) -> Self::Encoder<'_>;
}

/// An encoder for a consensus-encodable object.
pub trait Encoder {
    /// Yields the current encoded byteslice.
    ///
    /// Will always return the same value until [`Self::advance`] is called. May return an empty
    /// list.
    fn current_chunk(&self) -> &[u8];

    /// Moves the encoder to its next state.
    ///
    /// Does not need to be called when the encoder is first created. (In fact, if it
    /// is called, this will discard the first chunk of encoded data.)
    ///
    /// # Returns
    ///
    /// - `true` if the encoder has advanced to a new state and [`Self::current_chunk`] will return new data.
    /// - `false` if the encoder is exhausted and has no more states.
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

        impl$(<$lt>)? $crate::Encoder for $name$(<$lt>)? {
            #[inline]
            fn current_chunk(&self) -> &[u8] { self.0.current_chunk() }

            #[inline]
            fn advance(&mut self) -> bool { self.0.advance() }
        }
    }
}

/// Implements a newtype around an exact-size encoder which
/// implements the [`Encoder`] and [`ExactSizeEncoder`] traits
/// by forwarding to the wrapped encoder.
#[macro_export]
macro_rules! encoder_newtype_exact{
    (
        $(#[$($struct_attr:tt)*])*
        pub struct $name:ident$(<$lt:lifetime>)?($encoder:ty);
    ) => {
        $crate::encoder_newtype! {
            $(#[$($struct_attr)*])*
            pub struct $name$(<$lt>)?($encoder);
        }

        impl$(<$lt>)? $crate::ExactSizeEncoder for $name$(<$lt>)? {
            #[inline]
            fn len(&self) -> usize { self.0.len() }
        }
    }
}

/// Yields bytes from any [`Encodable`] instance.
pub struct EncodableByteIter<'s, T: Encodable + 's> {
    enc: T::Encoder<'s>,
    position: usize,
}

impl<'s, T: Encodable + 's> EncodableByteIter<'s, T> {
    /// Constructs a new byte iterator around a provided encodable.
    pub fn new(encodable: &'s T) -> Self { Self { enc: encodable.encoder(), position: 0 } }
}

impl<'s, T: Encodable + 's> Iterator for EncodableByteIter<'s, T> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(b) = self.enc.current_chunk().get(self.position) {
                self.position += 1;
                return Some(*b);
            } else if !self.enc.advance() {
                return None;
            }
            self.position = 0;
        }
    }
}

impl<'s, T> ExactSizeIterator for EncodableByteIter<'s, T>
where
    T: Encodable + 's,
    T::Encoder<'s>: ExactSizeEncoder,
{
    fn len(&self) -> usize { self.enc.len() - self.position }
}

/// An encoder with a known size.
pub trait ExactSizeEncoder: Encoder {
    /// The number of bytes remaining that the encoder will yield.
    fn len(&self) -> usize;

    /// Returns whether the encoder would yield an empty response.
    fn is_empty(&self) -> bool { self.len() == 0 }
}

/// Encodes an object into a vector.
#[cfg(feature = "alloc")]
pub fn encode_to_vec<T>(object: &T) -> Vec<u8>
where
    T: Encodable + ?Sized,
{
    let mut encoder = object.encoder();
    flush_to_vec(&mut encoder)
}

/// Flushes the output of an [`Encoder`] into a vector.
#[cfg(feature = "alloc")]
pub fn flush_to_vec<T>(encoder: &mut T) -> Vec<u8>
where
    T: Encoder + ?Sized,
{
    let mut vec = Vec::new();
    loop {
        vec.extend_from_slice(encoder.current_chunk());
        if !encoder.advance() {
            break;
        }
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
pub fn encode_to_writer<T, W>(object: &T, writer: W) -> Result<(), std::io::Error>
where
    T: Encodable + ?Sized,
    W: std::io::Write,
{
    let mut encoder = object.encoder();
    flush_to_writer(&mut encoder, writer)
}

/// Flushes the output of an [`Encoder`] to a standard I/O writer.
///
/// See [`encode_to_writer`] for more information.
///
/// # Errors
///
/// Returns any I/O error encountered while writing to the writer.
#[cfg(feature = "std")]
pub fn flush_to_writer<T, W>(encoder: &mut T, mut writer: W) -> Result<(), std::io::Error>
where
    T: Encoder + ?Sized,
    W: std::io::Write,
{
    loop {
        writer.write_all(encoder.current_chunk())?;
        if !encoder.advance() {
            break;
        }
    }
    Ok(())
}

impl<T: Encoder> Encoder for Option<T> {
    fn current_chunk(&self) -> &[u8] {
        match self {
            Some(encoder) => encoder.current_chunk(),
            None => &[],
        }
    }

    fn advance(&mut self) -> bool {
        match self {
            Some(encoder) => encoder.advance(),
            None => false,
        }
    }
}
