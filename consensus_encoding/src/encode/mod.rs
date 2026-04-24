// SPDX-License-Identifier: CC0-1.0

//! Consensus Encoding Traits

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

pub mod encoders;

/// A Bitcoin object which can be consensus-encoded.
///
/// To encode something, use the [`Self::encoder`] method to obtain a [`Self::Encoder`], which will
/// behave like an iterator yielding byte slices.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "alloc")] {
/// use bitcoin_consensus_encoding::{encoder_newtype, encode_to_vec, Encodable, ArrayEncoder};
///
/// struct Foo([u8; 4]);
///
/// encoder_newtype! {
///     pub struct FooEncoder<'e>(ArrayEncoder<4>);
/// }
///
/// impl Encodable for Foo {
///     type Encoder<'e> = FooEncoder<'e> where Self: 'e;
///
///     fn encoder(&self) -> Self::Encoder<'_> {
///         FooEncoder::new(ArrayEncoder::without_length_prefix(self.0))
///     }
/// }
///
/// let foo = Foo([0xde, 0xad, 0xbe, 0xef]);
/// assert_eq!(encode_to_vec(&foo), vec![0xde, 0xad, 0xbe, 0xef]);
/// # }
/// ```
pub trait Encodable {
    /// The encoder associated with this type. Conceptually, the encoder is like
    /// an iterator which yields byte slices.
    type Encoder<'e>: Encoder
    where
        Self: 'e;

    /// Constructs a "default encoder" for the type.
    fn encoder(&self) -> Self::Encoder<'_>;
}

/// An encoder for a consensus-encodable object.
///
/// The consumers of type implementing this encoder trait should generally use it in a loop like
/// this:
///
/// ```no-compile
/// loop {
///     process_current_chunk(encoder.current_chunk());
///     if !encoder.advance() {
///         break
///     }
/// }
/// // do NOT use encoder after this point
/// ```
///
/// Processing the chunks in an equivalent state machine (presumably future) is also permissible.
///
/// It is crucial that the callers use the methods in that order: obtain the slice via
/// `current_chunk`, write it somewhere and, once fully written, try to advance the encoder.
/// Attempting to call any method after [`advance`](Self::advance) returned `false` or calling
/// `advance` before fully processing the chunks will lead to unspecified buggy behavior.
pub trait Encoder {
    /// Yields the current encoded byteslice.
    ///
    /// Will always return the same value until [`Self::advance`] is called.
    /// May return an empty slice, however implementors should avoid returning empty slices unless
    /// the encoded type is truly empty.
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
    ///
    /// # Important
    ///
    /// After `false` was returned the encoder is in unspecified state. Calling any of its methods
    /// in such state is a bug (but not UB) unless the specific encoder documents otherwise. While
    /// usually the encoder simply stays in the last possible state this MUST NOT be relied upon by
    /// the callers.
    fn advance(&mut self) -> bool;
}

/// Implements a newtype around an encoder.
///
/// The new type will implement the [`Encoder`] trait by forwarding to the wrapped encoder. If your
/// type has a known size consider using [`crate::encoder_newtype_exact`] instead.
///
/// # Examples
/// ```
/// use bitcoin_consensus_encoding::{encoder_newtype, BytesEncoder};
///
/// encoder_newtype! {
///     /// The encoder for the [`Foo`] type.
///     pub struct FooEncoder<'e>(BytesEncoder<'e>);
/// }
/// ```
///
/// For a full example see `./examples/encoder.rs`.
#[macro_export]
macro_rules! encoder_newtype {
    (
        $(#[$($struct_attr:tt)*])*
        $vis:vis struct $name:ident<$lt:lifetime>($encoder:ty);
    ) => {
        $(#[$($struct_attr)*])*
        $vis struct $name<$lt>($encoder, core::marker::PhantomData<&$lt $encoder>);

        #[allow(clippy::type_complexity)]
        impl<$lt> $name<$lt> {
            /// Constructs a new instance of the newtype encoder.
            pub(crate) const fn new(encoder: $encoder) -> $name<$lt> {
                $name(encoder, core::marker::PhantomData)
            }
        }

        impl<$lt> $crate::Encoder for $name<$lt> {
            #[inline]
            fn current_chunk(&self) -> &[u8] { self.0.current_chunk() }

            #[inline]
            fn advance(&mut self) -> bool { self.0.advance() }
        }
    }
}

/// Implements a newtype around an exact-size encoder.
///
/// The new type will implement both the [`Encoder`] and [`ExactSizeEncoder`] traits
/// by forwarding to the wrapped encoder.
///
/// # Examples
/// ```
/// use bitcoin_consensus_encoding::{encoder_newtype_exact, ArrayEncoder};
///
/// encoder_newtype_exact! {
///     /// The encoder for the [`Bar`] type.
///     pub struct BarEncoder<'e>(ArrayEncoder<32>);
/// }
/// ```
///
/// For a full example see `./examples/encoder.rs`.
#[macro_export]
macro_rules! encoder_newtype_exact {
    (
        $(#[$($struct_attr:tt)*])*
        $vis:vis struct $name:ident<$lt:lifetime>($encoder:ty);
    ) => {
        $crate::encoder_newtype! {
            $(#[$($struct_attr)*])*
            $vis struct $name<$lt>($encoder);
        }

        impl<$lt> $crate::ExactSizeEncoder for $name<$lt> {
            #[inline]
            fn len(&self) -> usize { self.0.len() }
        }
    }
}

/// Yields bytes from any [`Encoder`] instance.
///
/// **Important** this iterator is **not** fused! Call `fuse` if you need it to be fused.
#[derive(Debug, Clone)]
pub struct EncoderByteIter<T: Encoder> {
    enc: T,
    position: usize,
}

impl<T: Encoder> EncoderByteIter<T> {
    /// Constructs a new byte iterator around a provided encoder.
    pub fn new(encoder: T) -> Self { Self { enc: encoder, position: 0 } }

    /// Returns the remaining bytes in the next non-empty chunk.
    ///
    /// The returned value is either a non-empty chunk of bytes that were not yielded yet,
    /// immediately following the already-yielded bytes or empty slice if the encoder finished.
    ///
    /// This call can be paired with `nth` to mark bytes as processed.
    ///
    /// Just like with encoders or this iterator, attempting to use this type after this method
    /// returned an empty slice will lead to unspecified behavior and is considered a bug in the
    /// caller.
    pub fn peek_chunk(&mut self) -> &[u8] {
        // Can't use `.get(self.position..)` due to borrowck bug.
        if self.position < self.enc.current_chunk().len() {
            &self.enc.current_chunk()[self.position..]
        } else {
            loop {
                if !self.enc.advance() {
                    return &[];
                }
                if !self.enc.current_chunk().is_empty() {
                    self.position = 0;
                    return self.enc.current_chunk();
                }
            }
        }
    }
}

impl<T: Encoder> Iterator for EncoderByteIter<T> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(b) = self.enc.current_chunk().get(self.position) {
                // length of slice is guaranteed to be at most `isize::MAX` thus is `n` so this cannot
                // overflow.
                self.position += 1;
                return Some(*b);
            } else if !self.enc.advance() {
                return None;
            }
            self.position = 0;
        }
    }

    fn nth(&mut self, mut n: usize) -> Option<Self::Item> {
        // This could be in a loop but we intentionally unroll one iteration so that addition is
        // only required at the beginning.
        if let Some(b) = self.position.checked_add(n).and_then(|pos| self.enc.current_chunk().get(pos)) {
            // length of slice is guaranteed to be at most `isize::MAX` thus is `n` so this cannot
            // overflow.
            self.position += n + 1;
            return Some(*b);
        }
        n -= self.enc.current_chunk().len() - self.position;
        if !self.enc.advance() {
            return None;
        }
        loop {
            if let Some(b) = self.enc.current_chunk().get(n) {
                self.position = n + 1;
                return Some(*b);
            }
            n -= self.enc.current_chunk().len();
            if !self.enc.advance() {
                return None;
            }
        }
    }
}

impl<T> ExactSizeIterator for EncoderByteIter<T>
where
    T: Encoder + ExactSizeEncoder,
{
    fn len(&self) -> usize { self.enc.len() - self.position }
}

/// An encoder with a known size.
pub trait ExactSizeEncoder: Encoder {
    /// The number of bytes remaining that the encoder will yield.
    ///
    /// **Important**: returns an unspecified value if [`Encoder::advance`] has returned `false`.
    fn len(&self) -> usize;

    /// Returns whether the encoder would yield an empty response.
    ///
    /// **Important**: returns an unspecified value if [`Encoder::advance`] has returned `false`.
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
/// This method writes data in potentially small chunks based on the encoder's internal chunking
/// strategy. For optimal performance with unbuffered writers (like [`std::fs::File`] or
/// [`std::net::TcpStream`]), consider wrapping your writer with [`std::io::BufWriter`].
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
