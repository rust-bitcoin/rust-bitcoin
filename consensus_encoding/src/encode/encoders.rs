// SPDX-License-Identifier: CC0-1.0

//! Collection of "standard encoders".
//!
//! These encoders should not be used directly. Instead, when implementing the [`super::Encodable`]
//! trait on a type, you should define a newtype around one or more of these encoders, and pass
//! through the [`Encoder`] implementation to your newtype. This avoids leaking encoding
//! implementation details to the users of your type.
//!
//! For implementing these newtypes, we provide the [`encoder_newtype`] and
//! [`encoder_newtype_exact`] macros.

use core::fmt;

use super::{Encodable, Encoder, ExactSizeEncoder};

/// An encoder for a single byte slice.
#[derive(Debug, Clone)]
pub struct BytesEncoder<'sl> {
    sl: &'sl [u8],
}

impl<'sl> BytesEncoder<'sl> {
    /// Constructs a byte encoder which encodes the given byte slice, with no length prefix.
    pub const fn without_length_prefix(sl: &'sl [u8]) -> Self { Self { sl } }
}

impl Encoder for BytesEncoder<'_> {
    fn current_chunk(&self) -> &[u8] { self.sl }

    fn advance(&mut self) -> bool { false }
}

impl<'sl> ExactSizeEncoder for BytesEncoder<'sl> {
    #[inline]
    fn len(&self) -> usize { self.sl.len() }
}

/// An encoder for a single array.
#[derive(Debug, Clone)]
pub struct ArrayEncoder<const N: usize> {
    arr: [u8; N],
}

impl<const N: usize> ArrayEncoder<N> {
    /// Constructs an encoder which encodes the array with no length prefix.
    pub const fn without_length_prefix(arr: [u8; N]) -> Self { Self { arr } }
}

impl<const N: usize> Encoder for ArrayEncoder<N> {
    #[inline]
    fn current_chunk(&self) -> &[u8] { &self.arr }

    #[inline]
    fn advance(&mut self) -> bool { false }
}

impl<const N: usize> ExactSizeEncoder for ArrayEncoder<N> {
    #[inline]
    fn len(&self) -> usize { self.arr.len() }
}

/// An encoder for a reference to an array.
///
/// This encoder borrows the array instead of taking ownership, avoiding a copy
/// when the array is already available by reference (e.g., as a struct field).
#[derive(Debug, Clone)]
pub struct ArrayRefEncoder<'e, const N: usize> {
    arr: &'e [u8; N],
}

impl<'e, const N: usize> ArrayRefEncoder<'e, N> {
    /// Constructs an encoder which encodes the array reference with no length prefix.
    pub const fn without_length_prefix(arr: &'e [u8; N]) -> Self { Self { arr } }
}

impl<const N: usize> Encoder for ArrayRefEncoder<'_, N> {
    #[inline]
    fn current_chunk(&self) -> &[u8] { self.arr }

    #[inline]
    fn advance(&mut self) -> bool { false }
}

impl<const N: usize> ExactSizeEncoder for ArrayRefEncoder<'_, N> {
    #[inline]
    fn len(&self) -> usize { self.arr.len() }
}

/// An encoder for a list of encodable types.
pub struct SliceEncoder<'e, T: Encodable> {
    /// The list of references to the objects we are encoding.
    sl: &'e [T],
    /// Encoder for the current object being encoded.
    cur_enc: Option<T::Encoder<'e>>,
}

impl<'e, T: Encodable> SliceEncoder<'e, T> {
    /// Constructs an encoder which encodes the slice _without_ adding the length prefix.
    ///
    /// To encode with a length prefix consider using [`Encoder2`].
    ///
    /// E.g, `Encoder2<CompactSizeEncoder, SliceEncoder<'e, Foo>>`.
    pub fn without_length_prefix(sl: &'e [T]) -> Self {
        // In this `map` call we cannot remove the closure. Seems to be a bug in the compiler.
        // Perhaps https://github.com/rust-lang/rust/issues/102540 which is 3 years old with
        // no replies or even an acknowledgement. We will not bother filing our own issue.
        Self { sl, cur_enc: sl.first().map(|x| T::encoder(x)) }
    }
}

impl<'e, T: Encodable> fmt::Debug for SliceEncoder<'e, T>
where
    T::Encoder<'e>: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SliceEncoder")
            .field("sl", &self.sl.len())
            .field("cur_enc", &self.cur_enc)
            .finish()
    }
}

// Manual impl rather than #[derive(Clone)] because derive would constrain `where T: Clone`,
// but `T` itself is never cloned, only the associated type `T::Encoder<'e>`.
impl<'e, T: Encodable> Clone for SliceEncoder<'e, T>
where
    T::Encoder<'e>: Clone,
{
    fn clone(&self) -> Self { Self { sl: self.sl, cur_enc: self.cur_enc.clone() } }
}

impl<T: Encodable> Encoder for SliceEncoder<'_, T> {
    fn current_chunk(&self) -> &[u8] {
        // `advance` sets `cur_enc` to `None` once the slice encoder is completely exhausted.
        self.cur_enc.as_ref().map(T::Encoder::current_chunk).unwrap_or_default()
    }

    fn advance(&mut self) -> bool {
        let Some(cur) = self.cur_enc.as_mut() else {
            return false;
        };

        loop {
            // On subsequent calls, attempt to advance the current encoder and return
            // success if this succeeds.
            if cur.advance() {
                return true;
            }
            // self.sl guaranteed to be non-empty if cur is non-None.
            self.sl = &self.sl[1..];

            // If advancing the current encoder failed, attempt to move to the next encoder.
            if let Some(x) = self.sl.first() {
                *cur = x.encoder();
                if !cur.current_chunk().is_empty() {
                    return true;
                }
            } else {
                self.cur_enc = None; // shortcut the next call to advance()
                return false;
            }
        }
    }
}

/// Helper macro to define an unrolled `EncoderN` composite encoder.
macro_rules! define_encoder_n {
    (
        $(#[$attr:meta])*
        $name:ident, $idx_limit:literal;
        $(($enc_idx:literal, $enc_ty:ident, $enc_field:ident),)*
    ) => {
        $(#[$attr])*
        #[derive(Debug, Clone)]
        pub struct $name<$($enc_ty,)*> {
            cur_idx: usize,
            $($enc_field: $enc_ty,)*
        }

        impl<$($enc_ty,)*> $name<$($enc_ty,)*> {
            /// Constructs a new composite encoder.
            pub const fn new($($enc_field: $enc_ty,)*) -> Self {
                Self { cur_idx: 0, $($enc_field,)* }
            }
        }

        impl<$($enc_ty: Encoder,)*> Encoder for $name<$($enc_ty,)*> {
            #[inline]
            fn current_chunk(&self) -> &[u8] {
                match self.cur_idx {
                    $($enc_idx => self.$enc_field.current_chunk(),)*
                    _ => unreachable!("index never reaches this value"),
                }
            }

            #[inline]
            fn advance(&mut self) -> bool {
                match self.cur_idx {
                    $(
                        $enc_idx => {
                            // For the last encoder, just pass through
                            if $enc_idx == $idx_limit - 1 {
                                return self.$enc_field.advance()
                            }
                            // For all others, return true, or increment to next encoder
                            if !self.$enc_field.advance() {
                                self.cur_idx += 1;
                            }
                            true
                        }
                    )*
                    _ => false,
                }
            }
        }

        impl<$($enc_ty,)*> ExactSizeEncoder for $name<$($enc_ty,)*>
        where
            $($enc_ty: Encoder + ExactSizeEncoder,)*
        {
            #[inline]
            fn len(&self) -> usize {
                0 $(+ self.$enc_field.len())*
            }
        }
    };
}

define_encoder_n! {
    /// An encoder which encodes two objects, one after the other.
    Encoder2, 2;
    (0, A, enc_1), (1, B, enc_2),
}

define_encoder_n! {
    /// An encoder which encodes three objects, one after the other.
    Encoder3, 3;
    (0, A, enc_1), (1, B, enc_2), (2, C, enc_3),
}

define_encoder_n! {
    /// An encoder which encodes four objects, one after the other.
    Encoder4, 4;
    (0, A, enc_1), (1, B, enc_2),
    (2, C, enc_3), (3, D, enc_4),
}

define_encoder_n! {
    /// An encoder which encodes six objects, one after the other.
    Encoder6, 6;
    (0, A, enc_1), (1, B, enc_2), (2, C, enc_3),
    (3, D, enc_4), (4, E, enc_5), (5, F, enc_6),
}
