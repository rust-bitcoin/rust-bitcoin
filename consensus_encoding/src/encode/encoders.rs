// SPDX-License-Identifier: CC0-1.0

//! Collection of "standard encoders".
//!
//! These encoders should not be used directly. Instead, when implementing the
//! [`super::Encodable`] trait on a type, you should define a newtype around one
//! or more of these encoders, and pass through the [`Encoder`] implementation
//! to your newtype. This avoids leaking encoding implementation details to the
//! users of your type.
//!

/// An encoder for a single byte slice.
use super::Encoder;

/// An encoder for a single byte slice.
pub struct BytesEncoder<'sl> {
    sl: Option<&'sl [u8]>,
}

impl<'sl> BytesEncoder<'sl> {
    /// Constructs a byte encoder which encodes the given byte slice, with no length
    /// prefix.
    pub fn without_length_prefix(sl: &'sl [u8]) -> Self { Self { sl: Some(sl) } }
}

impl<'e, 'sl> Encoder<'e> for BytesEncoder<'sl> {
    fn current_chunk(&self) -> Option<&[u8]> {
        self.sl
    }

    fn advance(&mut self)-> bool {
        self.sl = None;
        false
    }
}

/// An encoder for a single array.
pub struct ArrayEncoder<const N: usize> {
    arr: Option<[u8; N]>,
}

impl<const N: usize> ArrayEncoder<N> {
    /// Constructs an encoder which encodes the array with no length prefix.
    pub fn without_length_prefix(arr: [u8; N]) -> Self { Self { arr: Some(arr) } }
}

impl<'e, const N: usize> Encoder<'e> for ArrayEncoder<N> {
    fn current_chunk(&self) -> Option<&[u8]> {
        self.arr.as_ref().map(|x| &x[..])
    }


    fn advance(&mut self)-> bool {
        self.arr = None;
        false
    }
}
