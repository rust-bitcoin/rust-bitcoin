// SPDX-License-Identifier: CC0-1.0

//! Collection of "standard encoders".

/// An encoder for a single byte slice.
use super::Encoder;

/// An encoder for a single byte slice.
pub struct BytesEncoder<'sl> {
    sl: &'sl [u8],
    done: bool,
}

impl<'sl> BytesEncoder<'sl> {
    /// Constructs a byte encoder which encodes the given byte slice, with no length
    /// prefix.
    pub fn without_length_prefix(sl: &'sl [u8]) -> Self { Self { sl, done: false } }
}

impl<'sl> Encoder for BytesEncoder<'sl> {
    fn advance(&mut self) -> Option<&[u8]> {
        if self.done {
            None
        } else {
            self.done = true;
            Some(self.sl)
        }
    }

    fn unadvance(&mut self) { self.done = false; }
}

/// An encoder for a single array.
pub struct ArrayEncoder<const N: usize> {
    arr: [u8; N],
    done: bool,
}

impl<const N: usize> ArrayEncoder<N> {
    /// Constructs an encoder which encodes the array with no length prefix.
    pub fn without_length_prefix(arr: [u8; N]) -> Self { Self { arr, done: false } }
}

impl<const N: usize> Encoder for ArrayEncoder<N> {
    fn advance(&mut self) -> Option<&[u8]> {
        if self.done {
            None
        } else {
            self.done = true;
            Some(&self.arr)
        }
    }

    fn unadvance(&mut self) { self.done = false; }
}
