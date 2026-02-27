// SPDX-License-Identifier: CC0-1.0

//! Collection of "standard encoders".
//!
//! These encoders should not be used directly. Instead, when implementing the
//! [`super::Encodable`] trait on a type, you should define a newtype around one
//! or more of these encoders, and pass through the [`Encoder`] implementation
//! to your newtype. This avoids leaking encoding implementation details to the
//! users of your type.
//!
//! For implementing these newtypes, we provide the [`encoder_newtype`] and
//! [`encoder_newtype_exact`] macros.
//!

use internals::array_vec::ArrayVec;

use super::{Encodable, Encoder, ExactSizeEncoder};

/// The maximum length of a compact size encoding.
const SIZE: usize = 9;

/// An encoder for a single byte slice.
pub struct BytesEncoder<'sl> {
    sl: Option<&'sl [u8]>,
}

impl<'sl> BytesEncoder<'sl> {
    /// Constructs a byte encoder which encodes the given byte slice, with no length prefix.
    pub const fn without_length_prefix(sl: &'sl [u8]) -> Self { Self { sl: Some(sl) } }
}

impl Encoder for BytesEncoder<'_> {
    fn current_chunk(&self) -> &[u8] { self.sl.unwrap_or_default() }

    fn advance(&mut self) -> bool {
        self.sl = None;
        false
    }
}

impl<'sl> ExactSizeEncoder for BytesEncoder<'sl> {
    #[inline]
    fn len(&self) -> usize { self.sl.map_or(0, <[u8]>::len) }
}

/// An encoder for a single array.
pub struct ArrayEncoder<const N: usize> {
    arr: Option<[u8; N]>,
}

impl<const N: usize> ArrayEncoder<N> {
    /// Constructs an encoder which encodes the array with no length prefix.
    pub const fn without_length_prefix(arr: [u8; N]) -> Self { Self { arr: Some(arr) } }
}

impl<const N: usize> Encoder for ArrayEncoder<N> {
    #[inline]
    fn current_chunk(&self) -> &[u8] { self.arr.as_ref().map(|x| &x[..]).unwrap_or_default() }

    #[inline]
    fn advance(&mut self) -> bool {
        self.arr = None;
        false
    }
}

impl<const N: usize> ExactSizeEncoder for ArrayEncoder<N> {
    #[inline]
    fn len(&self) -> usize { self.arr.map_or(0, |a| a.len()) }
}

/// An encoder for a reference to an array.
///
/// This encoder borrows the array instead of taking ownership, avoiding a copy
/// when the array is already available by reference (e.g., as a struct field).
pub struct ArrayRefEncoder<'e, const N: usize> {
    arr: Option<&'e [u8; N]>,
}

impl<'e, const N: usize> ArrayRefEncoder<'e, N> {
    /// Constructs an encoder which encodes the array reference with no length prefix.
    pub const fn without_length_prefix(arr: &'e [u8; N]) -> Self {
        Self { arr: Some(arr) }
    }
}

impl<const N: usize> Encoder for ArrayRefEncoder<'_, N> {
    #[inline]
    fn current_chunk(&self) -> &[u8] {
        self.arr.map(|x| &x[..]).unwrap_or_default()
    }

    #[inline]
    fn advance(&mut self) -> bool {
        self.arr = None;
        false
    }
}

impl<const N: usize> ExactSizeEncoder for ArrayRefEncoder<'_, N> {
    #[inline]
    fn len(&self) -> usize {
        self.arr.map_or(0, |a| a.len())
    }
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
    /// To encode with a length prefix consider using the `Encoder2`.
    ///
    /// E.g, `Encoder2<CompactSizeEncoder, SliceEncoder<'e, Foo>>`.
    pub fn without_length_prefix(sl: &'e [T]) -> Self {
        // In this `map` call we cannot remove the closure. Seems to be a bug in the compiler.
        // Perhaps https://github.com/rust-lang/rust/issues/102540 which is 3 years old with
        // no replies or even an acknowledgement. We will not bother filing our own issue.
        Self { sl, cur_enc: sl.first().map(|x| T::encoder(x)) }
    }
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
                    _ => &[],
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

/// Encoder for a compact size encoded integer.
pub struct CompactSizeEncoder {
    buf: Option<ArrayVec<u8, SIZE>>,
}

impl CompactSizeEncoder {
    /// Constructs a new `CompactSizeEncoder`.
    ///
    /// Encodings are defined only for the range of u64. On systems where usize is
    /// larger than u64, it will be possible to call this method with out-of-range
    /// values. In such cases we will ignore the passed value and encode [`u64::MAX`].
    /// But even on such exotic systems, we expect users to pass the length of an
    /// in-memory object, meaning that such large values are impossible to obtain.
    pub fn new(value: usize) -> Self { Self { buf: Some(Self::encode(value)) } }

    /// Returns the number of bytes used to encode this `CompactSize` value.
    ///
    /// # Returns
    ///
    /// - 1 for 0..=0xFC
    /// - 3 for 0xFD..=(2^16-1)
    /// - 5 for 0x10000..=(2^32-1)
    /// - 9 otherwise.
    #[inline]
    pub const fn encoded_size(value: usize) -> usize {
        match value {
            0..=0xFC => 1,
            0xFD..=0xFFFF => 3,
            0x10000..=0xFFFF_FFFF => 5,
            _ => 9,
        }
    }

    /// Encodes `CompactSize` without allocating.
    #[inline]
    fn encode(value: usize) -> ArrayVec<u8, SIZE> {
        let mut res = ArrayVec::<u8, SIZE>::new();
        match value {
            0..=0xFC => {
                res.push(value as u8); // Cast ok because of match.
            }
            0xFD..=0xFFFF => {
                let v = value as u16; // Cast ok because of match.
                res.push(0xFD);
                res.extend_from_slice(&v.to_le_bytes());
            }
            0x10000..=0xFFFF_FFFF => {
                let v = value as u32; // Cast ok because of match.
                res.push(0xFE);
                res.extend_from_slice(&v.to_le_bytes());
            }
            _ => {
                res.push(0xFF);
                res.extend_from_slice(&value.to_le_bytes());
            }
        }
        res
    }
}

impl Encoder for CompactSizeEncoder {
    #[inline]
    fn current_chunk(&self) -> &[u8] { self.buf.as_ref().map(|b| &b[..]).unwrap_or_default() }

    #[inline]
    fn advance(&mut self) -> bool {
        self.buf = None;
        false
    }
}

impl ExactSizeEncoder for CompactSizeEncoder {
    #[inline]
    fn len(&self) -> usize { self.buf.map_or(0, |buf| buf.len()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_value_1_byte() {
        // Check lower bound, upper bound (and implicitly endian-ness).
        for v in [0x00, 0x01, 0x02, 0xFA, 0xFB, 0xFC] {
            let v = v as usize;
            assert_eq!(CompactSizeEncoder::encoded_size(v), 1);
            // Should be encoded as the value as a u8.
            let want = [v as u8];
            let got = CompactSizeEncoder::encode(v);
            assert_eq!(got.as_slice().len(), 1); // sanity check
            assert_eq!(got.as_slice(), want);
        }
    }

    macro_rules! check_encode {
        ($($test_name:ident, $size:expr, $value:expr, $want:expr);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    let value = $value as usize; // Because default integer type is i32.
                    assert_eq!(CompactSizeEncoder::encoded_size(value), $size);
                    let got = CompactSizeEncoder::encode(value);
                    assert_eq!(got.as_slice().len(), $size); // sanity check
                    assert_eq!(got.as_slice(), &$want);
                }
            )*
        }
    }

    check_encode! {
        // 3 byte encoding.
        encoded_value_3_byte_lower_bound, 3, 0xFD, [0xFD, 0xFD, 0x00]; // 0x00FD
        encoded_value_3_byte_endianness, 3, 0xABCD, [0xFD, 0xCD, 0xAB];
        encoded_value_3_byte_upper_bound, 3, 0xFFFF, [0xFD, 0xFF, 0xFF];
        // 5 byte encoding.
        encoded_value_5_byte_lower_bound, 5, 0x0001_0000, [0xFE, 0x00, 0x00, 0x01, 0x00];
        encoded_value_5_byte_endianness, 5, 0x0123_4567, [0xFE, 0x67, 0x45, 0x23, 0x01];
        encoded_value_5_byte_upper_bound, 5, 0xFFFF_FFFF, [0xFE, 0xFF, 0xFF, 0xFF, 0xFF];
    }

    // Only test on platforms with a usize that is 64 bits
    #[cfg(target_pointer_width = "64")]
    check_encode! {
        // 9 byte encoding.
        encoded_value_9_byte_lower_bound, 9, 0x0000_0001_0000_0000, [0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        encoded_value_9_byte_endianness, 9, 0x0123_4567_89AB_CDEF, [0xFF, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
        encoded_value_9_byte_upper_bound, 9, u64::MAX, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    }
}
