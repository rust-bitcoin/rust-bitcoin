// SPDX-License-Identifier: CC0-1.0

//! Collection of "standard encoders".
//!
//! These encoders should not be used directly. Instead, when implementing the
//! [`super::Encodable`] trait on a type, you should define a newtype around one
//! or more of these encoders, and pass through the [`Encoder`] implementation
//! to your newtype. This avoids leaking encoding implementation details to the
//! users of your type.
//!
//! For implementing these newtypes, we provide the [`encoder_newtype`] macro.
//!

use internals::array_vec::ArrayVec;
use internals::compact_size;

use super::{Encodable, Encoder};

/// The maximum length of a compact size encoding.
const SIZE: usize = compact_size::MAX_ENCODING_SIZE;

/// An encoder for a single byte slice.
pub struct BytesEncoder<'sl> {
    sl: Option<&'sl [u8]>,
    compact_size: Option<ArrayVec<u8, SIZE>>,
}

impl<'sl> BytesEncoder<'sl> {
    /// Constructs a byte encoder which encodes the given byte slice, with no length prefix.
    pub fn without_length_prefix(sl: &'sl [u8]) -> Self {
        Self { sl: Some(sl), compact_size: None }
    }

    /// Constructs a byte encoder which encodes the given byte slice, with the length prefix.
    pub fn with_length_prefix(sl: &'sl [u8]) -> Self {
        Self { sl: Some(sl), compact_size: Some(compact_size::encode(sl.len())) }
    }
}

impl Encoder for BytesEncoder<'_> {
    fn current_chunk(&self) -> Option<&[u8]> {
        if let Some(compact_size) = self.compact_size.as_ref() {
            Some(compact_size)
        } else {
            self.sl
        }
    }

    fn advance(&mut self) -> bool {
        if self.compact_size.is_some() {
            self.compact_size = None;
            true
        } else {
            self.sl = None;
            false
        }
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

impl<const N: usize> Encoder for ArrayEncoder<N> {
    #[inline]
    fn current_chunk(&self) -> Option<&[u8]> { self.arr.as_ref().map(|x| &x[..]) }

    #[inline]
    fn advance(&mut self) -> bool {
        self.arr = None;
        false
    }
}

/// An encoder for a list of encodable types.
pub struct SliceEncoder<'e, T: Encodable> {
    /// The list of references to the objects we are encoding.
    sl: &'e [T],
    /// The length prefix.
    compact_size: Option<ArrayVec<u8, SIZE>>,
    /// Encoder for the current object being encoded.
    cur_enc: Option<T::Encoder<'e>>,
}

impl<'e, T: Encodable> SliceEncoder<'e, T> {
    /// Constructs an encoder which encodes the slice with a length prefix.
    pub fn with_length_prefix(sl: &'e [T]) -> Self {
        let len = sl.len();
        let compact_size = Some(compact_size::encode(len));

        // In this `map` call we cannot remove the closure. Seems to be a bug in the compiler.
        // Perhaps https://github.com/rust-lang/rust/issues/102540 which is 3 years old with
        // no replies or even an acknowledgement. We will not bother filing our own issue.
        Self { sl, compact_size, cur_enc: sl.first().map(|x| T::encoder(x)) }
    }
}

impl<'e, T: Encodable> Encoder for SliceEncoder<'e, T> {
    fn current_chunk(&self) -> Option<&[u8]> {
        if let Some(compact_size) = self.compact_size.as_ref() {
            return Some(compact_size);
        }

        // `advance` sets `cur_enc` to `None` once the slice encoder is completely exhausted.
        // `current_chunk` is required to return `None` if called after the encoder is exhausted.
        self.cur_enc.as_ref().and_then(T::Encoder::current_chunk)
    }

    fn advance(&mut self) -> bool {
        // Handle compact_size first, regardless of whether we have elements.
        if self.compact_size.is_some() {
            self.compact_size = None;
            return self.cur_enc.is_some();
        }

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
                if cur.current_chunk().is_some() {
                    return true;
                }
            } else {
                self.cur_enc = None; // shortcut the next call to advance()
                return false;
            }
        }
    }
}

/// An encoder which encodes two objects, one after the other.
pub struct Encoder2<A, B> {
    enc_idx: usize,
    enc_1: A,
    enc_2: B,
}

impl<A, B> Encoder2<A, B> {
    /// Constructs a new composite encoder.
    pub fn new(enc_1: A, enc_2: B) -> Self { Self { enc_idx: 0, enc_1, enc_2 } }
}

impl<A: Encoder, B: Encoder> Encoder for Encoder2<A, B> {
    #[inline]
    fn current_chunk(&self) -> Option<&[u8]> {
        if self.enc_idx == 0 {
            self.enc_1.current_chunk()
        } else {
            self.enc_2.current_chunk()
        }
    }

    #[inline]
    fn advance(&mut self) -> bool {
        if self.enc_idx == 0 {
            if !self.enc_1.advance() {
                self.enc_idx += 1;
            }
            true
        } else {
            self.enc_2.advance()
        }
    }
}

// For now we implement every higher encoder by composing Encoder2s, because
// I'm lazy and this is trivial both to write and to review. For efficiency, we
// should eventually unroll all of these. There are only a couple of them. The
// unrolled versions should be macro-izable, if we want to do that.

/// An encoder which encodes three objects, one after the other.
pub struct Encoder3<A, B, C> {
    inner: Encoder2<Encoder2<A, B>, C>,
}

impl<A, B, C> Encoder3<A, B, C> {
    /// Constructs a new composite encoder.
    pub fn new(enc_1: A, enc_2: B, enc_3: C) -> Self {
        Self { inner: Encoder2::new(Encoder2::new(enc_1, enc_2), enc_3) }
    }
}

impl<A: Encoder, B: Encoder, C: Encoder> Encoder for Encoder3<A, B, C> {
    #[inline]
    fn current_chunk(&self) -> Option<&[u8]> { self.inner.current_chunk() }
    #[inline]
    fn advance(&mut self) -> bool { self.inner.advance() }
}

/// An encoder which encodes four objects, one after the other.
pub struct Encoder4<A, B, C, D> {
    inner: Encoder2<Encoder2<A, B>, Encoder2<C, D>>,
}

impl<A, B, C, D> Encoder4<A, B, C, D> {
    /// Constructs a new composite encoder.
    pub fn new(enc_1: A, enc_2: B, enc_3: C, enc_4: D) -> Self {
        Self { inner: Encoder2::new(Encoder2::new(enc_1, enc_2), Encoder2::new(enc_3, enc_4)) }
    }
}

impl<A: Encoder, B: Encoder, C: Encoder, D: Encoder> Encoder for Encoder4<A, B, C, D> {
    #[inline]
    fn current_chunk(&self) -> Option<&[u8]> { self.inner.current_chunk() }
    #[inline]
    fn advance(&mut self) -> bool { self.inner.advance() }
}

/// An encoder which encodes six objects, one after the other.
pub struct Encoder6<A, B, C, D, E, F> {
    inner: Encoder2<Encoder3<A, B, C>, Encoder3<D, E, F>>,
}

impl<A, B, C, D, E, F> Encoder6<A, B, C, D, E, F> {
    /// Constructs a new composite encoder.
    pub fn new(enc_1: A, enc_2: B, enc_3: C, enc_4: D, enc_5: E, enc_6: F) -> Self {
        Self {
            inner: Encoder2::new(
                Encoder3::new(enc_1, enc_2, enc_3),
                Encoder3::new(enc_4, enc_5, enc_6),
            ),
        }
    }
}

impl<A: Encoder, B: Encoder, C: Encoder, D: Encoder, E: Encoder, F: Encoder> Encoder
    for Encoder6<A, B, C, D, E, F>
{
    #[inline]
    fn current_chunk(&self) -> Option<&[u8]> { self.inner.current_chunk() }
    #[inline]
    fn advance(&mut self) -> bool { self.inner.advance() }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestBytes<'a>(&'a [u8], bool);

    impl<'a> Encodable for TestBytes<'a> {
        type Encoder<'s>
            = BytesEncoder<'s>
        where
            Self: 's;

        fn encoder(&self) -> Self::Encoder<'_> {
            if self.1 {
                BytesEncoder::with_length_prefix(self.0)
            } else {
                BytesEncoder::without_length_prefix(self.0)
            }
        }
    }

    struct TestArray<const N: usize>([u8; N]);

    impl<const N: usize> Encodable for TestArray<N> {
        type Encoder<'s>
            = ArrayEncoder<N>
        where
            Self: 's;

        fn encoder(&self) -> Self::Encoder<'_> { ArrayEncoder::without_length_prefix(self.0) }
    }

    #[test]
    fn encode_array_with_data() {
        // Should have one chunk with the array data, then exhausted.
        let test_array = TestArray([1u8, 2, 3, 4]);
        let mut encoder = test_array.encoder();
        assert_eq!(encoder.current_chunk(), Some(&[1u8, 2, 3, 4][..]));
        assert!(!encoder.advance());
        assert_eq!(encoder.current_chunk(), None);
    }

    #[test]
    fn encode_empty_array() {
        // Empty array should have one empty chunk, then exhausted.
        let test_array = TestArray([]);
        let mut encoder = test_array.encoder();
        assert_eq!(encoder.current_chunk(), Some(&[][..]));
        assert!(!encoder.advance());
        assert_eq!(encoder.current_chunk(), None);
    }

    #[test]
    fn encode_byte_slice_without_prefix() {
        // Should have one chunk with the byte data, then exhausted.
        let obj = [1u8, 2, 3];
        let test_bytes = TestBytes(&obj, false);
        let mut encoder = test_bytes.encoder();

        assert_eq!(encoder.current_chunk(), Some(&[1u8, 2, 3][..]));
        assert!(!encoder.advance());
        assert_eq!(encoder.current_chunk(), None);
    }

    #[test]
    fn encode_empty_byte_slice_without_prefix() {
        // Should have one empty chunk, then exhausted.
        let obj = [];
        let test_bytes = TestBytes(&obj, false);
        let mut encoder = test_bytes.encoder();

        assert_eq!(encoder.current_chunk(), Some(&[][..]));
        assert!(!encoder.advance());
        assert_eq!(encoder.current_chunk(), None);
    }

    #[test]
    fn encode_byte_slice_with_prefix() {
        // Should have length prefix chunk, then data chunk, then exhausted.
        let obj = [1u8, 2, 3];
        let test_bytes = TestBytes(&obj, true);
        let mut encoder = test_bytes.encoder();

        assert_eq!(encoder.current_chunk(), Some(&[3u8][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[1u8, 2, 3][..]));
        assert!(!encoder.advance());
        assert_eq!(encoder.current_chunk(), None);
    }

    #[test]
    fn encode_empty_byte_slice_with_prefix() {
        // Should have length prefix chunk (0), then empty data chunk, then exhausted.
        let obj = [];
        let test_bytes = TestBytes(&obj, true);
        let mut encoder = test_bytes.encoder();

        assert_eq!(encoder.current_chunk(), Some(&[0u8][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[][..]));
        assert!(!encoder.advance());
        assert_eq!(encoder.current_chunk(), None);
    }

    #[test]
    fn encode_slice_with_elements() {
        // Should have length prefix chunk, then element chunks, then exhausted.
        let slice = &[TestArray([0x34, 0x12, 0x00, 0x00]), TestArray([0x78, 0x56, 0x00, 0x00])];
        let mut encoder = SliceEncoder::with_length_prefix(slice);

        assert_eq!(encoder.current_chunk(), Some(&[2u8][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[0x34, 0x12, 0x00, 0x00][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[0x78, 0x56, 0x00, 0x00][..]));
        assert!(!encoder.advance());
        assert_eq!(encoder.current_chunk(), None);
    }

    #[test]
    fn encode_empty_slice() {
        // Should have only length prefix chunk (0), then exhausted.
        let slice: &[TestArray<4>] = &[];
        let mut encoder = SliceEncoder::with_length_prefix(slice);

        assert_eq!(encoder.current_chunk(), Some(&[0u8][..]));
        assert!(!encoder.advance());
        assert_eq!(encoder.current_chunk(), None);
    }

    #[test]
    fn encode_slice_with_zero_sized_arrays() {
        // Should have length prefix chunk, then empty array chunks, then exhausted.
        let slice = &[TestArray([]), TestArray([])];
        let mut encoder = SliceEncoder::with_length_prefix(slice);

        assert_eq!(encoder.current_chunk(), Some(&[2u8][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[][..]));
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), Some(&[][..]));
        assert!(!encoder.advance());
        assert_eq!(encoder.current_chunk(), None);
    }
}
