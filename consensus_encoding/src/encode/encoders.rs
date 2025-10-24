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
use internals::{compact_size, ToU64};

use super::{Encodable, Encoder};

/// The maximum length of a compact size encoding.
const SIZE: usize = 9;

/// An encoder for a single byte slice.
pub struct BytesEncoder<'sl> {
    sl: Option<&'sl [u8]>,
}

impl<'sl> BytesEncoder<'sl> {
    /// Constructs a byte encoder which encodes the given byte slice, with no length prefix.
    pub fn without_length_prefix(sl: &'sl [u8]) -> Self { Self { sl: Some(sl) } }
}

impl Encoder for BytesEncoder<'_> {
    fn current_chunk(&self) -> &[u8] { self.sl.unwrap_or_default() }

    fn advance(&mut self) -> bool {
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

impl<const N: usize> Encoder for ArrayEncoder<N> {
    #[inline]
    fn current_chunk(&self) -> &[u8] { self.arr.as_ref().map(|x| &x[..]).unwrap_or_default() }

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
    fn current_chunk(&self) -> &[u8] {
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
    fn current_chunk(&self) -> &[u8] { self.inner.current_chunk() }
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
    fn current_chunk(&self) -> &[u8] { self.inner.current_chunk() }
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
    fn current_chunk(&self) -> &[u8] { self.inner.current_chunk() }
    #[inline]
    fn advance(&mut self) -> bool { self.inner.advance() }
}

/// Encoder for a compact size encoded integer.
pub struct CompactSizeEncoder {
    buf: Option<ArrayVec<u8, SIZE>>,
}

impl CompactSizeEncoder {
    /// Constructs a new `CompactSizeEncoder`.
    pub fn new(value: impl ToU64) -> Self { Self { buf: Some(compact_size::encode(value)) } }
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

#[cfg(test)]
mod tests {
    use super::*;

    struct TestBytes<'a>(&'a [u8]);

    impl Encodable for TestBytes<'_> {
        type Encoder<'s>
            = BytesEncoder<'s>
        where
            Self: 's;

        fn encoder(&self) -> Self::Encoder<'_> { BytesEncoder::without_length_prefix(self.0) }
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
        assert_eq!(encoder.current_chunk(), &[1u8, 2, 3, 4][..]);
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_empty_array() {
        // Empty array should have one empty chunk, then exhausted.
        let test_array = TestArray([]);
        let mut encoder = test_array.encoder();
        assert!(encoder.current_chunk().is_empty());
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_byte_slice_without_prefix() {
        // Should have one chunk with the byte data, then exhausted.
        let obj = [1u8, 2, 3];
        let test_bytes = TestBytes(&obj);
        let mut encoder = test_bytes.encoder();

        assert_eq!(encoder.current_chunk(), &[1u8, 2, 3][..]);
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_empty_byte_slice_without_prefix() {
        // Should have one empty chunk, then exhausted.
        let obj = [];
        let test_bytes = TestBytes(&obj);
        let mut encoder = test_bytes.encoder();

        assert!(encoder.current_chunk().is_empty());
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_slice_with_elements() {
        // Should have the element chunks, then exhausted.
        let slice = &[TestArray([0x34, 0x12, 0x00, 0x00]), TestArray([0x78, 0x56, 0x00, 0x00])];
        let mut encoder = SliceEncoder::without_length_prefix(slice);

        assert_eq!(encoder.current_chunk(), &[0x34, 0x12, 0x00, 0x00][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x78, 0x56, 0x00, 0x00][..]);
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_empty_slice() {
        // Should immediately be exhausted.
        let slice: &[TestArray<4>] = &[];
        let mut encoder = SliceEncoder::without_length_prefix(slice);

        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_slice_with_zero_sized_arrays() {
        // Should have empty array chunks, then exhausted.
        let slice = &[TestArray([]), TestArray([])];
        let mut encoder = SliceEncoder::without_length_prefix(slice);

        assert!(encoder.current_chunk().is_empty());
        // FIXME: Its strange the we can't do this?
        // assert!(encoder.advance());
        // assert!(encoder.current_chunk().is_empty());
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_two_arrays() {
        // Should encode first array, then second array, then exhausted.
        let enc1 = TestArray([1u8, 2]).encoder();
        let enc2 = TestArray([3u8, 4]).encoder();
        let mut encoder = Encoder2::new(enc1, enc2);

        assert_eq!(encoder.current_chunk(), &[1u8, 2][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[3u8, 4][..]);
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_two_empty_arrays() {
        // Should encode first empty array, then second empty array, then exhausted.
        let enc1 = TestArray([]).encoder();
        let enc2 = TestArray([]).encoder();
        let mut encoder = Encoder2::new(enc1, enc2);

        assert!(encoder.current_chunk().is_empty());
        assert!(encoder.advance());
        assert!(encoder.current_chunk().is_empty());
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_three_arrays() {
        // Should encode three arrays in sequence, then exhausted.
        let enc1 = TestArray([1u8]).encoder();
        let enc2 = TestArray([2u8, 3u8]).encoder();
        let enc3 = TestArray([4u8, 5u8, 6u8]).encoder();
        let mut encoder = Encoder3::new(enc1, enc2, enc3);

        assert_eq!(encoder.current_chunk(), &[1u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[2u8, 3u8][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[4u8, 5u8, 6u8][..]);
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_four_arrays() {
        // Should encode four arrays in sequence, then exhausted.
        let enc1 = TestArray([0x10]).encoder();
        let enc2 = TestArray([0x20]).encoder();
        let enc3 = TestArray([0x30]).encoder();
        let enc4 = TestArray([0x40]).encoder();
        let mut encoder = Encoder4::new(enc1, enc2, enc3, enc4);

        assert_eq!(encoder.current_chunk(), &[0x10][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x20][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x30][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x40][..]);
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_six_arrays() {
        // Should encode six arrays in sequence, then exhausted.
        let enc1 = TestArray([0x01]).encoder();
        let enc2 = TestArray([0x02]).encoder();
        let enc3 = TestArray([0x03]).encoder();
        let enc4 = TestArray([0x04]).encoder();
        let enc5 = TestArray([0x05]).encoder();
        let enc6 = TestArray([0x06]).encoder();
        let mut encoder = Encoder6::new(enc1, enc2, enc3, enc4, enc5, enc6);

        assert_eq!(encoder.current_chunk(), &[0x01][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x02][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x03][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x04][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x05][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x06][..]);
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_mixed_composition_with_byte_slices() {
        // Should encode byte slice, then array, then exhausted.
        let enc1 = TestBytes(&[0xFF, 0xEE]).encoder();
        let enc2 = TestArray([0xDD, 0xCC]).encoder();
        let mut encoder = Encoder2::new(enc1, enc2);

        assert_eq!(encoder.current_chunk(), &[0xFF, 0xEE][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0xDD, 0xCC][..]);
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_nested_composition() {
        // Should encode empty array, single byte array, then three byte array, then exhausted.
        let enc1 = TestArray([]).encoder();
        let enc2 = TestArray([0x42]).encoder();
        let enc3 = TestArray([0x43, 0x44, 0x45]).encoder();
        let mut encoder = Encoder3::new(enc1, enc2, enc3);

        assert!(encoder.current_chunk().is_empty());
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x42][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x43, 0x44, 0x45][..]);
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_slice_with_array_composition() {
        // Should encode slice elements, then array, then exhausted.
        let slice = &[TestArray([0x10, 0x11]), TestArray([0x12, 0x13])];
        let slice_enc = SliceEncoder::without_length_prefix(slice);
        let array_enc = TestArray([0x20, 0x21]).encoder();
        let mut encoder = Encoder2::new(slice_enc, array_enc);

        assert_eq!(encoder.current_chunk(), &[0x10, 0x11][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x12, 0x13][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x20, 0x21][..]);
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_array_with_slice_composition() {
        // Should encode header array, then slice elements, then exhausted.
        let header = TestArray([0xFF, 0xFE]).encoder();
        let slice = &[TestArray([0x01]), TestArray([0x02]), TestArray([0x03])];
        let slice_enc = SliceEncoder::without_length_prefix(slice);
        let mut encoder = Encoder2::new(header, slice_enc);

        assert_eq!(encoder.current_chunk(), &[0xFF, 0xFE][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x01][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x02][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x03][..]);
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_multiple_slices_composition() {
        // Should encode three slices in sequence, then exhausted.
        let slice1 = &[TestArray([0xA1]), TestArray([0xA2])];
        let slice2: &[TestArray<1>] = &[];
        let slice3 = &[TestArray([0xC1]), TestArray([0xC2]), TestArray([0xC3])];

        let enc1 = SliceEncoder::without_length_prefix(slice1);
        let enc2 = SliceEncoder::without_length_prefix(slice2);
        let enc3 = SliceEncoder::without_length_prefix(slice3);
        let mut encoder = Encoder3::new(enc1, enc2, enc3);

        assert_eq!(encoder.current_chunk(), &[0xA1][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0xA2][..]);

        // Skip the empty slice
        assert!(encoder.advance());

        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0xC1][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0xC2][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0xC3][..]);
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_complex_nested_structure() {
        // Should encode header, slice with elements, and footer with prefix, then exhausted.
        let header = TestBytes(&[0xDE, 0xAD]).encoder();
        let data_slice = &[TestArray([0x01, 0x02]), TestArray([0x03, 0x04])];
        let slice_enc = SliceEncoder::without_length_prefix(data_slice);
        let footer = TestBytes(&[0xBE, 0xEF]).encoder();
        let mut encoder = Encoder3::new(header, slice_enc, footer);

        assert_eq!(encoder.current_chunk(), &[0xDE, 0xAD][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x01, 0x02][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0x03, 0x04][..]);
        assert!(encoder.advance());
        assert_eq!(encoder.current_chunk(), &[0xBE, 0xEF][..]);
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }
    #[test]
    fn encode_compact_size() {
        // 1-byte
        let mut e = CompactSizeEncoder::new(0x10u64);
        assert_eq!(e.current_chunk(), &[0x10][..]);
        assert!(!e.advance());
        assert!(e.current_chunk().is_empty());

        let mut e = CompactSizeEncoder::new(0xFCu64);
        assert_eq!(e.current_chunk(), &[0xFC][..]);
        assert!(!e.advance());
        assert!(e.current_chunk().is_empty());

        // 0xFD + u16
        let mut e = CompactSizeEncoder::new(0x00FDu64);
        assert_eq!(e.current_chunk(), &[0xFD, 0xFD, 0x00][..]);
        assert!(!e.advance());
        assert!(e.current_chunk().is_empty());

        let mut e = CompactSizeEncoder::new(0x0FFFu64);
        assert_eq!(e.current_chunk(), &[0xFD, 0xFF, 0x0F][..]);
        assert!(!e.advance());
        assert!(e.current_chunk().is_empty());

        // 0xFE + u32
        let mut e = CompactSizeEncoder::new(0x0001_0000u64);
        assert_eq!(e.current_chunk(), &[0xFE, 0x00, 0x00, 0x01, 0x00][..]);
        assert!(!e.advance());
        assert!(e.current_chunk().is_empty());

        let mut e = CompactSizeEncoder::new(0x0F0F_0F0Fu64);
        assert_eq!(e.current_chunk(), &[0xFE, 0x0F, 0x0F, 0x0F, 0x0F][..]);
        assert!(!e.advance());
        assert!(e.current_chunk().is_empty());

        // 0xFF + u64
        let mut e = CompactSizeEncoder::new(0x0000_F0F0_F0F0_F0E0u64);
        assert_eq!(e.current_chunk(), &[0xFF, 0xE0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0x00, 0x00][..]);
        assert!(!e.advance());
        assert!(e.current_chunk().is_empty());
    }
}
