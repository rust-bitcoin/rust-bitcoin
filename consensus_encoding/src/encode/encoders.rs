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
    pub const fn without_length_prefix(arr: &'e [u8; N]) -> Self { Self { arr: Some(arr) } }
}

impl<const N: usize> Encoder for ArrayRefEncoder<'_, N> {
    #[inline]
    fn current_chunk(&self) -> &[u8] { self.arr.map(|x| &x[..]).unwrap_or_default() }

    #[inline]
    fn advance(&mut self) -> bool {
        self.arr = None;
        false
    }
}

impl<const N: usize> ExactSizeEncoder for ArrayRefEncoder<'_, N> {
    #[inline]
    fn len(&self) -> usize { self.arr.map_or(0, |a| a.len()) }
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
    pub const fn new(enc_1: A, enc_2: B) -> Self { Self { enc_idx: 0, enc_1, enc_2 } }
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

impl<A, B> ExactSizeEncoder for Encoder2<A, B>
where
    A: Encoder + ExactSizeEncoder,
    B: Encoder + ExactSizeEncoder,
{
    #[inline]
    fn len(&self) -> usize { self.enc_1.len() + self.enc_2.len() }
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
    pub const fn new(enc_1: A, enc_2: B, enc_3: C) -> Self {
        Self { inner: Encoder2::new(Encoder2::new(enc_1, enc_2), enc_3) }
    }
}

impl<A: Encoder, B: Encoder, C: Encoder> Encoder for Encoder3<A, B, C> {
    #[inline]
    fn current_chunk(&self) -> &[u8] { self.inner.current_chunk() }
    #[inline]
    fn advance(&mut self) -> bool { self.inner.advance() }
}

impl<A, B, C> ExactSizeEncoder for Encoder3<A, B, C>
where
    A: Encoder + ExactSizeEncoder,
    B: Encoder + ExactSizeEncoder,
    C: Encoder + ExactSizeEncoder,
{
    #[inline]
    fn len(&self) -> usize { self.inner.len() }
}

/// An encoder which encodes four objects, one after the other.
pub struct Encoder4<A, B, C, D> {
    inner: Encoder2<Encoder2<A, B>, Encoder2<C, D>>,
}

impl<A, B, C, D> Encoder4<A, B, C, D> {
    /// Constructs a new composite encoder.
    pub const fn new(enc_1: A, enc_2: B, enc_3: C, enc_4: D) -> Self {
        Self { inner: Encoder2::new(Encoder2::new(enc_1, enc_2), Encoder2::new(enc_3, enc_4)) }
    }
}

impl<A: Encoder, B: Encoder, C: Encoder, D: Encoder> Encoder for Encoder4<A, B, C, D> {
    #[inline]
    fn current_chunk(&self) -> &[u8] { self.inner.current_chunk() }
    #[inline]
    fn advance(&mut self) -> bool { self.inner.advance() }
}

impl<A, B, C, D> ExactSizeEncoder for Encoder4<A, B, C, D>
where
    A: Encoder + ExactSizeEncoder,
    B: Encoder + ExactSizeEncoder,
    C: Encoder + ExactSizeEncoder,
    D: Encoder + ExactSizeEncoder,
{
    #[inline]
    fn len(&self) -> usize { self.inner.len() }
}

/// An encoder which encodes six objects, one after the other.
pub struct Encoder6<A, B, C, D, E, F> {
    inner: Encoder2<Encoder3<A, B, C>, Encoder3<D, E, F>>,
}

impl<A, B, C, D, E, F> Encoder6<A, B, C, D, E, F> {
    /// Constructs a new composite encoder.
    pub const fn new(enc_1: A, enc_2: B, enc_3: C, enc_4: D, enc_5: E, enc_6: F) -> Self {
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

impl<A, B, C, D, E, F> ExactSizeEncoder for Encoder6<A, B, C, D, E, F>
where
    A: Encoder + ExactSizeEncoder,
    B: Encoder + ExactSizeEncoder,
    C: Encoder + ExactSizeEncoder,
    D: Encoder + ExactSizeEncoder,
    E: Encoder + ExactSizeEncoder,
    F: Encoder + ExactSizeEncoder,
{
    #[inline]
    fn len(&self) -> usize { self.inner.len() }
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

    struct TestBytes<'a>(&'a [u8]);

    impl Encodable for TestBytes<'_> {
        type Encoder<'e>
            = BytesEncoder<'e>
        where
            Self: 'e;

        fn encoder(&self) -> Self::Encoder<'_> { BytesEncoder::without_length_prefix(self.0) }
    }

    struct TestArray<const N: usize>([u8; N]);

    impl<const N: usize> Encodable for TestArray<N> {
        type Encoder<'e>
            = ArrayEncoder<N>
        where
            Self: 'e;

        fn encoder(&self) -> Self::Encoder<'_> { ArrayEncoder::without_length_prefix(self.0) }
    }

    #[test]
    fn encode_array_with_data() {
        // Should have one chunk with the array data, then exhausted.
        let test_array = TestArray([1u8, 2, 3, 4]);
        let mut encoder = test_array.encoder();
        assert_eq!(encoder.len(), 4);
        assert!(!encoder.is_empty());
        assert_eq!(encoder.current_chunk(), &[1u8, 2, 3, 4][..]);
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_empty_array() {
        // Empty array should have one empty chunk, then exhausted.
        let test_array = TestArray([]);
        let mut encoder = test_array.encoder();
        assert_eq!(encoder.len(), 0);
        assert!(encoder.is_empty());
        assert!(encoder.current_chunk().is_empty());
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_array_ref_with_data() {
        // Should have one chunk with the array data, then exhausted.
        let data = [1u8, 2, 3, 4];
        let mut encoder = ArrayRefEncoder::without_length_prefix(&data);
        assert_eq!(encoder.len(), 4);
        assert!(!encoder.is_empty());
        assert_eq!(encoder.current_chunk(), &[1u8, 2, 3, 4][..]);
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
        assert_eq!(encoder.len(), 0);
    }

    #[test]
    fn encode_empty_array_ref() {
        // Empty array should have one empty chunk, then exhausted.
        let data = [];
        let mut encoder = ArrayRefEncoder::without_length_prefix(&data);
        assert_eq!(encoder.len(), 0);
        assert!(encoder.is_empty());
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

        assert_eq!(encoder.len(), 3);
        assert!(!encoder.is_empty());

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

        assert_eq!(encoder.len(), 0);
        assert!(encoder.is_empty());

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
        // The slice advanced is optimized to skip over empty chunks.
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_two_arrays() {
        // Should encode first array, then second array, then exhausted.
        let enc1 = TestArray([1u8, 2]).encoder();
        let enc2 = TestArray([3u8, 4]).encoder();
        let mut encoder = Encoder2::new(enc1, enc2);

        assert_eq!(encoder.len(), 4);
        assert!(!encoder.is_empty());

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

        assert_eq!(encoder.len(), 0);
        assert!(encoder.is_empty());

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

        assert_eq!(encoder.len(), 6);
        assert!(!encoder.is_empty());

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

        assert_eq!(encoder.len(), 4);
        assert!(!encoder.is_empty());

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

        assert_eq!(encoder.len(), 6);
        assert!(!encoder.is_empty());

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

        assert_eq!(encoder.len(), 4);
        assert!(!encoder.is_empty());

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

        assert_eq!(encoder.len(), 4);
        assert!(!encoder.is_empty());

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
        let mut e = CompactSizeEncoder::new(0x10usize);
        assert_eq!(e.current_chunk(), &[0x10][..]);
        assert_eq!(e.len(), 1);
        assert!(!e.advance());
        assert!(e.current_chunk().is_empty());

        let mut e = CompactSizeEncoder::new(0xFCusize);
        assert_eq!(e.current_chunk(), &[0xFC][..]);
        assert_eq!(e.len(), 1);
        assert!(!e.advance());
        assert!(e.current_chunk().is_empty());

        // 0xFD + u16
        let mut e = CompactSizeEncoder::new(0x00FDusize);
        assert_eq!(e.current_chunk(), &[0xFD, 0xFD, 0x00][..]);
        assert_eq!(e.len(), 3);
        assert!(!e.advance());
        assert!(e.current_chunk().is_empty());

        let mut e = CompactSizeEncoder::new(0x0FFFusize);
        assert_eq!(e.current_chunk(), &[0xFD, 0xFF, 0x0F][..]);
        assert_eq!(e.len(), 3);
        assert!(!e.advance());
        assert!(e.current_chunk().is_empty());

        // 0xFE + u32
        let mut e = CompactSizeEncoder::new(0x0001_0000usize);
        assert_eq!(e.current_chunk(), &[0xFE, 0x00, 0x00, 0x01, 0x00][..]);
        assert_eq!(e.len(), 5);
        assert!(!e.advance());
        assert!(e.current_chunk().is_empty());

        let mut e = CompactSizeEncoder::new(0x0F0F_0F0Fusize);
        assert_eq!(e.current_chunk(), &[0xFE, 0x0F, 0x0F, 0x0F, 0x0F][..]);
        assert_eq!(e.len(), 5);
        assert!(!e.advance());
        assert!(e.current_chunk().is_empty());

        // 0xFF + u64
        // This test only runs on systems with >= 64 bit usize.
        if core::mem::size_of::<usize>() >= 8 {
            let mut e = CompactSizeEncoder::new(0x0000_F0F0_F0F0_F0E0u64 as usize);
            assert_eq!(
                e.current_chunk(),
                &[0xFF, 0xE0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0x00, 0x00][..]
            );
            assert_eq!(e.len(), 9);
            assert!(!e.advance());
            assert!(e.current_chunk().is_empty());
        }

        // > u64::MAX encodes as u64::MAX.
        // This test only runs on systems with > 64 bit usize.
        if core::mem::size_of::<usize>() > 8 {
            let mut e = CompactSizeEncoder::new((u128::from(u64::MAX) + 5) as usize);
            assert_eq!(
                e.current_chunk(),
                &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF][..]
            );
            assert_eq!(e.len(), 9);
            assert!(!e.advance());
            assert!(e.current_chunk().is_empty());
        }
    }

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

    #[test]
    fn iter_encoder() {
        let test_array = TestArray([1u8, 2, 3, 4]);
        let mut iter = crate::EncodableByteIter::new(&test_array);

        assert_eq!(iter.len(), 4);

        assert_eq!(iter.next().unwrap(), 1);
        assert_eq!(iter.len(), 3);
        assert_eq!(iter.next().unwrap(), 2);
        assert_eq!(iter.len(), 2);
        assert_eq!(iter.next().unwrap(), 3);
        assert_eq!(iter.len(), 1);
        assert_eq!(iter.next().unwrap(), 4);
        assert_eq!(iter.len(), 0);
        assert!(iter.next().is_none());
    }
}
