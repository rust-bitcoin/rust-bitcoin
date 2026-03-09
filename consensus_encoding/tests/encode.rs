// SPDX-License-Identifier: CC0-1.0

//! Tests for encoder free functions.

#[cfg(feature = "std")]
use std::io::{Cursor, Write};

use bitcoin_consensus_encoding::{
    ArrayEncoder, ArrayRefEncoder, BytesEncoder, CompactSizeEncoder, Encodable, EncodableByteIter,
    Encoder, Encoder2, Encoder3, Encoder4, Encoder6, ExactSizeEncoder, SliceEncoder,
};

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

// Simple test type that implements Encodable.
#[cfg(feature = "alloc")]
struct TestData(u32);

#[cfg(feature = "alloc")]
impl Encodable for TestData {
    type Encoder<'e>
        = ArrayEncoder<4>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        ArrayEncoder::without_length_prefix(self.0.to_le_bytes())
    }
}

// Test with a type that creates an empty encoder.
#[cfg(feature = "alloc")]
struct EmptyData;

#[cfg(feature = "alloc")]
impl Encodable for EmptyData {
    type Encoder<'e>
        = ArrayEncoder<0>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> { ArrayEncoder::without_length_prefix([]) }
}

#[test]
#[cfg(feature = "std")]
fn encode_std_writer() {
    let data = TestData(0x1234_5678);

    let mut cursor = Cursor::new(Vec::new());
    bitcoin_consensus_encoding::encode_to_writer(&data, &mut cursor).unwrap();

    let result = cursor.into_inner();
    assert_eq!(result, vec![0x78, 0x56, 0x34, 0x12]);
}

#[test]
#[cfg(feature = "alloc")]
fn encode_vec() {
    let data = TestData(0xDEAD_BEEF);
    let vec = bitcoin_consensus_encoding::encode_to_vec(&data);
    assert_eq!(vec, vec![0xEF, 0xBE, 0xAD, 0xDE]);
}

#[test]
#[cfg(feature = "alloc")]
fn encode_vec_empty_data() {
    let data = EmptyData;
    let result = bitcoin_consensus_encoding::encode_to_vec(&data);
    assert!(result.is_empty());
}

#[test]
#[cfg(feature = "std")]
fn encode_std_writer_empty_data() {
    let data = EmptyData;
    let mut cursor = Cursor::new(Vec::new());
    bitcoin_consensus_encoding::encode_to_writer(&data, &mut cursor).unwrap();

    let result = cursor.into_inner();
    assert!(result.is_empty());
}

#[test]
#[cfg(feature = "std")]
fn encode_std_writer_io_error() {
    // Test writer that always fails.
    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("test error"))
        }

        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }

    let data = TestData(0x1234_5678);
    let mut writer = FailingWriter;

    let result = bitcoin_consensus_encoding::encode_to_writer(&data, &mut writer);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Other);
}

#[test]
fn encode_newtype_lifetime_flexibility() {
    // Test that the encoder_newtype macro allows different lifetime names.

    bitcoin_consensus_encoding::encoder_newtype! {
        pub struct CustomEncoder<'data>(BytesEncoder<'data>);
    }
    bitcoin_consensus_encoding::encoder_newtype! {
        pub struct NoLifetimeEncoder<'e>(ArrayEncoder<4>);
    }

    let test_data = b"hello world";
    let custom_encoder = CustomEncoder::new(BytesEncoder::without_length_prefix(test_data));
    let no_lifetime_encoder =
        NoLifetimeEncoder::new(ArrayEncoder::without_length_prefix([1, 2, 3, 4]));

    assert_eq!(custom_encoder.current_chunk(), test_data.as_slice());
    assert_eq!(no_lifetime_encoder.current_chunk(), &[1, 2, 3, 4][..]);
}

#[cfg(feature = "alloc")]
#[test]
fn encode_slice_encoder_mixed_empty_and_data() {
    // Test SliceEncoder behavior with mixed empty and non-empty elements.
    struct TestBytesVec(Vec<u8>);

    impl Encodable for TestBytesVec {
        type Encoder<'e>
            = BytesEncoder<'e>
        where
            Self: 'e;

        fn encoder(&self) -> Self::Encoder<'_> { BytesEncoder::without_length_prefix(&self.0) }
    }

    let slice = &[
        TestBytesVec(vec![]),
        TestBytesVec(vec![1, 2]),
        TestBytesVec(vec![]),
        TestBytesVec(vec![3]),
    ];

    let mut encoder = SliceEncoder::without_length_prefix(slice);

    assert!(encoder.current_chunk().is_empty());
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &[1, 2]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &[3]);
    assert!(!encoder.advance());
    assert!(encoder.current_chunk().is_empty());
}

#[test]
fn encode_compact_size_boundary_values() {
    // Test CompactSizeEncoder with boundary values.
    let mut encoder = CompactSizeEncoder::new(252usize);
    assert_eq!(encoder.current_chunk(), &[252]);
    assert!(!encoder.advance());

    let mut encoder = CompactSizeEncoder::new(253usize);
    assert_eq!(encoder.current_chunk(), &[0xFD, 253, 0]);
    assert!(!encoder.advance());

    let mut encoder = CompactSizeEncoder::new(0x10000usize);
    assert_eq!(encoder.current_chunk(), &[0xFE, 0, 0, 1, 0]);
    assert!(!encoder.advance());

    let mut encoder = CompactSizeEncoder::new(0usize);
    assert_eq!(encoder.current_chunk(), &[0]);
    assert!(!encoder.advance());
}

#[test]
fn encode_encoder2_with_first_empty_encoder() {
    // Test Encoder2 when first encoder produces no data.
    let enc1 = ArrayEncoder::<0>::without_length_prefix([]);
    let enc2 = ArrayEncoder::<3>::without_length_prefix([1, 2, 3]);

    let mut encoder = Encoder2::new(enc1, enc2);

    assert!(encoder.current_chunk().is_empty());
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &[1, 2, 3]);
    assert!(!encoder.advance());
    assert!(encoder.current_chunk().is_empty());
}

#[test]
fn encode_encoder_advance_multiple_times_when_exhausted() {
    // Test that calling advance() multiple times on exhausted encoder is safe.
    let mut encoder = ArrayEncoder::<2>::without_length_prefix([10, 20]);

    assert_eq!(encoder.current_chunk(), &[10, 20]);
    assert!(!encoder.advance());
    assert!(encoder.current_chunk().is_empty());
    assert!(!encoder.advance());
    assert!(!encoder.advance());
    assert!(!encoder.advance());
    assert!(encoder.current_chunk().is_empty());
}

#[test]
fn encode_option_encoder_some() {
    let mut encoder = Some(ArrayEncoder::<3>::without_length_prefix([1, 2, 3]));
    assert_eq!(encoder.current_chunk(), &[1, 2, 3]);
    assert!(!encoder.advance());
    assert!(encoder.current_chunk().is_empty());
}

#[test]
fn encode_option_encoder_none() {
    let mut encoder: Option<ArrayEncoder<3>> = None;
    assert!(encoder.current_chunk().is_empty());
    assert!(!encoder.advance());
    assert!(encoder.current_chunk().is_empty());
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
fn iter_encoder() {
    let test_array = TestArray([1u8, 2, 3, 4]);
    let mut iter = EncodableByteIter::new(&test_array);

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
