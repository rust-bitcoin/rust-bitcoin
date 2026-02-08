// SPDX-License-Identifier: CC0-1.0

//! Tests for encoder free functions.

#[cfg(feature = "std")]
use std::io::{Cursor, Write};

use bitcoin_consensus_encoding::{
    ArrayEncoder, BytesEncoder, CompactSizeEncoder, Encoder, Encoder2,
};
#[cfg(feature = "alloc")]
use bitcoin_consensus_encoding::{Encodable, SliceEncoder};

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
    struct TestBytes(Vec<u8>);

    impl Encodable for TestBytes {
        type Encoder<'e>
            = BytesEncoder<'e>
        where
            Self: 'e;

        fn encoder(&self) -> Self::Encoder<'_> { BytesEncoder::without_length_prefix(&self.0) }
    }

    let slice = &[TestBytes(vec![]), TestBytes(vec![1, 2]), TestBytes(vec![]), TestBytes(vec![3])];

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
    use bitcoin_consensus_encoding::Encoder;

    let mut encoder = Some(ArrayEncoder::<3>::without_length_prefix([1, 2, 3]));
    assert_eq!(encoder.current_chunk(), &[1, 2, 3]);
    assert!(!encoder.advance());
    assert!(encoder.current_chunk().is_empty());
}

#[test]
fn encode_option_encoder_none() {
    use bitcoin_consensus_encoding::Encoder;

    let mut encoder: Option<ArrayEncoder<3>> = None;
    assert!(encoder.current_chunk().is_empty());
    assert!(!encoder.advance());
    assert!(encoder.current_chunk().is_empty());
}
