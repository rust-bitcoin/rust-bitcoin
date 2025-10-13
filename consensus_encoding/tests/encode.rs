// SPDX-License-Identifier: CC0-1.0

//! Tests for encoder free functions.

#[cfg(feature = "std")]
use std::io::{Cursor, Write};

use bitcoin_consensus_encoding::{ArrayEncoder, BytesEncoder, Encoder};
#[cfg(feature = "alloc")]
use bitcoin_consensus_encoding::{Encodable};

// Simple test type that implements Encodable.
#[cfg(feature = "alloc")]
struct TestData(u32);

#[cfg(feature = "alloc")]
impl Encodable for TestData {
    type Encoder<'s>
        = ArrayEncoder<4>
    where
        Self: 's;

    fn encoder(&self) -> Self::Encoder<'_> {
        ArrayEncoder::without_length_prefix(self.0.to_le_bytes())
    }
}

// Test with a type that creates an empty encoder.
#[cfg(feature = "alloc")]
struct EmptyData;

#[cfg(feature = "alloc")]
impl Encodable for EmptyData {
    type Encoder<'s>
        = ArrayEncoder<0>
    where
        Self: 's;

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
        pub struct NoLifetimeEncoder(ArrayEncoder<4>);
    }

    let test_data = b"hello world";
    let custom_encoder = CustomEncoder(BytesEncoder::without_length_prefix(test_data));
    let no_lifetime_encoder = NoLifetimeEncoder(ArrayEncoder::without_length_prefix([1, 2, 3, 4]));

    assert_eq!(custom_encoder.current_chunk(), Some(test_data.as_slice()));
    assert_eq!(no_lifetime_encoder.current_chunk(), Some(&[1, 2, 3, 4][..]));
}
