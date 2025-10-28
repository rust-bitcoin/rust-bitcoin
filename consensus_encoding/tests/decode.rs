// SPDX-License-Identifier: CC0-1.0

//! Integration tests for decode module.

use bitcoin_consensus_encoding::{
    ArrayDecoder, CompactSizeDecoder, Decoder, Decoder2, UnexpectedEofError,
};

const EMPTY: &[u8] = &[];

#[test]
fn decode_array_excess_data_ignored() {
    let mut decoder = ArrayDecoder::<4>::new();
    let mut data = &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06][..];
    let needs_more = decoder.push_bytes(&mut data).unwrap();
    assert!(!needs_more, "ArrayDecoder should be complete after consuming all needed bytes");
    assert_eq!(data, &[0x05, 0x06]);
    let result = decoder.end().unwrap();
    assert_eq!(result, [0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn decode_array_streaming_behavior() {
    let mut decoder = ArrayDecoder::<4>::new();

    let mut data = &[0x01][..];
    let needs_more = decoder.push_bytes(&mut data).unwrap();
    assert!(needs_more, "ArrayDecoder should need more data after 1 byte");
    assert_eq!(data, EMPTY);

    let mut data = &[0x02, 0x03][..];
    let needs_more = decoder.push_bytes(&mut data).unwrap();
    assert!(needs_more, "ArrayDecoder should need more data after 3 bytes");
    assert_eq!(data, EMPTY);

    let mut data = &[0x04, 0x05, 0x06][..];
    let needs_more = decoder.push_bytes(&mut data).unwrap();
    assert!(!needs_more, "ArrayDecoder should be complete after 4 bytes");
    assert_eq!(data, &[0x05, 0x06]);

    let result = decoder.end().unwrap();
    assert_eq!(result, [0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn decode_array_insufficient_data_error() {
    let mut decoder = ArrayDecoder::<5>::new();
    let mut data = &[0xAA, 0xBB][..];

    let needs_more = decoder.push_bytes(&mut data).unwrap();
    assert!(needs_more, "ArrayDecoder should need more data after 2 bytes for 5-byte array");
    assert_eq!(data, EMPTY);

    let err = decoder.end().unwrap_err();
    assert!(matches!(err, UnexpectedEofError { .. }));
}

#[test]
fn decode_array_zero_size() {
    // Test zero-sized array decoder which doesn't consume any bytes.
    let mut decoder = ArrayDecoder::<0>::new();
    let mut data = &[0x01, 0x02, 0x03][..];

    let needs_more = decoder.push_bytes(&mut data).unwrap();
    assert!(!needs_more, "zero-sized ArrayDecoder should not need data");
    assert_eq!(data, &[0x01, 0x02, 0x03]);
    let result = decoder.end().unwrap();
    assert_eq!(result, [0u8; 0]);

    // read_limit should be 0.
    let decoder = ArrayDecoder::<0>::new();
    assert_eq!(decoder.read_limit(), 0);
}

#[test]
fn decode_array_empty_slice_push() {
    // Test pushing empty slices to ArrayDecoder.
    let mut decoder = ArrayDecoder::<3>::new();
    let mut empty_data = &[][..];

    let needs_more = decoder.push_bytes(&mut empty_data).unwrap();
    assert!(needs_more, "decoder should still need data after empty push");
    assert_eq!(empty_data, &[0u8; 0]);
    assert_eq!(decoder.read_limit(), 3);
}

#[test]
fn decode_decoder2_state_transitions() {
    // Test the state transition point boundary in Decoder2.
    let mut decoder: Decoder2<ArrayDecoder<2>, ArrayDecoder<3>> =
        Decoder2::new(ArrayDecoder::<2>::new(), ArrayDecoder::<3>::new());

    assert_eq!(decoder.read_limit(), 5);
    let mut data = &[0x01, 0x02][..];
    let needs_more = decoder.push_bytes(&mut data).unwrap();
    assert!(needs_more, "should need more data for second decoder");
    assert_eq!(data.len(), 0, "all data should be consumed");

    assert_eq!(decoder.read_limit(), 3);
    let mut more_data = &[0x03, 0x04, 0x05][..];
    let needs_more = decoder.push_bytes(&mut more_data).unwrap();
    assert!(!needs_more, "should not need more data after completing both decoders");
    assert_eq!(more_data.len(), 0, "all data should be consumed");

    assert_eq!(decoder.read_limit(), 0);
    let (first_result, second_result) = decoder.end().unwrap();
    assert_eq!(first_result, [0x01, 0x02]);
    assert_eq!(second_result, [0x03, 0x04, 0x05]);
}

#[test]
fn decode_decoder2_read_limit_with_exhausted() {
    // Test read_limit calculation when first decoder needs 0 bytes.
    let decoder1: Decoder2<ArrayDecoder<0>, ArrayDecoder<5>> =
        Decoder2::new(ArrayDecoder::<0>::new(), ArrayDecoder::<5>::new());
    assert_eq!(decoder1.read_limit(), 5);

    let mut decoder2: Decoder2<ArrayDecoder<2>, ArrayDecoder<3>> =
        Decoder2::new(ArrayDecoder::<2>::new(), ArrayDecoder::<3>::new());
    let mut data = &[0x01, 0x02][..];
    let needs_more = decoder2.push_bytes(&mut data).unwrap();
    assert!(needs_more, "should need more data for second decoder");
    assert_eq!(data.len(), 0, "all data should be consumed");
    assert_eq!(decoder2.read_limit(), 3);
}

#[test]
fn decode_compact_size_read_limit_transitions() {
    // Test read_limit behavior during compact size decoding.
    let mut decoder = CompactSizeDecoder::default();

    assert_eq!(decoder.read_limit(), 1);
    let mut data = &[0xFD][..];
    let needs_more = decoder.push_bytes(&mut data).unwrap();
    assert!(needs_more, "should need more data after seeing 0xFD");
    assert_eq!(data.len(), 0, "all data should be consumed");

    assert_eq!(decoder.read_limit(), 2);
    let mut data = &[0x00][..];
    let needs_more = decoder.push_bytes(&mut data).unwrap();
    assert!(needs_more, "should still need one more byte");
    assert_eq!(data.len(), 0, "all data should be consumed");
    assert_eq!(decoder.read_limit(), 1);

    let mut data = &[0x01][..];
    let needs_more = decoder.push_bytes(&mut data).unwrap();
    assert!(!needs_more, "should not need more data");
    assert_eq!(data.len(), 0, "all data should be consumed");
    assert_eq!(decoder.read_limit(), 0);

    let result = decoder.end().unwrap();
    assert_eq!(result, 256);
}

#[test]
fn decode_compact_size_single_byte_read_limit() {
    // Test read_limit for single-byte compact size.
    let mut decoder = CompactSizeDecoder::default();

    assert_eq!(decoder.read_limit(), 1);
    let mut data = &[0x42][..];
    let needs_more = decoder.push_bytes(&mut data).unwrap();
    assert!(!needs_more, "single-byte value should be complete");
    assert_eq!(data.len(), 0, "all data should be consumed");
    assert_eq!(decoder.read_limit(), 0);
    let result = decoder.end().unwrap();
    assert_eq!(result, 66);
}

#[cfg(feature = "alloc")]
#[test]
fn decode_cast_to_usize_boundary_conditions() {
    // Test the 4MB boundary and some edge cases.
    use bitcoin_consensus_encoding::cast_to_usize_if_valid;

    assert!(cast_to_usize_if_valid(4_000_000).is_ok());
    assert!(cast_to_usize_if_valid(4_000_001).is_err());
    assert!(cast_to_usize_if_valid(u64::MAX).is_err());
    assert_eq!(cast_to_usize_if_valid(0).unwrap(), 0);
}

#[cfg(feature = "alloc")]
#[test]
fn decode_byte_vec_decoder_empty() {
    // Test decoding empty byte vector, with length prefix of 0.
    use bitcoin_consensus_encoding::{ByteVecDecoder, Decoder};

    let mut decoder = ByteVecDecoder::new();
    let mut data = &[0x00][..];
    let needs_more = decoder.push_bytes(&mut data).unwrap();
    assert!(!needs_more, "decoder should not need more data for empty vector");
    assert_eq!(data.len(), 0, "all data should be consumed");
    assert_eq!(decoder.read_limit(), 0);
    let result = decoder.end().unwrap();
    assert!(result.is_empty());
}
