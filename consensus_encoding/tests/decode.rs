// SPDX-License-Identifier: CC0-1.0

//! Integration tests for decode module.

use consensus_encoding::{ArrayDecoder, Decoder, UnexpectedEof};

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
    assert!(matches!(err, UnexpectedEof { .. }));
}
