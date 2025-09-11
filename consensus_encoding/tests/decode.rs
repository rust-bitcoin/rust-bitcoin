// SPDX-License-Identifier: CC0-1.0

//! Integration tests for decode module.

use consensus_encoding::{ArrayDecoder, Decoder, UnexpectedEof};

const EMPTY: &[u8] = &[];

#[test]
fn decode_array_excess_data_ignored() {
    let mut decoder = ArrayDecoder::<4>::new();
    let mut data = &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06][..];
    decoder.push_bytes(&mut data).unwrap();
    assert_eq!(data, &[0x05, 0x06]);
    let result = decoder.end().unwrap();
    assert_eq!(result, [0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn decode_array_streaming_behavior() {
    let mut decoder = ArrayDecoder::<4>::new();

    let mut data = &[0x01][..];
    decoder.push_bytes(&mut data).unwrap();
    assert_eq!(data, EMPTY);

    let mut data = &[0x02, 0x03][..];
    decoder.push_bytes(&mut data).unwrap();
    assert_eq!(data, EMPTY);

    let mut data = &[0x04, 0x05, 0x06][..];
    decoder.push_bytes(&mut data).unwrap();
    assert_eq!(data, &[0x05, 0x06]);

    let result = decoder.end().unwrap();
    assert_eq!(result, [0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn decode_array_insufficient_data_error() {
    let mut decoder = ArrayDecoder::<5>::new();
    let mut data = &[0xAA, 0xBB][..];

    decoder.push_bytes(&mut data).unwrap();
    assert_eq!(data, EMPTY);

    let err = decoder.end().unwrap_err();
    assert_eq!(err, UnexpectedEof { missing: 3 });
    assert_eq!(err.to_string(), "not enough bytes for decoder, 3 more bytes required");
}
