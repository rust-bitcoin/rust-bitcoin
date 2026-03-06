// SPDX-License-Identifier: CC0-1.0

//! Round-trip integration tests for `CompactSize` codec.

#[cfg(feature = "alloc")]
use bitcoin_consensus_encoding::{
    decode_from_slice, encode_to_vec, CompactSizeDecoder, CompactSizeDecoderError,
    CompactSizeEncoder, CompactSizeU64Decoder, Decodable, Decoder, Encodable,
};

/// A `usize` value encoded and decoded as a compact size length prefix.
#[cfg(feature = "alloc")]
struct CompactSizeUsize(usize);

#[cfg(feature = "alloc")]
impl Encodable for CompactSizeUsize {
    type Encoder<'e>
        = CompactSizeEncoder
    where
        Self: 'e;
    fn encoder(&self) -> Self::Encoder<'_> { CompactSizeEncoder::new(self.0) }
}

/// Wraps `CompactSizeDecoder` to produce `CompactSizeUsize`.
#[cfg(feature = "alloc")]
struct CompactSizeUsizeDecoderWrapper(CompactSizeDecoder);

#[cfg(feature = "alloc")]
impl Decoder for CompactSizeUsizeDecoderWrapper {
    type Output = CompactSizeUsize;
    type Error = CompactSizeDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> { self.0.end().map(CompactSizeUsize) }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "alloc")]
impl Decodable for CompactSizeUsize {
    type Decoder = CompactSizeUsizeDecoderWrapper;
    fn decoder() -> Self::Decoder { CompactSizeUsizeDecoderWrapper(CompactSizeDecoder::new()) }
}

/// A `u64` value encoded and decoded as a compact size integer.
#[cfg(feature = "alloc")]
struct CompactSizeU64(u64);

#[cfg(feature = "alloc")]
impl Encodable for CompactSizeU64 {
    type Encoder<'e>
        = CompactSizeEncoder
    where
        Self: 'e;
    fn encoder(&self) -> Self::Encoder<'_> { CompactSizeEncoder::new_u64(self.0) }
}

/// Wraps `CompactSizeU64Decoder` to produce `CompactSizeU64`.
#[cfg(feature = "alloc")]
struct CompactSizeU64DecoderWrapper(CompactSizeU64Decoder);

#[cfg(feature = "alloc")]
impl Decoder for CompactSizeU64DecoderWrapper {
    type Output = CompactSizeU64;
    type Error = CompactSizeDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> { self.0.end().map(CompactSizeU64) }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "alloc")]
impl Decodable for CompactSizeU64 {
    type Decoder = CompactSizeU64DecoderWrapper;
    fn decoder() -> Self::Decoder { CompactSizeU64DecoderWrapper(CompactSizeU64Decoder::new()) }
}

#[test]
#[cfg(feature = "alloc")]
fn round_trip_usize_zero() {
    let bytes = encode_to_vec(&CompactSizeUsize(0x00));
    assert_eq!(bytes, [0x00]);
    assert_eq!(decode_from_slice::<CompactSizeUsize>(&bytes).unwrap().0, 0x00);
}

#[test]
#[cfg(feature = "alloc")]
fn round_trip_usize_one_byte_max() {
    // 0xFC is the largest value that fits in a single byte.
    let bytes = encode_to_vec(&CompactSizeUsize(0xFC));
    assert_eq!(bytes, [0xFC]);
    assert_eq!(decode_from_slice::<CompactSizeUsize>(&bytes).unwrap().0, 0xFC);
}

#[test]
#[cfg(feature = "alloc")]
fn round_trip_usize_three_byte_min() {
    // 0xFD is the smallest value that requires the 0xFD prefix.
    let bytes = encode_to_vec(&CompactSizeUsize(0xFD));
    assert_eq!(bytes, [0xFD, 0xFD, 0x00]);
    assert_eq!(decode_from_slice::<CompactSizeUsize>(&bytes).unwrap().0, 0xFD);
}

#[test]
#[cfg(feature = "alloc")]
fn round_trip_usize_three_byte_max() {
    let bytes = encode_to_vec(&CompactSizeUsize(0xFFFF));
    assert_eq!(bytes, [0xFD, 0xFF, 0xFF]);
    assert_eq!(decode_from_slice::<CompactSizeUsize>(&bytes).unwrap().0, 0xFFFF);
}

#[test]
#[cfg(feature = "alloc")]
fn round_trip_usize_five_byte_min() {
    // 0x10000 is the smallest value that requires the 0xFE prefix.
    let bytes = encode_to_vec(&CompactSizeUsize(0x10000));
    assert_eq!(bytes, [0xFE, 0x00, 0x00, 0x01, 0x00]);
    assert_eq!(decode_from_slice::<CompactSizeUsize>(&bytes).unwrap().0, 0x10000);
}

#[test]
#[cfg(feature = "alloc")]
fn round_trip_u64_zero() {
    let bytes = encode_to_vec(&CompactSizeU64(0x00));
    assert_eq!(bytes, [0x00]);
    assert_eq!(decode_from_slice::<CompactSizeU64>(&bytes).unwrap().0, 0x00);
}

#[test]
#[cfg(feature = "alloc")]
fn round_trip_u64_one_byte_max() {
    let bytes = encode_to_vec(&CompactSizeU64(0xFC));
    assert_eq!(bytes, [0xFC]);
    assert_eq!(decode_from_slice::<CompactSizeU64>(&bytes).unwrap().0, 0xFC);
}

#[test]
#[cfg(feature = "alloc")]
fn round_trip_u64_three_byte_min() {
    let bytes = encode_to_vec(&CompactSizeU64(0xFD));
    assert_eq!(bytes, [0xFD, 0xFD, 0x00]);
    assert_eq!(decode_from_slice::<CompactSizeU64>(&bytes).unwrap().0, 0xFD);
}

#[test]
#[cfg(feature = "alloc")]
fn round_trip_u64_three_byte_max() {
    let bytes = encode_to_vec(&CompactSizeU64(0xFFFF));
    assert_eq!(bytes, [0xFD, 0xFF, 0xFF]);
    assert_eq!(decode_from_slice::<CompactSizeU64>(&bytes).unwrap().0, 0xFFFF);
}

#[test]
#[cfg(feature = "alloc")]
fn round_trip_u64_five_byte_min() {
    // 0x1_0000 is the smallest value that requires the 0xFE prefix.
    let bytes = encode_to_vec(&CompactSizeU64(0x1_0000));
    assert_eq!(bytes, [0xFE, 0x00, 0x00, 0x01, 0x00]);
    assert_eq!(decode_from_slice::<CompactSizeU64>(&bytes).unwrap().0, 0x1_0000);
}

#[test]
#[cfg(feature = "alloc")]
fn round_trip_u64_five_byte_max() {
    let bytes = encode_to_vec(&CompactSizeU64(0xFFFF_FFFF));
    assert_eq!(bytes, [0xFE, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(decode_from_slice::<CompactSizeU64>(&bytes).unwrap().0, 0xFFFF_FFFF);
}

#[test]
#[cfg(feature = "alloc")]
fn round_trip_u64_nine_byte_min() {
    // 0x1_0000_0000 is the smallest value that requires the 0xFF prefix.
    let bytes = encode_to_vec(&CompactSizeU64(0x1_0000_0000));
    assert_eq!(bytes, [0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
    assert_eq!(decode_from_slice::<CompactSizeU64>(&bytes).unwrap().0, 0x1_0000_0000);
}

#[test]
#[cfg(feature = "alloc")]
fn round_trip_u64_max() {
    let bytes = encode_to_vec(&CompactSizeU64(u64::MAX));
    assert_eq!(bytes, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(decode_from_slice::<CompactSizeU64>(&bytes).unwrap().0, u64::MAX);
}

#[test]
#[cfg(feature = "alloc")]
fn non_minimal_rejected_u64_using_fd_prefix_for_small_value() {
    // 0x42 fits in one byte but is encoded with the 0xFD (3-byte) prefix.
    assert!(decode_from_slice::<CompactSizeU64>(&[0xFD, 0x42, 0x00]).is_err());
}

#[test]
#[cfg(feature = "alloc")]
fn non_minimal_rejected_u64_using_fe_prefix_for_small_value() {
    // 0x42 fits in one byte but is encoded with the 0xFE (5-byte) prefix.
    assert!(decode_from_slice::<CompactSizeU64>(&[0xFE, 0x42, 0x00, 0x00, 0x00]).is_err());
}

#[test]
#[cfg(feature = "alloc")]
fn non_minimal_rejected_u64_using_ff_prefix_for_small_value() {
    // 0x42 fits in one byte but is encoded with the 0xFF (9-byte) prefix.
    assert!(decode_from_slice::<CompactSizeU64>(&[
        0xFF, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])
    .is_err());
}

#[test]
#[cfg(feature = "alloc")]
fn non_minimal_rejected_usize_using_fd_prefix_for_small_value() {
    assert!(decode_from_slice::<CompactSizeUsize>(&[0xFD, 0x10, 0x00]).is_err());
}
