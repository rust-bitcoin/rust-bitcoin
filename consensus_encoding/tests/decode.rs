// SPDX-License-Identifier: CC0-1.0

//! Integration tests for decode module.

#[cfg(feature = "std")]
use std::io::{Cursor, Read};

use bitcoin_consensus_encoding as encoding;
#[cfg(feature = "alloc")]
use encoding::check_decode;
use encoding::{
    check_decoder, decode_from_slice, decode_from_slice_unbounded, ArrayDecoder,
    CompactSizeDecoder, Decode, DecodeError, Decoder, Decoder2, UnexpectedEofError,
};
#[cfg(feature = "hex")]
use bitcoin_consensus_encoding::{decode_from_hex, FromHexError};
#[cfg(feature = "std")]
use encoding::{decode_from_read, decode_from_read_unbuffered, ReadError};
#[cfg(feature = "alloc")]
use encoding::{ByteVecDecoder, VecDecoder, VecDecoderError};

const EMPTY: &[u8] = &[];

#[test]
fn decode_array_excess_data_ignored() {
    let mut decoder = ArrayDecoder::<4>::new();
    let mut data = &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06][..];
    let status = decoder.push_bytes(&mut data).unwrap();
    assert!(status.is_ready(), "ArrayDecoder should be complete after consuming all needed bytes");
    assert_eq!(data, &[0x05, 0x06]);
    let result = decoder.end().unwrap();
    assert_eq!(result, [0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn decode_array_streaming_behavior() {
    let mut decoder = ArrayDecoder::<4>::new();

    let mut data = &[0x01][..];
    let status = decoder.push_bytes(&mut data).unwrap();
    assert!(status.needs_more(), "ArrayDecoder should need more data after 1 byte");
    assert_eq!(data, EMPTY);

    let mut data = &[0x02, 0x03][..];
    let status = decoder.push_bytes(&mut data).unwrap();
    assert!(status.needs_more(), "ArrayDecoder should need more data after 3 bytes");
    assert_eq!(data, EMPTY);

    let mut data = &[0x04, 0x05, 0x06][..];
    let status = decoder.push_bytes(&mut data).unwrap();
    assert!(status.is_ready(), "ArrayDecoder should be complete after 4 bytes");
    assert_eq!(data, &[0x05, 0x06]);

    let result = decoder.end().unwrap();
    assert_eq!(result, [0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn decode_array_insufficient_data_error() {
    let mut decoder = ArrayDecoder::<5>::new();
    let mut data = &[0xAA, 0xBB][..];

    let status = decoder.push_bytes(&mut data).unwrap();
    assert!(
        status.needs_more(),
        "ArrayDecoder should need more data after 2 bytes for 5-byte array"
    );
    assert_eq!(data, EMPTY);

    let err = decoder.end().unwrap_err();
    assert!(matches!(err, UnexpectedEofError { .. }));
}

#[test]
fn decode_array_zero_size() {
    // Test zero-sized array decoder which doesn't consume any bytes.
    let mut decoder = ArrayDecoder::<0>::new();
    let mut data = &[0x01, 0x02, 0x03][..];

    let status = decoder.push_bytes(&mut data).unwrap();
    assert!(status.is_ready(), "zero-sized ArrayDecoder should not need data");
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

    let status = decoder.push_bytes(&mut empty_data).unwrap();
    assert!(status.needs_more(), "decoder should still need data after empty push");
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
    let status = decoder.push_bytes(&mut data).unwrap();
    assert!(status.needs_more(), "should need more data for second decoder");
    assert_eq!(data.len(), 0, "all data should be consumed");

    assert_eq!(decoder.read_limit(), 3);
    let mut more_data = &[0x03, 0x04, 0x05][..];
    let status = decoder.push_bytes(&mut more_data).unwrap();
    assert!(status.is_ready(), "should not need more data after completing both decoders");
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
    let status = decoder2.push_bytes(&mut data).unwrap();
    assert!(status.needs_more(), "should need more data for second decoder");
    assert_eq!(data.len(), 0, "all data should be consumed");
    assert_eq!(decoder2.read_limit(), 3);
}

#[test]
fn decode_decoder2_end_with_first_decoder_incomplete() {
    // Test calling end() when first decoder is incomplete.
    let mut decoder = Decoder2::new(ArrayDecoder::<5>::new(), ArrayDecoder::<3>::new());

    let mut data = &[0x01, 0x02][..];
    let _ = decoder.push_bytes(&mut data);
    let err = decoder.end().unwrap_err();

    assert!(matches!(err, encoding::Decoder2Error::First(UnexpectedEofError { .. })));
}

#[test]
fn decode_decoder2_end_with_second_decoder_incomplete() {
    // Test calling end() when second decoder is incomplete.
    let mut decoder = Decoder2::new(ArrayDecoder::<2>::new(), ArrayDecoder::<5>::new());

    let mut data = &[0x01, 0x02, 0x03][..];
    let _ = decoder.push_bytes(&mut data);
    let err = decoder.end().unwrap_err();

    assert!(matches!(err, encoding::Decoder2Error::Second(UnexpectedEofError { .. })));
}

#[test]
fn decode_decoder2_with_zero_sized_first_decoder_end() {
    // Test edge case where first decoder needs 0 bytes.
    let mut decoder = Decoder2::new(ArrayDecoder::<0>::new(), ArrayDecoder::<3>::new());

    let mut data = &[0x42][..];
    let _ = decoder.push_bytes(&mut data);

    let err = decoder.end().unwrap_err();
    assert!(matches!(err, encoding::Decoder2Error::Second(UnexpectedEofError { .. })));
}

#[test]
#[cfg(feature = "alloc")]
fn decode_byte_vec_decoder_empty() {
    // Test decoding empty byte vector, with length prefix of 0.
    use encoding::{ByteVecDecoder, Decoder};

    let mut decoder = ByteVecDecoder::new();
    let mut data = &[0x00][..];
    let status = decoder.push_bytes(&mut data).unwrap();
    assert!(status.is_ready(), "decoder should not need more data for empty vector");
    assert_eq!(data.len(), 0, "all data should be consumed");
    assert_eq!(decoder.read_limit(), 0);
    let result = decoder.end().unwrap();
    assert!(result.is_empty());
}

#[test]
#[cfg(feature = "alloc")]
fn decode_byte_vec_decoder_does_not_overconsume() {
    use encoding::ByteVecDecoder;

    let mut decoder = ByteVecDecoder::new();
    let mut data = &[0x02, 0xAA, 0xBB, 0xCC, 0xDD][..];
    assert!(decoder.push_bytes(&mut data).unwrap().is_ready());
    assert_eq!(data, &[0xCC, 0xDD][..]);
    assert_eq!(decoder.end().unwrap(), vec![0xAA, 0xBB]);
}

#[test]
#[cfg(feature = "alloc")]
fn decode_byte_vec_decoder_does_not_overconsume_on_second_chunk() {
    use encoding::ByteVecDecoder;

    // First chunk prefix declares 4 payload bytes and provides the first one.
    let mut first_chunk: &[u8] = &[0x04, 0xAA];
    // Second chunk provides the remaining 3 payload bytes plus two trailing bytes.
    let mut second_chunk: &[u8] = &[0xBB, 0xCC, 0xDD, 0x11, 0x22];

    let mut decoder = ByteVecDecoder::new();

    assert!(decoder.push_bytes(&mut first_chunk).unwrap().needs_more());
    assert!(first_chunk.is_empty());

    let status = decoder.push_bytes(&mut second_chunk).unwrap();
    assert!(status.is_ready());
    assert_eq!(second_chunk, &[0x11, 0x22][..]);

    let decoded_vec = decoder.end().unwrap();
    assert_eq!(decoded_vec, vec![0xAA, 0xBB, 0xCC, 0xDD]);
}

#[derive(Debug, PartialEq)]
struct TestArray([u8; 4]);

impl Decode for TestArray {
    type Decoder = TestArrayDecoder;
}

#[derive(Default)]
struct TestArrayDecoder {
    inner: ArrayDecoder<4>,
}

impl Decoder for TestArrayDecoder {
    type Output = TestArray;
    type Error = UnexpectedEofError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<encoding::DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> { self.inner.end().map(TestArray) }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

#[test]
fn decode_from_slice_success() {
    let data = [1, 2, 3, 4];
    let result: Result<TestArray, _> = decode_from_slice(&data);
    assert!(result.is_ok());
    let decoded = result.unwrap();
    assert_eq!(decoded.0, [1, 2, 3, 4]);
}

#[test]
fn decode_from_slice_unexpected_eof() {
    let data = [1, 2, 3];
    let result: Result<TestArray, _> = decode_from_slice(&data);
    assert!(result.is_err());
}

#[test]
fn decode_from_slice_extra_data() {
    let data = [1, 2, 3, 4, 5];
    let result: Result<TestArray, _> = decode_from_slice(&data);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, DecodeError::Unconsumed(_)));
}

#[test]
fn decode_from_slice_unbounded_extra_data() {
    let data = [1, 2, 3, 4, 5];
    let bytes = &mut data.as_slice();
    let result: Result<TestArray, _> = decode_from_slice_unbounded(bytes);
    assert!(result.is_ok());
    let decoded = result.unwrap();
    assert_eq!(decoded.0, [1, 2, 3, 4]);
    assert_eq!(bytes.len(), 1);
}

#[test]
#[cfg(feature = "hex")]
fn decode_from_hex_test() {
    let result: Result<TestArray, _> = decode_from_hex("01020304");
    assert_eq!(result.unwrap().0, [0x01, 0x02, 0x03, 0x04]);
    let result: Result<TestArray, _> = decode_from_hex("DEADBEEF");
    assert_eq!(result.unwrap().0, [0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
#[cfg(all(feature = "hex", feature = "alloc"))]
fn decode_from_hex_larger_than_internal_buffer() {
    const COUNT: usize = 1100;

    let mut encoded = vec![0xFD, 0x4C, 0x04];
    encoded.extend(core::iter::repeat(0xDEAD_BEEF_u32.to_le_bytes()).take(COUNT).flatten());
    assert!(encoded.len() > 4096);

    let mut hex = String::with_capacity(encoded.len() * 2);
    for byte in &encoded {
        hex.push_str(&format!("{:02x}", byte));
    }

    let result: Result<Test, _> = decode_from_hex(&hex);
    assert_eq!(result.unwrap(), Test(vec![Inner(0xDEAD_BEEF); COUNT]));
}

#[test]
#[cfg(feature = "hex")]
fn decode_from_hex_error() {
    let result: Result<TestArray, _> = decode_from_hex("0102030");
    assert!(matches!(result, Err(FromHexError::OddLength(_))));
    let result: Result<TestArray, _> = decode_from_hex("0102GG04");
    assert!(matches!(result, Err(FromHexError::InvalidChar(_))));
    let result: Result<TestArray, _> = decode_from_hex("0102");
    assert!(matches!(result, Err(FromHexError::Decode(DecodeError::Parse(_)))));
    let result: Result<TestArray, _> = decode_from_hex("");
    assert!(matches!(result, Err(FromHexError::Decode(DecodeError::Parse(_)))));
    let result: Result<TestArray, _> = decode_from_hex("0102030405060708");
    assert!(matches!(result, Err(FromHexError::Decode(DecodeError::Unconsumed(_)))));
}

#[test]
#[cfg(feature = "std")]
fn decode_from_read_extra_data() {
    let data = [1, 2, 3, 4, 5, 6];
    let mut cursor = Cursor::new(&data);
    let result: Result<TestArray, _> = decode_from_read(&mut cursor);
    assert!(result.is_ok());
    let decoded = result.unwrap();
    assert_eq!(decoded.0, [1, 2, 3, 4]);
}

#[test]
#[cfg(feature = "std")]
fn decode_from_read_success() {
    let data = [1, 2, 3, 4];
    let cursor = Cursor::new(&data);
    let result: Result<TestArray, _> = decode_from_read(cursor);
    assert!(result.is_ok());
    let decoded = result.unwrap();
    assert_eq!(decoded.0, [1, 2, 3, 4]);
}

#[test]
#[cfg(feature = "std")]
fn decode_from_read_unexpected_eof() {
    let data = [1, 2, 3];
    let cursor = Cursor::new(&data);
    let result: Result<TestArray, _> = decode_from_read(cursor);
    assert!(matches!(result, Err(ReadError::Decode(_))));
}

#[test]
#[cfg(feature = "std")]
fn decode_from_read_trait_object() {
    let data = [1, 2, 3, 4];
    let mut cursor = Cursor::new(&data);
    // Test that we can pass a trait object (&mut dyn BufRead implements BufRead).
    let reader: &mut dyn std::io::BufRead = &mut cursor;
    let result: Result<TestArray, _> = decode_from_read(reader);
    assert!(result.is_ok());
    let decoded = result.unwrap();
    assert_eq!(decoded.0, [1, 2, 3, 4]);
}

#[test]
#[cfg(feature = "std")]
fn decode_from_read_by_reference() {
    let data = [1, 2, 3, 4];
    let mut cursor = Cursor::new(&data);
    // Test that we can pass by reference (&mut T implements BufRead when T: BufRead).
    let result: Result<TestArray, _> = decode_from_read(&mut cursor);
    assert!(result.is_ok());
    let decoded = result.unwrap();
    assert_eq!(decoded.0, [1, 2, 3, 4]);

    let mut buf = Vec::new();
    let _ = cursor.read_to_end(&mut buf);
}

#[test]
#[cfg(feature = "std")]
fn decode_from_read_unbuffered_success() {
    let data = [1, 2, 3, 4];
    let cursor = Cursor::new(&data);
    let result: Result<TestArray, _> = decode_from_read_unbuffered(cursor);
    assert!(result.is_ok());
    let decoded = result.unwrap();
    assert_eq!(decoded.0, [1, 2, 3, 4]);
}

#[test]
#[cfg(feature = "std")]
fn decode_from_read_unbuffered_unexpected_eof() {
    let data = [1, 2, 3];
    let cursor = Cursor::new(&data);
    let result: Result<TestArray, _> = decode_from_read_unbuffered(cursor);
    assert!(matches!(result, Err(ReadError::Decode(_))));
}

#[test]
#[cfg(feature = "std")]
fn decode_from_read_unbuffered_empty() {
    let data = [];
    let cursor = Cursor::new(&data);
    let result: Result<TestArray, _> = decode_from_read_unbuffered(cursor);
    assert!(matches!(result, Err(ReadError::Decode(_))));
}

#[test]
#[cfg(feature = "std")]
fn decode_from_read_unbuffered_extra_data() {
    let data = [1, 2, 3, 4, 5, 6];
    let cursor = Cursor::new(&data);
    let result: Result<TestArray, _> = decode_from_read_unbuffered(cursor);
    assert!(result.is_ok());
    let decoded = result.unwrap();
    assert_eq!(decoded.0, [1, 2, 3, 4]);
}

#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct Inner(u32);

#[cfg(feature = "alloc")]
#[derive(Clone, Default)]
struct InnerDecoder(ArrayDecoder<4>);

#[cfg(feature = "alloc")]
impl Decoder for InnerDecoder {
    type Output = Inner;
    type Error = UnexpectedEofError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<encoding::DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let n = u32::from_le_bytes(self.0.end()?);
        Ok(Inner(n))
    }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "alloc")]
impl Decode for Inner {
    type Decoder = InnerDecoder;
}

#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct Test(Vec<Inner>);

#[cfg(feature = "alloc")]
#[derive(Clone, Default)]
struct TestDecoder(VecDecoder<Inner>);

#[cfg(feature = "alloc")]
impl Decoder for TestDecoder {
    type Output = Test;
    type Error = VecDecoderError<UnexpectedEofError>;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<encoding::DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let v = self.0.end()?;
        Ok(Test(v))
    }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "alloc")]
impl Decode for Test {
    type Decoder = TestDecoder;
}

// Stress test the push_bytes impl by passing in a single byte slice repeatedly.
macro_rules! check_decode_one_byte_at_a_time {
    ($decoder:expr; $($test_name:ident, $want:expr, $array:expr);* $(;)?) => {
        $(
            #[test]
            #[allow(non_snake_case)]
            fn $test_name() {
                let mut decoder = $decoder;

                for (i, _) in $array.iter().enumerate() {
                    if i < $array.len() - 1 {
                        let mut p = &$array[i..i+1];
                        assert!(decoder.push_bytes(&mut p).unwrap().needs_more());
                    } else {
                        // last byte: `push_bytes` should return Ready since no more bytes required.
                        let mut p = &$array[i..];
                        assert!(decoder.push_bytes(&mut p).unwrap().is_ready());
                    }
                }

                let got = decoder.end().unwrap();
                assert_eq!(got, $want);
            }
        )*

    }
}

check_decode_one_byte_at_a_time! {
    CompactSizeDecoder::new_with_limit(0xF0F0_F0F0);
    decode_compact_size_0x10, 0x10, [0x10];
    decode_compact_size_0xFC, 0xFC, [0xFC];
    decode_compact_size_0xFD, 0xFD, [0xFD, 0xFD, 0x00];
    decode_compact_size_0x100, 0x100, [0xFD, 0x00, 0x01];
    decode_compact_size_0xFFF, 0x0FFF, [0xFD, 0xFF, 0x0F];
    decode_compact_size_0x0F0F_0F0F, 0x0F0F_0F0F, [0xFE, 0xF, 0xF, 0xF, 0xF];
}

#[cfg(feature = "alloc")]
fn two_fifty_six_bytes_encoded() -> Vec<u8> {
    let data = [0xff; 256];
    let mut v = Vec::with_capacity(259);

    v.extend_from_slice(&[0xFD, 0x00, 0x01]); // 256 encoded as a  compact size.
    v.extend_from_slice(&data);
    v
}

#[cfg(feature = "alloc")]
check_decode_one_byte_at_a_time! {
    ByteVecDecoder::default();
        decode_byte_vec, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
    [0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        decode_byte_vec_multi_byte_length_prefix, [0xff; 256], two_fifty_six_bytes_encoded();
}

#[test]
#[cfg(feature = "alloc")]
fn vec_decoder_empty() {
    // Empty with a couple of arbitrary extra bytes.
    check_decode(&[0x00], &Test(vec![]));
}

#[test]
#[cfg(feature = "alloc")]
fn vec_decoder_one_item() {
    let encoded = vec![0x01, 0xEF, 0xBE, 0xAD, 0xDE];
    check_decode(&encoded, &Test(vec![Inner(0xDEAD_BEEF)]));
}

#[test]
#[cfg(feature = "alloc")]
fn vec_decoder_two_items() {
    let encoded = vec![0x02, 0xEF, 0xBE, 0xAD, 0xDE, 0xBE, 0xBA, 0xFE, 0xCA];
    check_decode(&encoded, &Test(vec![Inner(0xDEAD_BEEF), Inner(0xCAFE_BABE)]));
}

#[test]
#[cfg(feature = "alloc")]
fn vec_decoder_clone_mid_decode() {
    // Feed the length prefix and first item, clone, then feed the second item to both.
    let prefix = vec![0x02, 0xEF, 0xBE, 0xAD, 0xDE]; // length=2, first item
    let second = vec![0xBE, 0xBA, 0xFE, 0xCA]; // second item

    let mut slice = prefix.as_slice();
    let mut decoder = Test::decoder();
    decoder.push_bytes(&mut slice).unwrap();

    let mut clone = decoder.clone();

    let mut slice = second.as_slice();
    decoder.push_bytes(&mut slice).unwrap();
    let got = decoder.end().unwrap();
    assert_eq!(got, Test(vec![Inner(0xDEAD_BEEF), Inner(0xCAFE_BABE)]));

    let mut slice = second.as_slice();
    clone.push_bytes(&mut slice).unwrap();
    let got = clone.end().unwrap();
    assert_eq!(got, Test(vec![Inner(0xDEAD_BEEF), Inner(0xCAFE_BABE)]));
}

#[cfg(feature = "alloc")]
fn two_fifty_six_elements() -> Test {
    Test(core::iter::repeat(Inner(0xDEAD_BEEF)).take(256).collect())
}

#[cfg(feature = "alloc")]
fn two_fifty_six_elements_encoded() -> Vec<u8> {
    [0xFD, 0x00, 0x01] // 256 encoded as a  compact size.
        .into_iter()
        .chain(core::iter::repeat(0xDEAD_BEEF_u32.to_le_bytes()).take(256).flatten())
        .collect()
}

#[cfg(feature = "alloc")]
check_decode_one_byte_at_a_time! {
    TestDecoder::default();
        decode_vec, Test(vec![Inner(0xDEAD_BEEF), Inner(0xCAFE_BABE)]),
    vec![0x02, 0xEF, 0xBE, 0xAD, 0xDE, 0xBE, 0xBA, 0xFE, 0xCA];
        decode_vec_multi_byte_length_prefix, two_fifty_six_elements(), two_fifty_six_elements_encoded();
}

#[test]
#[cfg(feature = "alloc")]
fn vec_decoder_one_item_plus_more_data() {
    // One u32 plus some other bytes.
    check_decode(&[0x01, 0xEF, 0xBE, 0xAD, 0xDE], &Test(vec![Inner(0xDEAD_BEEF)]));
}

#[cfg(feature = "std")]
#[test]
fn decode_vec_from_read_unbuffered_success() {
    let encoded = [0x01, 0xEF, 0xBE, 0xAD, 0xDE, 0xff, 0xff, 0xff, 0xff];
    let mut cursor = Cursor::new(&encoded);

    let got = encoding::decode_from_read_unbuffered::<Test, _>(&mut cursor).unwrap();
    assert_eq!(cursor.position(), 5);

    let want = Test(vec![Inner(0xDEAD_BEEF)]);
    assert_eq!(got, want);
}

#[test]
#[cfg(feature = "alloc")]
fn decode_byte_vec_decoder_end_incomplete_length_prefix() {
    let mut decoder = ByteVecDecoder::new();
    let mut data = &[0xFD, 0x05][..];
    let status = decoder.push_bytes(&mut data).unwrap();
    assert!(status.needs_more());

    let err = decoder.end().unwrap_err();
    assert!(matches!(err, encoding::ByteVecDecoderError { .. }));
}

#[test]
#[cfg(feature = "alloc")]
fn decode_byte_vec_decoder_end_incomplete_data() {
    // Length=5 but only 2 bytes of data.
    let mut decoder = ByteVecDecoder::new();
    let mut data = &[0x05, 0xAA, 0xBB][..];
    let status = decoder.push_bytes(&mut data).unwrap();
    assert!(status.needs_more());

    let err = decoder.end().unwrap_err();
    assert!(matches!(err, encoding::ByteVecDecoderError { .. }));
}

#[test]
#[cfg(feature = "alloc")]
fn decode_vec_decoder_end_incomplete_length_prefix() {
    let mut decoder = VecDecoder::<Inner>::new();
    let mut data = &[0xFD, 0x05][..];
    let status = decoder.push_bytes(&mut data).unwrap();
    assert!(status.needs_more());

    let err = decoder.end().unwrap_err();
    assert!(matches!(err, encoding::VecDecoderError { .. }));
}

#[test]
#[cfg(feature = "alloc")]
fn decode_vec_decoder_end_incomplete_item() {
    // Length=3 but only 2 bytes of data.
    let mut decoder = VecDecoder::<Inner>::new();
    let mut data = &[0x03, 0xAA, 0xBB][..];
    let status = decoder.push_bytes(&mut data).unwrap();
    assert!(status.needs_more());

    let err = decoder.end().unwrap_err();
    assert!(matches!(err, encoding::VecDecoderError { .. }));
}

#[test]
#[cfg(feature = "alloc")]
#[should_panic(expected = "decoded value doesn't match expected value")]
fn check_decode_panic_on_mismatched_value() {
    let encoded = [0xEF, 0xBE, 0xAD, 0xDEu8];
    let expected = Inner(0x1234_5678);
    check_decode(&encoded, &expected);
}

#[test]
#[should_panic(expected = "decoded value doesn't match expected value")]
fn check_decoder_panic_on_mismatched_value() {
    let decoder = ArrayDecoder::<1>::new();
    let bytes = &[0x42u8][..];
    let expected = [0x99u8];
    check_decoder(decoder, bytes, &expected);
}
