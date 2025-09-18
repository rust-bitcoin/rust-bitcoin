// SPDX-License-Identifier: CC0-1.0

//! Test composition of encoders and decoders.

use consensus_encoding::{
    ArrayDecoder, ArrayEncoder, Decodable, Decoder, Decoder2, Decoder6, Encodable, Encoder,
    Encoder2, Encoder6,
};

const EMPTY: &[u8] = &[];

// A simple composite type that encodes as [4 bytes] + [2 bytes].
#[derive(Debug, PartialEq, Eq)]
struct CompositeData {
    first: [u8; 4],
    second: [u8; 2],
}

impl Encodable for CompositeData {
    type Encoder<'e> = Encoder2<ArrayEncoder<4>, ArrayEncoder<2>>;

    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder2::new(
            ArrayEncoder::without_length_prefix(self.first),
            ArrayEncoder::without_length_prefix(self.second),
        )
    }
}

/// A wrapper decoder that converts the tuple output to [`CompositeData`].
struct CompositeDataDecoder {
    inner: Decoder2<ArrayDecoder<4>, ArrayDecoder<2>>,
}

impl CompositeDataDecoder {
    fn new() -> Self {
        Self { inner: Decoder2::new(ArrayDecoder::<4>::new(), ArrayDecoder::<2>::new()) }
    }
}

impl Decoder for CompositeDataDecoder {
    type Output = CompositeData;
    type Error = <Decoder2<ArrayDecoder<4>, ArrayDecoder<2>> as Decoder>::Error;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.inner.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let (first, second) = self.inner.end()?;
        Ok(CompositeData { first, second })
    }
}

impl Decodable for CompositeData {
    type Decoder = CompositeDataDecoder;

    fn decoder() -> Self::Decoder { CompositeDataDecoder::new() }
}

#[test]
fn composition_chain() {
    let original = CompositeData { first: [0x01, 0x02, 0x03, 0x04], second: [0x05, 0x06] };
    // Encode using the pull encoder.
    let mut encoder = original.encoder();
    let mut encoded_bytes = Vec::new();
    while let Some(chunk) = encoder.current_chunk() {
        encoded_bytes.extend_from_slice(chunk);
        encoder.advance();
    }
    // Decode using the push decoder.
    let mut decoder = CompositeData::decoder();
    let mut bytes = &encoded_bytes[..];
    let needs_more = decoder.push_bytes(&mut bytes).unwrap();
    assert!(!needs_more, "CompositeData decoder should be ready to end");
    assert_eq!(bytes, EMPTY);
    let decoded = decoder.end().unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn composition_nested() {
    let data = b"abcdef";
    let mut encoder6 = Encoder6::new(
        ArrayEncoder::without_length_prefix([data[0]]),
        ArrayEncoder::without_length_prefix([data[1]]),
        ArrayEncoder::without_length_prefix([data[2]]),
        ArrayEncoder::without_length_prefix([data[3]]),
        ArrayEncoder::without_length_prefix([data[4]]),
        ArrayEncoder::without_length_prefix([data[5]]),
    );

    let mut encoded_bytes = Vec::new();
    while let Some(chunk) = encoder6.current_chunk() {
        encoded_bytes.extend_from_slice(chunk);
        encoder6.advance();
    }
    assert_eq!(encoded_bytes, data);

    let mut decoder6 = Decoder6::new(
        ArrayDecoder::<1>::new(),
        ArrayDecoder::<1>::new(),
        ArrayDecoder::<1>::new(),
        ArrayDecoder::<1>::new(),
        ArrayDecoder::<1>::new(),
        ArrayDecoder::<1>::new(),
    );
    let mut bytes = &encoded_bytes[..];
    let needs_more = decoder6.push_bytes(&mut bytes).unwrap();
    assert!(!needs_more, "Decoder6 should be ready to end");
    assert_eq!(bytes, EMPTY);
    let (first, second, third, fourth, fifth, sixth) = decoder6.end().unwrap();
    assert_eq!(first, [data[0]]);
    assert_eq!(second, [data[1]]);
    assert_eq!(third, [data[2]]);
    assert_eq!(fourth, [data[3]]);
    assert_eq!(fifth, [data[4]]);
    assert_eq!(sixth, [data[5]]);
}

#[test]
fn composition_extra_bytes() {
    // Test that Decoder2 consumes exactly what it needs and leaves extra bytes unconsumed.
    let mut decoder2 = Decoder2::new(ArrayDecoder::<2>::new(), ArrayDecoder::<3>::new());
    let mut bytes = &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08][..];
    let original_len = bytes.len();

    let needs_more = decoder2.push_bytes(&mut bytes).unwrap();
    assert!(!needs_more, "Decoder2 should be ready to end after consuming all needed bytes");

    let consumed = original_len - bytes.len();
    assert_eq!(consumed, 5, "Decoder2 should consume exactly 5 bytes");
    assert_eq!(bytes.len(), 3, "3 bytes should remain unconsumed");
    assert_eq!(bytes, &[0x06, 0x07, 0x08], "Remaining bytes should be the last 3");

    let (first, second) = decoder2.end().unwrap();
    assert_eq!(first, [0x01, 0x02], "First decoder should get first 2 bytes");
    assert_eq!(second, [0x03, 0x04, 0x05], "Second decoder should get next 3 bytes");
}
