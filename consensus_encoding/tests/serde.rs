// SPDX-License-Identifier: CC0-1.0

//! Tests for `serde_as_consensus`.

#![cfg(feature = "serde")]

use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, Decode, Decoder, DecoderStatus, Encode, UnexpectedEofError,
};

struct TestArray<const N: usize>([u8; N]);

impl<const N: usize> Encode for TestArray<N> {
    type Encoder<'e>
        = ArrayEncoder<N>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> { ArrayEncoder::without_length_prefix(self.0) }
}

#[derive(Default)]
struct TestArrayDecoder<const N: usize>(ArrayDecoder<N>);

impl<const N: usize> Decoder for TestArrayDecoder<N> {
    type Output = TestArray<N>;
    type Error = UnexpectedEofError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> { self.0.end().map(TestArray) }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl<const N: usize> Decode for TestArray<N> {
    type Decoder = TestArrayDecoder<N>;
}

#[derive(serde::Serialize)]
struct WithConsensus(
    #[serde(with = "bitcoin_consensus_encoding::serde_as_consensus")] TestArray<4>,
);

#[test]
fn serialize_array_bytes_as_hex_json() {
    let value = WithConsensus(TestArray([0xef, 0xbe, 0xad, 0xde]));

    assert_eq!(serde_json::to_string(&value).unwrap(), "\"efbeadde\"");
}
