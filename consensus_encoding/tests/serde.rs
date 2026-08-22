// SPDX-License-Identifier: CC0-1.0

//! Tests for `serde_as_consensus`.

#![cfg(feature = "serde")]

use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, Decode, Decoder, DecoderStatus, Encode, UnexpectedEofError,
};

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct WithConsensus(
    #[serde(with = "bitcoin_consensus_encoding::serde_as_consensus")] TestArray<4>,
);

#[test]
fn serialize_array_bytes_as_hex_json() {
    let value = WithConsensus(TestArray([0xef, 0xbe, 0xad, 0xde]));

    assert_eq!(serde_json::to_string(&value).unwrap(), "\"efbeadde\"");
}

#[test]
fn deserialize_hex_json_into_array() {
    let json = "\"efbeadde\"";

    let decoded: WithConsensus = serde_json::from_str(json).unwrap();

    assert_eq!(
        decoded,
        WithConsensus(TestArray([0xef, 0xbe, 0xad, 0xde]))
    );
}

#[test]
fn deserialize_invalid_hex_json() {
    let json = "\"zzbeadde\"";

    let err = serde_json::from_str::<WithConsensus>(json).unwrap_err();

    assert!(
        err.to_string().contains("hex")
            || err.to_string().contains("decode")
            || err.to_string().contains("invalid")
    );
}

#[test]
fn deserialize_odd_length_hex_json() {
    let json = "\"efbeadd\"";

    let err = serde_json::from_str::<WithConsensus>(json).unwrap_err();

    assert!(
        err.to_string().contains("odd")
            || err.to_string().contains("length")
            || err.to_string().contains("hex")
    );
}
