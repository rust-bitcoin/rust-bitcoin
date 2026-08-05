// SPDX-License-Identifier: CC0-1.0

//! Tests for [`VecDecoderWith`] and [`ExactVecDecoderWith`].

#![cfg(feature = "alloc")]

use bitcoin_consensus_encoding::{
    ArrayDecoder, Decoder, DecoderStatus, ExactVecDecoderWith, UnexpectedEofError, VecDecoderWith,
};

/// A test item decoded from 4 little-endian bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Item(u32);

/// Decoder for [`Item`]: reads exactly 4 bytes and interprets them as a LE u32.
#[derive(Default, Clone)]
struct ItemDecoder(ArrayDecoder<4>);

impl Decoder for ItemDecoder {
    type Output = Item;
    type Error = UnexpectedEofError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        Ok(Item(u32::from_le_bytes(self.0.end()?)))
    }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

/// Decodes a [`VecDecoderWith`] from `bytes` in a single call, returning the decoded items.
fn decode_vec(bytes: &[u8]) -> Vec<Item> {
    let mut decoder = VecDecoderWith::<ItemDecoder>::new();
    let mut slice = bytes;
    decoder.push_bytes(&mut slice).unwrap();
    decoder.end().unwrap()
}

/// Decodes an [`ExactVecDecoderWith`] of the given `count` from `bytes` in a single call.
fn decode_exact(count: usize, bytes: &[u8]) -> Vec<Item> {
    let mut decoder = ExactVecDecoderWith::<ItemDecoder>::new(count);
    let mut slice = bytes;
    decoder.push_bytes(&mut slice).unwrap();
    decoder.end().unwrap()
}

#[test]
fn vec_decoder_with_empty() {
    assert_eq!(decode_vec(&[0x00]), vec![]);
}

#[test]
fn vec_decoder_with_single_item() {
    let bytes = [0x01, 0xEF, 0xBE, 0xAD, 0xDE];
    assert_eq!(decode_vec(&bytes), vec![Item(0xDEAD_BEEF)]);
}

#[test]
fn vec_decoder_with_multiple_items() {
    let bytes = [0x02, 0xEF, 0xBE, 0xAD, 0xDE, 0xBE, 0xBA, 0xFE, 0xCA];
    assert_eq!(decode_vec(&bytes), vec![Item(0xDEAD_BEEF), Item(0xCAFE_BABE)]);
}

#[test]
fn vec_decoder_with_needs_more_during_prefix() {
    let mut decoder = VecDecoderWith::<ItemDecoder>::new();
    let mut empty: &[u8] = &[];
    assert!(decoder.push_bytes(&mut empty).unwrap().needs_more());
}

#[test]
fn vec_decoder_with_needs_more_during_items() {
    let mut decoder = VecDecoderWith::<ItemDecoder>::new();
    // Prefix says 1 item but we only provide 2 of the 4 bytes.
    let mut partial: &[u8] = &[0x01, 0xEF, 0xBE];
    assert!(decoder.push_bytes(&mut partial).unwrap().needs_more());
}

#[test]
fn exact_vec_decoder_with_zero_count() {
    assert_eq!(decode_exact(0, &[]), vec![]);
}

#[test]
fn exact_vec_decoder_with_single_item() {
    let bytes = [0xEF, 0xBE, 0xAD, 0xDE];
    assert_eq!(decode_exact(1, &bytes), vec![Item(0xDEAD_BEEF)]);
}

#[test]
fn exact_vec_decoder_with_multiple_items() {
    let bytes = [0xEF, 0xBE, 0xAD, 0xDE, 0xBE, 0xBA, 0xFE, 0xCA];
    assert_eq!(decode_exact(2, &bytes), vec![Item(0xDEAD_BEEF), Item(0xCAFE_BABE)]);
}

#[test]
fn exact_vec_decoder_with_needs_more() {
    let mut decoder = ExactVecDecoderWith::<ItemDecoder>::new(1);
    // Only provide 2 of the 4 bytes needed.
    let mut partial: &[u8] = &[0xEF, 0xBE];
    assert!(decoder.push_bytes(&mut partial).unwrap().needs_more());
}

#[test]
fn exact_vec_decoder_with_zero_count_ignores_trailing_bytes() {
    // Bytes present, but count is 0. Decoder is immediately ready and leaves bytes unconsumed.
    let mut decoder = ExactVecDecoderWith::<ItemDecoder>::new(0);
    let mut bytes: &[u8] = &[0xFF, 0xFF];
    assert!(decoder.push_bytes(&mut bytes).unwrap().is_ready());
    assert_eq!(bytes.len(), 2);
}
