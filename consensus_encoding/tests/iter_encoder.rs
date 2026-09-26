// SPDX-License-Identifier: CC0-1.0

//! Integration tests for [`IterEncoder`].

#![cfg(feature = "alloc")]

use bitcoin_consensus_encoding::{
    drain_to_vec, BytesEncoder, Encoder, Encoder2, EncoderStatus, IterEncoder,
};

/// Constructs a [`BytesEncoder`] from a static byte slice for use in tests.
fn enc(b: &'static [u8]) -> BytesEncoder<'static> { BytesEncoder::without_length_prefix(b) }

/// An encoder which yields a fixed sequence of chunks, any of which may be empty.
///
/// [`Encoder::current_chunk`] is documented as being allowed to return an empty slice, so an
/// encoder may yield nothing on its first state and still have bytes afterwards. [`BytesEncoder`]
/// cannot express that because it is finished after a single chunk.
struct ChunkedEncoder {
    chunks: &'static [&'static [u8]],
    pos: usize,
}

impl ChunkedEncoder {
    fn new(chunks: &'static [&'static [u8]]) -> Self { Self { chunks, pos: 0 } }
}

impl Encoder for ChunkedEncoder {
    fn current_chunk(&self) -> &[u8] { self.chunks.get(self.pos).copied().unwrap_or(&[]) }

    fn advance(&mut self) -> EncoderStatus {
        self.pos += 1;
        if self.pos < self.chunks.len() {
            EncoderStatus::HasMore
        } else {
            EncoderStatus::Finished
        }
    }
}

/// Drives an [`IterEncoder`] built from `iter` to completion, returning the encoded bytes.
fn encode<I>(iter: I) -> Vec<u8>
where
    I: IntoIterator,
    I::IntoIter: Iterator,
    <I::IntoIter as Iterator>::Item: bitcoin_consensus_encoding::Encoder,
{
    drain_to_vec(&mut IterEncoder::new(iter))
}

#[test]
fn empty_iterator() {
    let result = drain_to_vec(&mut IterEncoder::new(core::iter::empty::<BytesEncoder<'static>>()));
    assert_eq!(result, Vec::<u8>::new());
}

#[test]
fn iterator_of_empty_encoders() {
    assert_eq!(encode([enc(&[]), enc(&[])]), Vec::<u8>::new());
}

#[test]
fn single_encoder() {
    assert_eq!(encode([enc(&[1, 2, 3, 4])]), [1, 2, 3, 4]);
}

#[test]
fn multiple_encoders_in_sequence() {
    assert_eq!(encode([enc(&[1, 2]), enc(&[3, 4])]), [1, 2, 3, 4]);
}

#[test]
fn leading_empty_encoders_skipped() {
    let mut encoder = IterEncoder::new([enc(&[]), enc(&[]), enc(&[1, 2, 3])]);
    assert_eq!(encoder.current_chunk(), &[1, 2, 3]);
    assert_eq!(drain_to_vec(&mut encoder), [1, 2, 3]);
}

#[test]
fn trailing_empty_encoders_skipped() {
    assert_eq!(encode([enc(&[1, 2, 3]), enc(&[]), enc(&[])]), [1, 2, 3]);
}

#[test]
fn interleaved_empty_encoders_skipped() {
    assert_eq!(encode([enc(&[1]), enc(&[]), enc(&[2]), enc(&[]), enc(&[3])]), [1, 2, 3]);
}

#[test]
fn encoder_with_leading_empty_chunk_not_dropped() {
    assert_eq!(encode([ChunkedEncoder::new(&[&[], &[1, 2, 3]])]), [1, 2, 3]);
}

#[test]
fn encoder_with_multiple_leading_empty_chunks_not_dropped() {
    assert_eq!(encode([ChunkedEncoder::new(&[&[], &[], &[1, 2, 3]])]), [1, 2, 3]);
}

#[test]
fn encoder_with_leading_empty_chunk_not_dropped_mid_sequence() {
    let encoders = [
        ChunkedEncoder::new(&[&[1]]),
        ChunkedEncoder::new(&[&[], &[2]]),
        ChunkedEncoder::new(&[&[3]]),
    ];
    assert_eq!(encode(encoders), [1, 2, 3]);
}

#[test]
fn encoder_with_interior_empty_chunks_not_truncated() {
    assert_eq!(encode([ChunkedEncoder::new(&[&[1], &[], &[2], &[], &[3]])]), [1, 2, 3]);
}

#[test]
fn encoders_yielding_only_empty_chunks_skipped() {
    let encoders = [
        ChunkedEncoder::new(&[&[], &[]]),
        ChunkedEncoder::new(&[&[1, 2]]),
        ChunkedEncoder::new(&[&[], &[]]),
    ];
    assert_eq!(encode(encoders), [1, 2]);
}

#[test]
fn composite_encoder_with_empty_leading_component_not_dropped() {
    // `Encoder2` yields its first encoder's chunk first, so an empty leading component makes the
    // composite yield an empty chunk while it still has bytes to encode.
    let encoders = [
        Encoder2::new(enc(&[]), enc(&[1])),
        Encoder2::new(enc(&[2]), enc(&[])),
        Encoder2::new(enc(&[]), enc(&[3])),
    ];
    assert_eq!(encode(encoders), [1, 2, 3]);
}
