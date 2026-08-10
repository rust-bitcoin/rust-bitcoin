// SPDX-License-Identifier: CC0-1.0

//! Integration tests for [`IterEncoder`].

#![cfg(feature = "alloc")]

use bitcoin_consensus_encoding::{drain_to_vec, BytesEncoder, IterEncoder};

/// Constructs a [`BytesEncoder`] from a static byte slice for use in tests.
fn enc(b: &'static [u8]) -> BytesEncoder<'static> { BytesEncoder::without_length_prefix(b) }

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
    assert_eq!(encode([enc(&[]), enc(&[]), enc(&[1, 2, 3])]), [1, 2, 3]);
}

#[test]
fn trailing_empty_encoders_skipped() {
    assert_eq!(encode([enc(&[1, 2, 3]), enc(&[]), enc(&[])]), [1, 2, 3]);
}

#[test]
fn interleaved_empty_encoders_skipped() {
    assert_eq!(encode([enc(&[1]), enc(&[]), enc(&[2]), enc(&[]), enc(&[3])]), [1, 2, 3]);
}
