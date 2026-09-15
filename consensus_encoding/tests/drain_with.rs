// SPDX-License-Identifier: CC0-1.0

//! Tests that the optimized drain-based [`Encoder::drain_with`] interface produces the same bytes
//! as the pull-based interface ([`Encoder::current_chunk`] and [`Encoder::advance`]), including
//! when called on a partially-advanced encoder.

#![cfg(feature = "alloc")]

use bitcoin_consensus_encoding::{
    ArrayEncoder, BytesEncoder, Encode, Encoder, Encoder2, Encoder3, Encoder6, EncoderStatus,
    IterEncoder, PrefixedSliceEncoder, SliceEncoder,
};

/// Collects an encoder's with the pull-based interface, one chunk at a time.
fn pull_to_vec<E: Encoder>(enc: &mut E) -> Vec<u8> {
    let mut v = Vec::new();
    loop {
        v.extend_from_slice(enc.current_chunk());
        if enc.advance().has_finished() {
            break;
        }
    }
    v
}

/// Advances `enc` `n` times, returning false if the encoder finished early.
fn advance_n<E: Encoder>(enc: &mut E, n: usize) -> bool {
    for _ in 0..n {
        if enc.advance().has_finished() {
            return false;
        }
    }
    true
}

/// Checks that the drain-based `drain_with` produces the same bytes as the pull-based loop, both
/// from the start and after every possible number of `advance()` calls that leaves the encoder
/// unfinished.
fn check_drain_with<E: Encoder>(mut make: impl FnMut() -> E) {
    let mut testable_depths = 0;
    let mut probe = make();
    while probe.advance().has_more() {
        testable_depths += 1;
    }

    for n in 0..=testable_depths {
        let mut pull_enc = make();
        let mut drain_enc = make();
        assert!(advance_n(&mut pull_enc, n));
        assert!(advance_n(&mut drain_enc, n));

        let mut drained = Vec::new();
        drain_enc.drain_with(&mut |chunk| drained.extend_from_slice(chunk));

        assert_eq!(pull_to_vec(&mut pull_enc), drained, "outputs differ after {} advances", n);
    }
}

/// Item type whose encoding may be empty (exercises empty-item skipping).
enum MaybeEmpty {
    Empty,
    Data(u8),
}

impl Encode for MaybeEmpty {
    type Encoder<'e>
        = BytesEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        match self {
            Self::Empty => BytesEncoder::without_length_prefix(&[]),
            Self::Data(x) => BytesEncoder::without_length_prefix(core::slice::from_ref(x)),
        }
    }
}

struct U32(u32);

impl Encode for U32 {
    type Encoder<'e>
        = ArrayEncoder<4>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        ArrayEncoder::without_length_prefix(self.0.to_le_bytes())
    }
}

fn enc(b: &'static [u8]) -> BytesEncoder<'static> { BytesEncoder::without_length_prefix(b) }

#[test]
fn drain_with_leaf_encoders() {
    check_drain_with(|| ArrayEncoder::without_length_prefix([1, 2, 3, 4]));
    check_drain_with(|| enc(&[5, 6, 7]));
    check_drain_with(|| ArrayEncoder::<0>::without_length_prefix([]));
}

#[test]
fn drain_with_option_encoder() {
    check_drain_with(|| Some(ArrayEncoder::without_length_prefix([9, 8, 7, 6])));
    check_drain_with(|| Option::<ArrayEncoder<4>>::None);
}

#[test]
fn drain_with_encoder2() {
    check_drain_with(|| {
        Encoder2::new(ArrayEncoder::without_length_prefix([1, 2, 3, 4]), enc(&[5, 6]))
    });
}

#[test]
fn drain_with_encoder3_with_empty_first() {
    check_drain_with(|| {
        Encoder3::new(
            ArrayEncoder::<0>::without_length_prefix([]),
            enc(&[1, 2]),
            ArrayEncoder::without_length_prefix([3, 4, 5, 6]),
        )
    });
}

#[test]
fn drain_with_iter_encoder() {
    check_drain_with(|| {
        IterEncoder::new([enc(&[]), enc(&[1, 2]), enc(&[]), enc(&[3]), enc(&[4, 5, 6])])
    });
}

#[test]
fn drain_with_slice_encoder() {
    check_drain_with(|| SliceEncoder::without_length_prefix(&[U32(1), U32(2), U32(3)]));
}

#[test]
fn drain_with_slice_encoder_with_empty_items() {
    check_drain_with(|| {
        SliceEncoder::without_length_prefix(&[
            MaybeEmpty::Empty,
            MaybeEmpty::Data(1),
            MaybeEmpty::Empty,
            MaybeEmpty::Data(2),
        ])
    });
}

#[test]
fn drain_with_prefixed_slice_encoder() {
    check_drain_with(|| PrefixedSliceEncoder::new(&[U32(7), U32(8)]));
}

#[test]
fn drain_with_nested_composite() {
    check_drain_with(|| {
        Encoder3::new(
            ArrayEncoder::without_length_prefix([0, 0, 0, 2]),
            PrefixedSliceEncoder::new(&[U32(1), U32(2)]),
            SliceEncoder::without_length_prefix(&[MaybeEmpty::Data(9), MaybeEmpty::Empty]),
        )
    });
}

#[test]
fn drain_with_encoder6_with_options_and_slices() {
    // Models the shape of segwit transaction encoding.
    check_drain_with(|| {
        Encoder6::new(
            ArrayEncoder::without_length_prefix([2, 0, 0, 0]),
            Some(ArrayEncoder::without_length_prefix([0, 1])),
            PrefixedSliceEncoder::new(&[U32(1), U32(2)]),
            PrefixedSliceEncoder::new(&[MaybeEmpty::Data(3), MaybeEmpty::Empty]),
            Some(IterEncoder::new([enc(&[4, 5]), enc(&[6])])),
            ArrayEncoder::without_length_prefix([0, 0, 0, 0]),
        )
    });
}

#[test]
fn drain_with_encoder6_with_none_options() {
    check_drain_with(|| {
        Encoder6::new(
            ArrayEncoder::without_length_prefix([1, 0, 0, 0]),
            Option::<ArrayEncoder<2>>::None,
            PrefixedSliceEncoder::new(&[U32(1)]),
            PrefixedSliceEncoder::new(&[U32(2)]),
            Option::<BytesEncoder>::None,
            ArrayEncoder::without_length_prefix([0, 0, 0, 0]),
        )
    });
}

#[test]
fn drain_with_marks_encoder_finished() {
    let mut enc = Encoder2::new(ArrayEncoder::without_length_prefix([1, 2, 3, 4]), enc(&[5, 6]));
    let mut out = Vec::new();
    enc.drain_with(&mut |chunk| out.extend_from_slice(chunk));
    assert_eq!(out, [1, 2, 3, 4, 5, 6]);
    // After draining, advance() reports the encoder as finished.
    assert_eq!(enc.advance(), EncoderStatus::Finished);
}
