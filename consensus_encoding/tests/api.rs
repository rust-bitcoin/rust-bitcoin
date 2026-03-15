// SPDX-License-Identifier: CC0-1.0

//! Test the API surface of `consensus_encoding`.
//!
//! The point of these tests is to check the API surface as opposed to test the API functionality.
//!
//! ref: <https://rust-lang.github.io/api-guidelines/about.html>

#![allow(dead_code)]
#![allow(unused_imports)]

use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, ArrayRefEncoder, BytesEncoder, CompactSizeDecoder,
    CompactSizeDecoderError, CompactSizeEncoder, UnexpectedEofError,
};
#[cfg(feature = "alloc")]
use bitcoin_consensus_encoding::{
    ByteVecDecoder, ByteVecDecoderError, LengthPrefixExceedsMaxError, VecDecoderError,
};

static BYTES: &[u8] = &[];

/// A struct that includes all public non-error structs.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Structs {
    a: ArrayDecoder<4>,
    b: ArrayEncoder<4>,
    c: ArrayRefEncoder<'static, 4>,
    d: BytesEncoder<'static>,
    #[cfg(feature = "alloc")]
    e: ByteVecDecoder,
    f: CompactSizeDecoder,
    g: CompactSizeEncoder,
}

/// A struct that includes all types that implement `Clone`.
#[derive(Clone)] // C-COMMON-TRAITS: `Clone`
struct Clone {
    a: ArrayDecoder<4>,
    b: ArrayEncoder<4>,
    c: ArrayRefEncoder<'static, 4>,
    d: BytesEncoder<'static>,
    #[cfg(feature = "alloc")]
    e: ByteVecDecoder,
    f: CompactSizeDecoder,
    g: CompactSizeEncoder,
}

/// A struct that includes all public error types.
// These derives are the policy of `rust-bitcoin` not Rust API guidelines.
#[derive(Debug, Clone, PartialEq, Eq)] // All public types implement Debug (C-DEBUG).
struct Errors {
    #[cfg(feature = "alloc")]
    a: ByteVecDecoderError,
    b: CompactSizeDecoderError,
    #[cfg(feature = "alloc")]
    c: LengthPrefixExceedsMaxError,
    d: UnexpectedEofError,
    #[cfg(feature = "alloc")]
    e: VecDecoderError<UnexpectedEofError>,
}

#[test]
fn api_can_use_all_encoder_types() {
    use bitcoin_consensus_encoding::{
        ArrayEncoder, ArrayRefEncoder, BytesEncoder, CompactSizeEncoder, Encoder2, Encoder3,
        Encoder4, Encoder6, SliceEncoder,
    };
}

#[test]
fn api_can_use_all_decoder_types() {
    use bitcoin_consensus_encoding::{
        ArrayDecoder, CompactSizeDecoder, Decoder2, Decoder3, Decoder4, Decoder6,
    };
    #[cfg(feature = "alloc")]
    use bitcoin_consensus_encoding::{ByteVecDecoder, VecDecoder};
}

#[test]
fn api_can_use_all_decoder_error_types() {
    use bitcoin_consensus_encoding::{CompactSizeDecoderError, UnexpectedEofError};
    #[cfg(feature = "std")]
    use bitcoin_consensus_encoding::ReadError;
    #[cfg(feature = "alloc")]
    use bitcoin_consensus_encoding::{
        ByteVecDecoderError, LengthPrefixExceedsMaxError, VecDecoderError,
    };
}

// `Debug` representation is never empty (C-DEBUG-NONEMPTY).
#[test]
fn api_all_non_error_types_have_non_empty_debug() {
    static ARR: [u8; 4] = [0u8; 4];

    let debug = format!("{:?}", ArrayDecoder::<4>::default());
    assert!(!debug.is_empty());
    let debug = format!("{:?}", ArrayEncoder::<4>::without_length_prefix([0u8; 4]));
    assert!(!debug.is_empty());
    let debug = format!("{:?}", ArrayRefEncoder::<4>::without_length_prefix(&ARR));
    assert!(!debug.is_empty());
    let debug = format!("{:?}", BytesEncoder::without_length_prefix(BYTES));
    assert!(!debug.is_empty());
    #[cfg(feature = "alloc")]
    {
        let debug = format!("{:?}", ByteVecDecoder::default());
        assert!(!debug.is_empty());
    }
    let debug = format!("{:?}", CompactSizeDecoder::default());
    assert!(!debug.is_empty());
    let debug = format!("{:?}", CompactSizeEncoder::new(0));
    assert!(!debug.is_empty());
}

#[test]
fn all_types_implement_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    //  Types are `Send` and `Sync` where possible (C-SEND-SYNC).
    assert_send::<Structs>();
    assert_sync::<Structs>();

    // Error types should implement the Send and Sync traits (C-GOOD-ERR).
    assert_send::<Errors>();
    assert_sync::<Errors>();
}

#[test]
fn dyn_compatible() {
    // If this builds then traits are dyn compatible.
    struct Traits {
        a: Box<dyn bitcoin_consensus_encoding::Encoder>,
        b: Box<dyn bitcoin_consensus_encoding::ExactSizeEncoder>,
    }
    // The following traits are not dyn compatible:
    // - `Encodable`: has a GAT (`type Encoder<'e>`)
    // - `Decodable`: has an associated type (`type Decoder`)
    // - `Decoder`: has a `Sized` bound
}