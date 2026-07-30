// SPDX-License-Identifier: CC0-1.0

//! Test the API surface (not functionality) of `bitcoin-consensus-encoding`.
//!
//! See [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/about.html) and the [rust-bitcoin policies](../../docs/policy.md).

#![allow(dead_code)]
#![allow(unused_imports)]

use core::convert::Infallible;
use core::fmt;

use bitcoin_consensus_encoding::{
    self as encoding, encoder_newtype, ArrayDecoder, ArrayEncoder, ArrayRefEncoder, BytesEncoder,
    CompactSizeDecoder, CompactSizeDecoderError, CompactSizeEncoder, CompactSizeU64Decoder, Decode,
    Decoder, Decoder2, Decoder3, Decoder4, Decoder6, Encode, EncoderByteIter, SliceEncoder,
    UnexpectedEofError,
};
use encoding::error::{DecodeError, UnconsumedError};
#[cfg(feature = "std")]
use encoding::ReadError;
#[cfg(feature = "alloc")]
use encoding::{
    ByteVecDecoder, ByteVecDecoderError, LengthPrefixExceedsMaxError, VecDecoder, VecDecoderError,
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
    h: CompactSizeU64Decoder,
    i: Decoder2<D, D>,
    j: Decoder3<D, D, D>,
    k: Decoder4<D, D, D, D>,
    l: Decoder6<D, D, D, D, D, D>,
    m: EncoderByteIter<FooEncoder<'static>>,
    n: SliceEncoder<'static, Foo>,
    #[cfg(feature = "alloc")]
    o: VecDecoder<Foo>,
}

// Dummy decoder to use in place of generic.
type D = FooDecoder;

// Dummy type that can be encoded/decoded.
#[derive(Debug, Clone)]
struct Foo([u8; 4]);

impl Foo {
    fn dummy() -> Self { Self([0; 4]) }
}

encoder_newtype! {
    #[derive(Debug, Clone)]
    pub struct FooEncoder<'e>(ArrayEncoder<4>);
}

impl Encode for Foo {
    type Encoder<'e>
        = FooEncoder<'e>
    where
        Self: 'e;
    fn encoder(&self) -> Self::Encoder<'_> {
        FooEncoder::new(ArrayEncoder::without_length_prefix(self.0))
    }
}

#[derive(Debug, Default, Clone)]
struct FooDecoder(ArrayDecoder<4>);

impl Decoder for FooDecoder {
    type Output = Foo;
    type Error = UnexpectedEofError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<encoding::DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes)
    }
    fn end(self) -> Result<Self::Output, Self::Error> { self.0.end().map(Foo) }
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl Decode for Foo {
    type Decoder = FooDecoder;
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
    h: CompactSizeU64Decoder,
    // We don't implement Clone for the composite decoders.
    //
    // i: Decoder2<D, D>,
    // j: Decoder3<D, D, D>,
    // k: Decoder4<D, D, D, D>,
    // l: Decoder6<D, D, D, D, D, D>,
    m: EncoderByteIter<FooEncoder<'static>>,
    n: SliceEncoder<'static, Foo>,
    #[cfg(feature = "alloc")]
    o: VecDecoder<Foo>,
}

/// A struct that includes all types that implement `Default` (implies decoders).
#[derive(Default)] // C-COMMON-TRAITS: `Default`
struct Default {
    a: ArrayDecoder<4>,
    #[cfg(feature = "alloc")]
    e: ByteVecDecoder,
    f: CompactSizeDecoder,
    h: CompactSizeU64Decoder,
    // We don't implement Default for the composite decoders.
    //
    // i: Decoder2<D, D>,
    // j: Decoder3<D, D, D>,
    // k: Decoder4<D, D, D, D>,
    // l: Decoder6<D, D, D, D, D, D>,
    #[cfg(feature = "alloc")]
    o: VecDecoder<Foo>,
}

/// A struct that includes all public error types.
// These derives are the policy of `rust-bitcoin` not Rust API guidelines.
#[derive(Debug, Clone, PartialEq, Eq)] // All public types implement Debug (C-DEBUG).
struct Errors {
    // a: ReadError<UnexpectedEofError>, // Debug only, tested below.
    b: DecodeError<UnexpectedEofError>,
    c: UnconsumedError,
    d: CompactSizeDecoderError,
    #[cfg(feature = "alloc")]
    e: LengthPrefixExceedsMaxError,
    #[cfg(feature = "alloc")]
    f: ByteVecDecoderError,
    #[cfg(feature = "alloc")]
    g: VecDecoderError<UnexpectedEofError>,
    h: UnexpectedEofError,
}

/// C-DEBUG-NONEMPTY: Tests that `ReadError` has non-empty Debug.
#[test]
#[cfg(feature = "std")]
fn c_debug_nonempty_read_error() {
    use std::io::{BufReader, Cursor};

    let s = String::new();
    let cursor = Cursor::new(s.as_bytes());
    let reader = BufReader::new(cursor);
    let err = encoding::decode_from_read::<Foo, BufReader<Cursor<&[u8]>>>(reader).unwrap_err();
    let debug = format!("{:?}", err);
    assert!(!debug.is_empty()); // We don't check this for other errors.
}

/// C-DEBUG-NONEMPTY: Tests that all public non-error types have non-empty Debug.
#[test]
fn c_debug_nonempty() {
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
    let debug = format!("{:?}", CompactSizeU64Decoder::default());
    assert!(!debug.is_empty());

    let d = || FooDecoder::default();

    let debug = format!("{:?}", Decoder2::new(d(), d()));
    assert!(!debug.is_empty());
    let debug = format!("{:?}", Decoder3::new(d(), d(), d()));
    assert!(!debug.is_empty());
    let debug = format!("{:?}", Decoder4::new(d(), d(), d(), d()));
    assert!(!debug.is_empty());
    let debug = format!("{:?}", Decoder6::new(d(), d(), d(), d(), d(), d()));
    assert!(!debug.is_empty());

    let debug = format!("{:?}", EncoderByteIter::new(Foo::dummy().encoder()));
    assert!(!debug.is_empty());
    let debug = format!("{:?}", SliceEncoder::without_length_prefix(&[Foo::dummy()]));
    assert!(!debug.is_empty());
    #[cfg(feature = "alloc")]
    {
        let debug = format!("{:?}", VecDecoder::<Foo>::default());
        assert!(!debug.is_empty());
    }
}

/// C-SEND-SYNC: Tests that all public types implement `Send` + `Sync`.
#[test]
fn c_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    //  Types are `Send` and `Sync` where possible (C-SEND-SYNC).
    assert_send::<Structs>();
    assert_sync::<Structs>();

    // Error types should implement the Send and Sync traits (C-GOOD-ERR).
    assert_send::<Errors>();
    assert_sync::<Errors>();
}

/// C-GOOD-ERR: Tests that all public error types implement Display.
#[test]
fn c_good_err_display() {
    fn assert_display<T: fmt::Display>() {}

    #[cfg(feature = "std")]
    assert_display::<ReadError<UnexpectedEofError>>();
    assert_display::<DecodeError<UnexpectedEofError>>();
    assert_display::<UnconsumedError>();
    assert_display::<CompactSizeDecoderError>();
    #[cfg(feature = "alloc")]
    assert_display::<LengthPrefixExceedsMaxError>();
    #[cfg(feature = "alloc")]
    assert_display::<ByteVecDecoderError>();
    #[cfg(feature = "alloc")]
    assert_display::<VecDecoderError<UnexpectedEofError>>();
    assert_display::<UnexpectedEofError>();
}

/// C-OBJECT: Tests that traits are object-safe where appropriate.
#[test]
fn c_object() {
    // If this builds then traits are dyn compatible.
    struct Traits {
        a: Box<dyn encoding::Encoder>,
        b: Box<dyn encoding::ExactSizeEncoder>,
    }
    // The following traits are not dyn compatible:
    // - `Encode`: has a GAT (`type Encoder<'e>`)
    // - `Decode`: has an associated type (`type Decoder`)
    // - `Decoder`: has a `Sized` bound
}

/// P-ERROR-INFALLIBLE: Tests that error types implement `From<Infallible>`.
#[test]
fn p_error_infallible() {
    fn assert_from_infallible<T: From<Infallible>>() {}

    assert_from_infallible::<DecodeError<UnexpectedEofError>>();
    assert_from_infallible::<UnconsumedError>();
    assert_from_infallible::<CompactSizeDecoderError>();
    #[cfg(feature = "alloc")]
    assert_from_infallible::<LengthPrefixExceedsMaxError>();
    #[cfg(feature = "alloc")]
    assert_from_infallible::<ByteVecDecoderError>();
    #[cfg(feature = "alloc")]
    assert_from_infallible::<VecDecoderError<UnexpectedEofError>>();
    assert_from_infallible::<UnexpectedEofError>();
}
