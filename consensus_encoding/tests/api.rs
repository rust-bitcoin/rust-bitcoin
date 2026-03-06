// SPDX-License-Identifier: CC0-1.0

//! Test the API surface of `consensus_encoding`.
//!
//! The point of these tests is to check the API surface as opposed to test the API functionality.
//!
//! ref: <https://rust-lang.github.io/api-guidelines/about.html>

#![allow(dead_code)]
#![allow(unused_imports)]

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
    use bitcoin_consensus_encoding::{
        CompactSizeDecoderError, Decoder2Error, Decoder3Error, Decoder4Error, Decoder6Error,
        UnexpectedEofError,
    };
    #[cfg(feature = "alloc")]
    use bitcoin_consensus_encoding::{
        ByteVecDecoderError, LengthPrefixExceedsMaxError, VecDecoderError,
    };
}
