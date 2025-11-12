// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin - consensus encoding and decoding
//!
//! This library provides traits that can be used to encode/decode objects in a
//! consensus-consistent way.
//!

#![no_std]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod decode;
mod encode;

#[cfg(feature = "alloc")]
pub use self::decode::decoders::{
    cast_to_usize_if_valid, ByteVecDecoder, ByteVecDecoderError, LengthPrefixExceedsMaxError,
    VecDecoder, VecDecoderError,
};
pub use self::decode::decoders::{
    ArrayDecoder, CompactSizeDecoder, CompactSizeDecoderError, Decoder2, Decoder2Error, Decoder3,
    Decoder3Error, Decoder4, Decoder4Error, Decoder6, Decoder6Error, UnexpectedEofError,
};
#[cfg(feature = "std")]
pub use self::decode::{
    decode_from_read, decode_from_read_unbuffered, decode_from_read_unbuffered_with, ReadError,
};
pub use self::decode::{decode_from_slice, Decodable, Decoder};
#[cfg(feature = "alloc")]
pub use self::encode::encode_to_vec;
#[cfg(feature = "std")]
pub use self::encode::encode_to_writer;
pub use self::encode::encoders::{
    ArrayEncoder, BytesEncoder, CompactSizeEncoder, Encoder2, Encoder3, Encoder4, Encoder6,
    SliceEncoder,
};
pub use self::encode::{Encodable, Encoder, EncodableByteIter};
