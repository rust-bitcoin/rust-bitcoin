// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin - consensus encoding and decoding
//!
//! This library provides traits that can be used to encode/decode objects in a
//! consensus-consistent way.
//!

#![no_std]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
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

pub use self::decode::decoders::{
    ArrayDecoder, Decoder2, Decoder3, Decoder4, Decoder6, DecoderError, Either, UnexpectedEof,
};
pub use self::decode::{Decodable, Decoder};
#[cfg(feature = "alloc")]
pub use self::encode::encode_to_vec;
#[cfg(feature = "std")]
pub use self::encode::encode_to_writer;
pub use self::encode::encoders::{
    ArrayEncoder, BytesEncoder, Encoder2, Encoder3, Encoder4, Encoder6,
};
pub use self::encode::{encode_to_hash_engine, Encodable, Encoder};
