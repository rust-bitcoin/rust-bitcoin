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

// We only support machines with index size of 4 bytes or more.
//
// Bitcoin consensus code relies on being able to have containers with more than 65536 (2^16)
// entries in them so we cannot support consensus logic on machines that only have 16-bit memory
// addresses.
//
// We specifically do not use `target_pointer_width` because of the possibility that pointer width
// does not equal index size.
//
// ref: https://github.com/rust-bitcoin/rust-bitcoin/pull/2929#discussion_r1661848565
internals::const_assert!(
    core::mem::size_of::<usize>() >= 4;
    "platforms that have usize less than 32 bits are not supported"
);

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

// FIXME: With all the errors this probably needs to be public.
mod decode;
mod encode;

pub use self::decode::decoders::{
    ArrayDecoder, Decoder2, Decoder3, Decoder4, Decoder6, Either, UnexpectedEofError, VecDecoder,
    VecDecoderError,
};
pub use self::decode::{decode_compact_size, CompactSizeDecodeError, Decodable, Decoder};
#[cfg(feature = "alloc")]
pub use self::encode::encode_to_vec;
#[cfg(feature = "std")]
pub use self::encode::encode_to_writer;
pub use self::encode::encoders::{
    ArrayEncoder, BytesEncoder, Encoder2, Encoder3, Encoder4, Encoder6,
};
pub use self::encode::{encode_to_hash_engine, Encodable, Encoder};
