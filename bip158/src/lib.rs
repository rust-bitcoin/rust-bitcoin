// SPDX-License-Identifier: CC0-1.0

//! # BIP-0158 compact block filters

#![no_std]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod hash_types;

pub use self::hash_types::{
    FilterHash, FilterHashDecoder, FilterHashDecoderError, FilterHashEncoder, FilterHeader,
    FilterHeaderDecoder, FilterHeaderDecoderError, FilterHeaderEncoder,
};

include!("../include/decoder_newtype.rs"); // decoder_newtype! macro
