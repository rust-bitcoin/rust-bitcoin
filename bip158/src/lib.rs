// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin BIP-158 implementation.

#![no_std]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod filter;
mod hash_types;

pub use self::filter::{
    BasicFilter, BuildError, DecodeError, BASIC_FILTER_M, BASIC_FILTER_P, BASIC_FILTER_TYPE,
};
pub use self::hash_types::{
    FilterHash, FilterHashDecoder, FilterHashDecoderError, FilterHashEncoder, FilterHeader,
    FilterHeaderDecoder, FilterHeaderDecoderError, FilterHeaderEncoder,
};
