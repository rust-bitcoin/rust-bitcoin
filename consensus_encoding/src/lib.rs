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

mod encode;

pub use self::encode::encoders::{
    ArrayEncoder, BytesEncoder, Encoder2, Encoder3, Encoder4, Encoder6,
};
pub use self::encode::{Encodable, Encoder};
