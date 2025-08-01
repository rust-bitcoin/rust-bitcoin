// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin - consensus encoding and decoding
//!
//! This library provides traits that can be used to encode/decode objects in a
//! consensus-consistent way.
//!
//! ## Notes on I/O
//!
//! I/O in Rust has a few problems in relation to no-std, as such we depend on the [`bitcoin-io`]
//! crate and this library uses `io::Read` and `io::Write` to read and write respectively to readers
//! and writers that are, to the best of our ability, interoperable with `std::io`. This includes
//! error handling by way of the [`bitcoin_io::Error`].
//!
//! [bitcoin-io]: io
//! [`bitcoin_io::Error`]: io::Error

#![no_std]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Exclude lints we don't think are valuable.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)`instead of enforcing `format!("{x}")`

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;
