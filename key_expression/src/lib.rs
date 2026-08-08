// SPDX-License-Identifier: CC0-1.0

//! Bitcoin key expression and deterministic derivation
//!
//! This library provides types and functionality for key expressions and deterministic key
//! derivation.

#![no_std]
// Experimental features we need.
#![doc(test(attr(warn(unused))))]
// Coding conventions.
#![warn(deprecated_in_future)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

extern crate hashes;

extern crate hex;

#[cfg(feature = "serde")]
extern crate serde;

#[cfg(feature = "alloc")]
pub mod bip32;
