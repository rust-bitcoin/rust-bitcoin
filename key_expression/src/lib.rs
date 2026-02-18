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

extern crate hex_stable as hex;

#[cfg(feature = "serde")]
extern crate serde;

// Pull in shared impl_array_newtype_stringify macro from include
// The impl_array_newtype_stringify requires crate::serde, $crate::hex and
// crate::hashes to exist.
include!("../include/array_newtype.rs");

#[cfg(feature = "alloc")]
pub mod bip32;
