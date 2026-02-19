// SPDX-License-Identifier: CC0-1.0

//! Bitcoin hierarchichical deterministic key derivation
//!
//! This library provides types and functionality for hierarchical deterministic key
//! derivation based on BIP-32/380.

// NB: This crate is empty if `alloc` is not enabled.
#![cfg(feature = "alloc")]
#![no_std]
// Experimental features we need.
#![doc(test(attr(warn(unused))))]
// Coding conventions.
#![warn(deprecated_in_future)]
#![warn(missing_docs)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;
