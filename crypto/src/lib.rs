// SPDX-License-Identifier: CC0-1.0

//! Cryptography support for the rust-bitcoin ecosystem.

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

pub mod ecdsa;
pub mod key;
pub mod sighash;
