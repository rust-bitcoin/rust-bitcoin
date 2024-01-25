// SPDX-License-Identifier: CC0-1.0

//! Rust Bitcoin units library
//!
//! This library provides basic types used by the Rust Bitcoin ecosystem.

// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

// Coding conventions.
#![warn(missing_docs)]

// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.

#![no_std]

// Disable 16-bit support at least for now as we can't guarantee it yet.
#[cfg(target_pointer_width = "16")]
compile_error!(
    "rust-bitcoin currently only supports architectures with pointers wider than 16 bits, let us
    know if you want 16-bit support. Note that we do NOT guarantee that we will implement it!"
);

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// A generic serialization/deserialization framework.
#[cfg(feature = "serde")]
pub extern crate serde;

pub mod amount;

#[doc(inline)]
pub use self::amount::{Amount, ParseAmountError, SignedAmount};
