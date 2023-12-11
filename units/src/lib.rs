// SPDX-License-Identifier: CC0-1.0

//! Rust Bitcoin units library
//!
//! This library provides basic types used by the Rust Bitcoin ecosystem.

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Coding conventions
#![warn(missing_docs)]
// Exclude clippy lints we don't think are valuable
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134

// Disable 16-bit support at least for now as we can't guarantee it yet.
#[cfg(target_pointer_width = "16")]
compile_error!(
    "rust-bitcoin currently only supports architectures with pointers wider than 16 bits, let us
    know if you want 16-bit support. Note that we do NOT guarantee that we will implement it!"
);

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

#[cfg(not(feature = "std"))]
extern crate core;

/// A generic serialization/deserialization framework.
#[cfg(feature = "serde")]
pub extern crate serde;

// TODO: Make amount module less dependent on an allocator.
#[cfg(feature = "alloc")]
pub mod amount;

#[cfg(feature = "alloc")]
#[doc(inline)]
pub use self::amount::{Amount, ParseAmountError, SignedAmount};

#[rustfmt::skip]
mod prelude {
    #[cfg(all(feature = "alloc", not(feature = "std"), not(test)))]
    pub use alloc::string::{String, ToString};

    #[cfg(any(feature = "std", test))]
    pub use std::string::{String, ToString};
}
