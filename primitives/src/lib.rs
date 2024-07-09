// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin - primitive types.
//!
//! Primitive data types that are used throughout the [`rust-bitcoin`] ecosystem.
//!
//! [`rust-bitcoin`]: <https://github.com/rust-bitcoin>

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Coding conventions.
#![warn(missing_docs)]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::needless_borrows_for_generic_args)] // https://github.com/rust-lang/rust-clippy/issues/12454

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "serde")]
extern crate actual_serde as serde;

pub mod opcodes;

#[rustfmt::skip]
#[allow(unused_imports)]
mod prelude {
    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::string::ToString;

    #[cfg(any(feature = "std", test))]
    pub use std::string::ToString;
}
