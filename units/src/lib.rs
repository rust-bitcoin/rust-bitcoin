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
#![allow(clippy::needless_borrows_for_generic_args)] // https://github.com/rust-lang/rust-clippy/issues/12454
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

#[cfg(test)]
#[macro_use]
mod test_macros;

pub mod amount;
#[cfg(feature = "alloc")]
pub mod fee_rate;
#[cfg(feature = "alloc")]
pub mod locktime;
#[cfg(feature = "alloc")]
pub mod parse;
#[cfg(feature = "alloc")]
pub mod weight;

#[doc(inline)]
pub use self::amount::{Amount, SignedAmount};
pub use self::amount::ParseAmountError;
#[cfg(feature = "alloc")]
pub use self::parse::ParseIntError;
#[cfg(feature = "alloc")]
#[doc(inline)]
pub use self::{
    fee_rate::FeeRate,
    weight::Weight,
};

#[rustfmt::skip]
#[allow(unused_imports)]
mod prelude {
    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub use alloc::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, slice, rc};

    #[cfg(feature = "std")]
    pub use std::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, rc};
}
