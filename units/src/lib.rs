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

// We only support 32 and 64 bit machines.
//
// - We can't guarantee this lib works on architectures with less than 32 bit pointer width.
// - 128 bit machines don't exist yet but Rust does not implement `Into<u64>` for `usize`,
//   presumably to support 128 machines when they do exist. This makes conversion from `usize`
//   fallible which is annoying so we explicitly do not support 128 bit architectures.
#[cfg(all(not(target_pointer_width = "32"), not(target_pointer_width = "64")))]
compile_error!("bitcoin-units currently only supports 32 and 64 bit architectures.");

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
pub mod block;
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
#[cfg(feature = "alloc")]
#[doc(inline)]
#[rustfmt::skip]
pub use self::{
    block::{BlockHeight, BlockInterval},
    fee_rate::FeeRate,
    // ParseIntError is used by other modules, so we re-export it.
    parse::ParseIntError,
    weight::Weight
};

#[rustfmt::skip]
#[allow(unused_imports)]
mod prelude {
    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub use alloc::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, slice, rc};

    #[cfg(feature = "std")]
    pub use std::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, rc};
}
