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

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

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
    weight::Weight
};
