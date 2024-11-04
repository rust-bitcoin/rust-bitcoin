// SPDX-License-Identifier: CC0-1.0

//! Rust Bitcoin units library
//!
//! This library provides basic types used by the Rust Bitcoin ecosystem.

#![no_std]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod amount;
pub mod block;
pub mod fee_rate;
pub mod locktime;
pub mod parse;
pub mod weight;

#[doc(inline)]
#[rustfmt::skip]
pub use self::{
    amount::{Amount, SignedAmount},
    block::{BlockHeight, BlockInterval},
    fee_rate::FeeRate,
    weight::Weight
};
