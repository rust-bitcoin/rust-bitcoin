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

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod fee;
mod internal_macros;

#[doc(hidden)]
pub mod _export {
    /// A re-export of `core::*`.
    pub mod _core {
        pub use core::*;
    }
}

pub mod amount;
pub mod block;
pub mod fee_rate;
pub mod locktime;
pub mod parse;
pub mod timestamp;
pub mod weight;

#[doc(inline)]
#[rustfmt::skip]
pub use self::{
    amount::{Amount, SignedAmount},
    block::{BlockHeight, BlockInterval},
    fee_rate::FeeRate,
    timestamp::Timestamp,
    weight::Weight
};
