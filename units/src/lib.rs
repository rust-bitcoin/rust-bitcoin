// SPDX-License-Identifier: CC0-1.0

//! Rust Bitcoin - unit types
//!
//! This library provides basic types used by the Rust Bitcoin ecosystem.
//!
//! If you are using `rust-bitcoin` then you do not need to access this crate directly. Everything
//! here is re-exported in `rust-bitcoin` at the same path. Also the same re-exports exist in
//! `primitives` if you are using that crate instead of `bitcoin`.
//!
//! # Examples
//!
//! ```
//! // Exactly the same as `use bitcoin::{amount, Amount}`.
//! use bitcoin_units::{amount, Amount};
//!
//! let _amount = Amount::from_sat(1_000)?;
//! # Ok::<_, amount::OutOfRangeError>(())
//! ```

#![no_std]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Exclude lints we don't think are valuable.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)`instead of enforcing `format!("{x}")`

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// Re-export the `consensus-encoding-unbuffered-io` crate.
#[cfg(feature = "consensus-encoding-unbuffered-io")]
pub extern crate consensus_encoding_unbuffered_io;

#[doc(hidden)]
pub mod _export {
    /// A re-export of `core::*`.
    pub mod _core {
        pub use core::*;
    }
}

mod fee;
mod internal_macros;

pub mod amount;
pub mod block;
pub mod fee_rate;
pub mod locktime;
pub mod parse;
pub mod result;
pub mod sequence;
pub mod time;
pub mod weight;

#[doc(inline)]
#[rustfmt::skip]
pub use self::{
    amount::{Amount, SignedAmount},
    block::{BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval},
    fee_rate::FeeRate,
    locktime::{absolute, relative},
    result::NumOpResult,
    sequence::Sequence,
    time::BlockTime,
    weight::Weight
};

#[deprecated(since = "TBD", note = "use `BlockHeightInterval` instead")]
#[doc(hidden)]
pub type BlockInterval = BlockHeightInterval;

/// Constructs a new `Error::ParseFailed` error.
// This whole variant should go away because of the inner string.
#[cfg(feature = "consensus-encoding-unbuffered-io")]
pub(crate) fn parse_failed_error(msg: &'static str) -> consensus_encoding_unbuffered_io::Error {
    consensus_encoding_unbuffered_io::Error::Parse(
        consensus_encoding_unbuffered_io::ParseError::ParseFailed(msg),
    )
}
