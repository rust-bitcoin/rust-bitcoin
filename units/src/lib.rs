// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin Unit Types
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
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Exclude lints we don't think are valuable.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)` instead of enforcing `format!("{x}")`
// Extra restriction lints.
#![warn(clippy::indexing_slicing)] // Avoid implicit panics from indexing/slicing.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "encoding")]
pub extern crate encoding;

#[cfg(feature = "serde")]
pub extern crate serde;

#[cfg(feature = "arbitrary")]
pub extern crate arbitrary;

#[doc(hidden)]
pub mod _export {
    /// A re-export of `core::*`.
    pub mod _core {
        pub use core::*;
    }
}

// Keep the whole module even though nothing changed other than removing `hex_*_unchecked()`
// functions from `parse_int`. All the errors are the same but I (tcharding) wasn't able to work out
// how to re-export them.
pub mod parse_int;

// Semver everything from 0.5.0
// The only change was removal of 
pub use units::amount;
pub use units::block;
pub use units::fee_rate;
pub use units::locktime;
pub use units::pow;
pub use units::result;
pub use units::sequence;
pub use units::time;
pub use units::weight;

#[doc(inline)]
#[rustfmt::skip]
pub use self::{
    amount::{Amount, SignedAmount},
    block::{BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval},
    fee_rate::FeeRate,
    locktime::{absolute, relative},
    pow::{CompactTarget, Target, Work},
    result::NumOpResult,
    sequence::Sequence,
    time::BlockTime,
    weight::Weight
};

#[deprecated(since = "1.0.0-rc.0", note = "use `BlockHeightInterval` instead")]
#[doc(hidden)]
pub type BlockInterval = BlockHeightInterval;
