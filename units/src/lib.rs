// SPDX-License-Identifier: CC0-1.0

//! Basic (numeric) types used by the Rust Bitcoin ecosystem.
//!
//! This crate contains basic types that have minimal requirements on the platform they run on.
//! Specifically, they do not require an allocator and they do not require `usize` to be at least
//! 32-bit. If you need more than this crate provides check the [`bitcoin`] crate or the
//! [`bitcoin-primitives`] crate.
//!
//! # Guidance on crate use
//!
//! Libraries that only need the types present in this crate should depend only on this crate, not
//! `bitcoin` or `bitcoin-primitives` so that they don't add bloat to compilation and review. It is
//! recommended that binaries or other root crates depend on `bitcoin` during the prototyping stage
//! and then optionally try to trim down the dependencies by using the leaf crates. However this is
//! unlikely to be feasible for non-trivial applications.
//!
//! If you are using the `bitcoin` crate then you do not need to access this crate directly.
//! Everything here is re-exported in `bitcoin` at the same path. Also the same re-exports exist in
//! `bitcoin-primitives` if you are using that crate instead of `bitcoin`.
//!
//! ## Features
//!
//! * `std` - turns on `std` integration, mainly the `std::error::Error` trait in old Rust versions.
//! * `alloc` - turns on features that require the `alloc` crate, such as `String` interop.
//! * `serde` - causes the crate to depend on `serde` and provide support for serializing and
//!   deserializing its types.
//! * `arbitrary` - causes the crate to depend on `arbitrary` and implement the `Arbitrary` trait.
//!
//! # MSRV
//!
//! This crate supports Rust 1.63, however some of its dependencies may not do so or may require
//! pinning. Similarly, some features may require newer Rust version (implicitly or explicitly).
//!
//! ## Policy
//!
//! The crate should always compile on latest Debian stable and on any compiler version that is up
//! to two years old. Note that 1.63 is the version currently available in Debian 12.
//!
//! # Examples
//!
//! ```
//! // Exactly the same as `use bitcoin::{amount, Amount}`.
//! use bitcoin_units::{amount, Amount};
//!
//! let amount = Amount::from_sat(1_000)?;
//! # let _ = amount;
//! # Ok::<_, amount::OutOfRangeError>(())
//! ```
//!
//! [`bitcoin`]: https://docs.rs/bitcoin
//! [`bitcoin-primitives`]: https://docs.rs/bitcoin-primitives

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

mod internal_macros;
mod result;

#[doc(hidden)]
pub mod _export {
    /// A re-export of `core::*`.
    pub mod _core {
        pub use core::*;
    }
}

pub mod amount;
pub mod block;
pub mod fee;
pub mod fee_rate;
pub mod locktime;
pub mod parse;
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
    result::{NumOpError, NumOpResult, MathOp},
    sequence::Sequence,
    time::BlockTime,
    weight::Weight
};
pub(crate) use self::result::OptionExt;

#[deprecated(since = "TBD", note = "use `BlockHeightInterval` instead")]
#[doc(hidden)]
pub type BlockInterval = BlockHeightInterval;
