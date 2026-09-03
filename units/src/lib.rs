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
//! *If you are using the `bitcoin` crate then you do not need to access this crate directly.*
//!
//! Everything here is re-exported in `bitcoin` at the same path. Also the same re-exports exist in
//! `bitcoin-primitives` if you are using that crate instead of `bitcoin`.
//!
//! Libraries that only need the types present in this crate should depend only on this crate, not
//! `bitcoin` or `bitcoin-primitives` so that they don't add bloat to compilation and review. It is
//! recommended that binaries or other root crates depend on `bitcoin` during the prototyping stage
//! and then optionally try to trim down the dependencies by using the leaf crates. However this is
//! unlikely to be feasible for non-trivial applications.
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
//! This crate supports Rust 1.74, however some of its dependencies may not do so or may require
//! pinning. Similarly, some features may require newer Rust version (implicitly or explicitly).
//!
//! ## Policy
//!
//! Our MSRV policy it to only bump MSRV to the one that is available on the latest Debian stable
//! and is at least two years old. However, we will try to be even more conservative when practical
//! given this crate is very widely used.
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
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Extra restriction lints.
#![warn(clippy::indexing_slicing)] // Avoid implicit panics from indexing/slicing.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "arbitrary")]
pub extern crate arbitrary;
#[cfg(feature = "encoding")]
pub extern crate encoding;
#[cfg(feature = "serde")]
pub extern crate serde;

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
pub mod parse_int;
pub mod pow;
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
    pow::{CompactTarget, Target, Work},
    result::NumOpResult,
    sequence::Sequence,
    time::BlockTime,
    weight::Weight
};

// decoder_newtype! macro
#[cfg(feature = "encoding")]
include!("../include/decoder_newtype.rs");
