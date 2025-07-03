// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin - unit types
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
//! let amount = Amount::from_sat(1_000)?;
//! # let _ = amount;
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
pub mod time;
pub mod weight;

#[doc(inline)]
#[rustfmt::skip]
pub use self::{
    amount::{Amount, SignedAmount},
    block::{BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval},
    fee_rate::FeeRate,
    result::{NumOpError, NumOpResult, MathOp},
    time::BlockTime,
    weight::Weight
};
pub(crate) use self::result::OptionExt;

#[deprecated(since = "TBD", note = "use `BlockHeightInterval` instead")]
#[doc(hidden)]
pub type BlockInterval = BlockHeightInterval;

/// Calculates the sum over the iterator using checked arithmetic.
pub trait CheckedSum<R>: sealed::Sealed<R> {
    /// Calculates the sum over the iterator using checked arithmetic. If an
    /// overflow happens it returns [`None`].
    fn checked_sum(self) -> Option<R>;
}

mod sealed {
    use super::{Amount, SignedAmount, Weight};

    /// Used to seal the `CheckedSum` trait
    pub trait Sealed<A> {}

    impl<T> Sealed<Amount> for T where T: Iterator<Item = Amount> {}
    impl<T> Sealed<SignedAmount> for T where T: Iterator<Item = SignedAmount> {}
    impl<T> Sealed<Weight> for T where T: Iterator<Item = Weight> {}
}
