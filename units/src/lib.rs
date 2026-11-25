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
//!
//! # Compatibility with 0.5.x
//!
//! This 0.4.1 release is a "semver trick" release (see
//! <https://github.com/dtolnay/semver-trick>): every type is forwarded from `bitcoin-units`
//! 0.5.1 so that code depending on `"0.4"` and code depending on `"0.5"` share the exact same
//! types instead of the compiler treating them as two unrelated types. See
//! <https://github.com/rust-bitcoin/rust-bitcoin/issues/6338>.
//!
//! The items that were deprecated in 0.4.0 and then removed in 0.5.0 are still available to 0.4.0
//! callers who have not yet migrated. Removed methods and associated constants are provided by
//! `bitcoin-units` 0.5.1 as hidden, deprecated inherent items. The
//! `parse_int::hex_{u16,u32,u64,u128}_unchecked` functions are restored here as free functions and
//! removed type names as type aliases.

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

pub mod locktime;
pub mod parse_int;

#[doc(inline)]
pub use units_v0_5::*;

#[deprecated(since = "1.0.0-rc.0", note = "use `BlockHeightInterval` instead")]
#[doc(hidden)]
pub type BlockInterval = BlockHeightInterval;

#[doc(inline)]
pub use locktime::{absolute, relative};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn block_interval_alias() {
        let interval: BlockInterval = BlockHeightInterval::MAX;
        assert_eq!(interval, BlockHeightInterval::MAX);
    }

    #[test]
    #[allow(deprecated)]
    fn root_locktime_modules_carry_restored_items() {
        let blocks: crate::relative::Height = crate::relative::NumberOfBlocks::from_height(10);
        assert_eq!(blocks.value(), 10);

        let intervals: crate::relative::Time =
            crate::relative::NumberOf512Seconds::from_512_second_intervals(10);
        assert_eq!(intervals.to_512_second_intervals(), 10);

        let mtp: crate::absolute::Time = crate::absolute::MedianTimePast::from_u32(1_653_195_600)
            .expect("in range for a median time past");
        assert_eq!(
            crate::absolute::LockTime::from_time(mtp.to_u32()),
            crate::absolute::LockTime::from_mtp(mtp.to_u32())
        );

        let height = crate::absolute::Height::from_consensus(100).expect("in range for a height");
        assert_eq!(height.to_u32(), 100);
    }
}
