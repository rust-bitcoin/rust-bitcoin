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
//! 0.5.0 so that code depending on `"0.4"` and code depending on `"0.5"` share the exact same
//! types instead of the compiler treating them as two unrelated types. See
//! <https://github.com/rust-bitcoin/rust-bitcoin/issues/6338>.
//!
//! The items that were deprecated in 0.4.0 and then removed in 0.5.0 are restored here for 0.4.0
//! callers who have not yet migrated. The `parse_int::hex_{u16,u32,u64,u128}_unchecked` functions
//! are restored as free functions, removed type names as type aliases, and removed methods and
//! associated constants as extension traits. Because they now live on extension traits, the
//! restored methods are no longer `const fn` and the relevant trait has to be in scope to call
//! them.

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

pub mod amount;
pub mod fee_rate;
pub mod locktime;
pub mod parse_int;
pub mod pow;
pub mod sequence;
pub mod weight;

#[doc(inline)]
pub use units_v0_5::*;

#[deprecated(since = "1.0.0-rc.0", note = "use `BlockHeightInterval` instead")]
#[doc(hidden)]
pub type BlockInterval = BlockHeightInterval;

#[doc(inline)]
pub use amount::SignedAmountExt;
#[doc(inline)]
pub use fee_rate::FeeRateExt;
#[doc(inline)]
pub use locktime::{absolute, relative};
#[cfg(feature = "alloc")]
#[doc(inline)]
pub use pow::CompactTargetExt;
#[doc(inline)]
pub use sequence::SequenceExt;
#[doc(inline)]
pub use weight::WeightExt;

mod sealed {
    pub trait Sealed {}
    impl Sealed for units_v0_5::SignedAmount {}
    impl Sealed for units_v0_5::FeeRate {}
    impl Sealed for units_v0_5::Weight {}
    impl Sealed for units_v0_5::Sequence {}
    impl Sealed for units_v0_5::CompactTarget {}
    impl Sealed for units_v0_5::locktime::absolute::LockTime {}
    impl Sealed for units_v0_5::locktime::absolute::Height {}
    impl Sealed for units_v0_5::locktime::absolute::MedianTimePast {}
    impl Sealed for units_v0_5::locktime::relative::NumberOfBlocks {}
    impl Sealed for units_v0_5::locktime::relative::NumberOf512Seconds {}
}

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
        use crate::absolute::{HeightExt as _, LockTimeExt as _};
        use crate::relative::NumberOfBlocksExt as _;

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
