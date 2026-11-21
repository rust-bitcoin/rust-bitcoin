// SPDX-License-Identifier: CC0-1.0

//! Provides type [`LockTime`] that implements the logic around `nSequence`/`OP_CHECKSEQUENCEVERIFY`.
//!
//! There are two types of lock time: lock-by-blockheight and lock-by-blocktime, distinguished by
//! whether bit 22 of the `u32` consensus value is set.
//!
//! Forwarded from `bitcoin-units` 0.5.0 (see the crate-level docs on the semver trick), plus a
//! compat shim restoring the items that 0.5.0 removed.

use units_v0_5::locktime::relative as v0_5;
#[doc(inline)]
pub use units_v0_5::locktime::relative::*;

#[deprecated(since = "1.0.0-rc.0", note = "use `NumberOfBlocks` instead")]
#[doc(hidden)]
pub type Height = v0_5::NumberOfBlocks;

#[deprecated(since = "1.0.0-rc.0", note = "use `NumberOf512Seconds` instead")]
#[doc(hidden)]
pub type Time = v0_5::NumberOf512Seconds;

/// Restores `NumberOfBlocks` methods that `bitcoin-units` removed in 0.5.0.
pub trait NumberOfBlocksExt: crate::sealed::Sealed {
    /// Returns the inner `u16` value.
    #[deprecated(since = "1.0.0-rc.0", note = "use `to_height` instead")]
    #[doc(hidden)]
    fn value(self) -> u16;

    /// Returns the `u32` value used to encode this locktime in an nSequence field or
    /// argument to `OP_CHECKSEQUENCEVERIFY`.
    #[deprecated(
        since = "1.0.0-rc.0",
        note = "use `LockTime::from` followed by `to_consensus_u32` instead"
    )]
    fn to_consensus_u32(self) -> u32;
}

impl NumberOfBlocksExt for v0_5::NumberOfBlocks {
    fn value(self) -> u16 { self.to_height() }
    fn to_consensus_u32(self) -> u32 { u32::from(self.to_height()) }
}

/// Restores `NumberOf512Seconds` methods that `bitcoin-units` removed in 0.5.0.
pub trait NumberOf512SecondsExt: crate::sealed::Sealed {
    /// Returns the inner `u16` value.
    #[deprecated(since = "1.0.0-rc.0", note = "use `to_512_second_intervals` instead")]
    #[doc(hidden)]
    fn value(self) -> u16;

    /// Returns the `u32` value used to encode this locktime in an nSequence field or
    /// argument to `OP_CHECKSEQUENCEVERIFY`.
    #[deprecated(
        since = "1.0.0-rc.0",
        note = "use `LockTime::from` followed by `to_consensus_u32` instead"
    )]
    fn to_consensus_u32(self) -> u32;
}

impl NumberOf512SecondsExt for v0_5::NumberOf512Seconds {
    fn value(self) -> u16 { self.to_512_second_intervals() }
    fn to_consensus_u32(self) -> u32 { (1u32 << 22) | u32::from(self.to_512_second_intervals()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn number_of_blocks_compat() {
        let n = v0_5::NumberOfBlocks::from_height(10);
        assert_eq!(n.value(), n.to_height());
        assert_eq!(n.to_consensus_u32(), u32::from(n.to_height()));

        let _: Height = n;
    }

    #[test]
    #[allow(deprecated)]
    fn number_of_512_seconds_compat() {
        let n = v0_5::NumberOf512Seconds::from_512_second_intervals(10);
        assert_eq!(n.value(), n.to_512_second_intervals());
        assert_eq!(n.to_consensus_u32(), (1u32 << 22) | u32::from(n.to_512_second_intervals()));

        let _: Time = n;
    }
}
