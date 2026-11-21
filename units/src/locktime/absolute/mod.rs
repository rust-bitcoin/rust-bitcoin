// SPDX-License-Identifier: CC0-1.0

//! Provides type [`LockTime`] that implements the logic around `nLockTime`/`OP_CHECKLOCKTIMEVERIFY`.
//!
//! There are two types of lock time: lock-by-blockheight and lock-by-blocktime, distinguished by
//! whether `LockTime < LOCK_TIME_THRESHOLD`.
//!
//! Forwarded from `bitcoin-units` 0.5.0 (see the crate-level docs on the semver trick), plus a
//! compat shim restoring the items that 0.5.0 removed.

use units_v0_5::locktime::absolute as v0_5;
#[doc(inline)]
pub use units_v0_5::locktime::absolute::*;

#[deprecated(since = "1.0.0-rc.0", note = "use `MedianTimePast` instead")]
#[doc(hidden)]
pub type Time = v0_5::MedianTimePast;

/// Restores `LockTime` constructors that `bitcoin-units` removed in 0.5.0.
pub trait LockTimeExt: Sized + crate::sealed::Sealed {
    /// Constructs a new `LockTime` from `n`, expecting `n` to be a median-time-past (MTP) which
    /// is in range for a locktime.
    #[deprecated(since = "1.0.0-rc.0", note = "use `from_mtp` instead")]
    #[doc(hidden)]
    fn from_time(n: u32) -> Result<Self, v0_5::ConversionError>;
}

impl LockTimeExt for v0_5::LockTime {
    fn from_time(n: u32) -> Result<Self, v0_5::ConversionError> { Self::from_mtp(n) }
}

/// Restores `Height` methods that `bitcoin-units` removed in 0.5.0.
pub trait HeightExt: Sized + crate::sealed::Sealed {
    /// Constructs a new block height directly from a `u32` value.
    #[deprecated(since = "1.0.0-rc.0", note = "use `from_u32` instead")]
    #[doc(hidden)]
    fn from_consensus(n: u32) -> Result<Self, v0_5::ConversionError>;

    /// Returns the inner `u32` value.
    #[deprecated(since = "1.0.0-rc.0", note = "use `to_u32` instead")]
    #[doc(hidden)]
    fn to_consensus_u32(self) -> u32;
}

impl HeightExt for v0_5::Height {
    fn from_consensus(n: u32) -> Result<Self, v0_5::ConversionError> { Self::from_u32(n) }
    fn to_consensus_u32(self) -> u32 { self.to_u32() }
}

/// Restores `MedianTimePast` methods that `bitcoin-units` removed in 0.5.0.
pub trait MedianTimePastExt: Sized + crate::sealed::Sealed {
    /// Constructs a new MTP directly from a `u32` value.
    #[deprecated(since = "1.0.0-rc.0", note = "use `from_u32` instead")]
    #[doc(hidden)]
    fn from_consensus(n: u32) -> Result<Self, v0_5::ConversionError>;

    /// Returns the inner `u32` value.
    #[deprecated(since = "1.0.0-rc.0", note = "use `to_u32` instead")]
    #[doc(hidden)]
    fn to_consensus_u32(self) -> u32;
}

impl MedianTimePastExt for v0_5::MedianTimePast {
    fn from_consensus(n: u32) -> Result<Self, v0_5::ConversionError> { Self::from_u32(n) }
    fn to_consensus_u32(self) -> u32 { self.to_u32() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn lock_time_from_time() {
        let n = 1_653_195_600;
        assert_eq!(LockTime::from_time(n).unwrap(), LockTime::from_mtp(n).unwrap());
    }

    #[test]
    #[allow(deprecated)]
    fn height_compat() {
        let h = v0_5::Height::from_u32(100).unwrap();
        assert_eq!(v0_5::Height::from_consensus(100).unwrap(), h);
        assert_eq!(h.to_consensus_u32(), h.to_u32());
    }

    #[test]
    #[allow(deprecated)]
    fn median_time_past_compat() {
        let mtp = v0_5::MedianTimePast::from_u32(1_653_195_600).unwrap();
        assert_eq!(v0_5::MedianTimePast::from_consensus(1_653_195_600).unwrap(), mtp);
        assert_eq!(mtp.to_consensus_u32(), mtp.to_u32());
    }

    #[test]
    #[allow(deprecated)]
    fn time_alias() { let _: Time = v0_5::MedianTimePast::from_u32(1_653_195_600).unwrap(); }
}
