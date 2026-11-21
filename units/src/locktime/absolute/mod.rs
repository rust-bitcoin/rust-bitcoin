// SPDX-License-Identifier: CC0-1.0

//! Provides type [`LockTime`] that implements the logic around `nLockTime`/`OP_CHECKLOCKTIMEVERIFY`.
//!
//! There are two types of lock time: lock-by-blockheight and lock-by-blocktime, distinguished by
//! whether `LockTime < LOCK_TIME_THRESHOLD`.
//!
//! Forwarded from `bitcoin-units` 0.5.1 (see the crate-level docs on the semver trick), plus
//! aliases for the type names that 0.5.0 removed.

use units_v0_5::locktime::absolute as v0_5;
#[doc(inline)]
pub use units_v0_5::locktime::absolute::*;

#[deprecated(since = "1.0.0-rc.0", note = "use `MedianTimePast` instead")]
#[doc(hidden)]
pub type Time = v0_5::MedianTimePast;

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
