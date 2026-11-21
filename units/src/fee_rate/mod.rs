// SPDX-License-Identifier: CC0-1.0

//! The [`FeeRate`] type.
//!
//! Forwarded from `bitcoin-units` 0.5.0 (see the crate-level docs on the semver trick), plus a
//! compat shim restoring the `FeeRate` methods that 0.5.0 removed.

#[doc(inline)]
pub use units_v0_5::fee_rate::*;
use units_v0_5::{Amount, Weight};

/// Restores `FeeRate` methods that `bitcoin-units` removed in 0.5.0.
///
/// Import this trait to call `fee_wu`/`fee_vb` on a [`FeeRate`] as if they
/// were still inherent methods, the way they were in 0.4.0.
pub trait FeeRateExt: crate::sealed::Sealed {
    /// Calculates the fee by multiplying this fee rate by weight, in weight units, returning [`None`]
    /// if an overflow occurred.
    ///
    /// This is equivalent to `Self::mul_by_weight(weight).ok()`.
    #[must_use]
    #[deprecated(since = "1.0.0-rc.0", note = "use `to_fee()` instead")]
    fn fee_wu(self, weight: Weight) -> Option<Amount>;

    /// Calculates the fee by multiplying this fee rate by weight, in virtual bytes, returning [`None`]
    /// if `vb` cannot be represented as [`Weight`].
    ///
    /// This is equivalent to converting `vb` to [`Weight`] using [`Weight::from_vb`] and then calling
    /// `to_fee()`.
    #[must_use]
    #[deprecated(since = "1.0.0-rc.0", note = "use Weight::from_vb and then `to_fee()` instead")]
    fn fee_vb(self, vb: u64) -> Option<Amount>;
}

impl FeeRateExt for units_v0_5::FeeRate {
    fn fee_wu(self, weight: Weight) -> Option<Amount> { self.mul_by_weight(weight).ok() }
    fn fee_vb(self, vb: u64) -> Option<Amount> { Weight::from_vb(vb).map(|w| self.to_fee(w)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn fee_rate_fee_wu() {
        let fee_rate = units_v0_5::FeeRate::from_sat_per_vb(2);
        let weight = Weight::from_vb(3).unwrap();
        assert_eq!(fee_rate.fee_wu(weight), Some(fee_rate.to_fee(weight)));
        assert_eq!(fee_rate.fee_wu(Weight::MAX), None);
    }

    #[test]
    #[allow(deprecated)]
    fn fee_rate_fee_vb() {
        let fee_rate = units_v0_5::FeeRate::from_sat_per_vb(2);
        assert_eq!(fee_rate.fee_vb(3), Some(fee_rate.to_fee(Weight::from_vb(3).unwrap())));
        assert_eq!(fee_rate.fee_vb(u64::MAX), None);
    }
}
