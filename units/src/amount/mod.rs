// SPDX-License-Identifier: CC0-1.0

//! Bitcoin amounts.
//!
//! This module mainly introduces the [`Amount`] and [`SignedAmount`] types.
//! We refer to the documentation on the types for more information.
//!
//! Forwarded from `bitcoin-units` 0.5.0 (see the crate-level docs on the semver trick), plus a
//! compat shim restoring [`SignedAmount::checked_abs`] which 0.5.0 removed.

#[doc(inline)]
pub use units_v0_5::amount::*;

/// Restores [`SignedAmount::checked_abs`], removed from `bitcoin-units` in 0.5.0.
///
/// Import this trait to call `checked_abs` on a [`SignedAmount`] as if it were still an
/// inherent method, the way it was in 0.4.0.
pub trait SignedAmountExt: crate::sealed::Sealed {
    /// Returns the absolute value of this [`SignedAmount`].
    ///
    /// Consider using `unsigned_abs` which is often more practical.
    #[must_use]
    #[deprecated(since = "1.0.0-rc.0", note = "Never returns none, use `abs()` instead")]
    fn checked_abs(self) -> Option<units_v0_5::SignedAmount>;
}

impl SignedAmountExt for units_v0_5::SignedAmount {
    #[allow(clippy::unnecessary_wraps)] // To match stdlib function definition.
    fn checked_abs(self) -> Option<units_v0_5::SignedAmount> { Some(self.abs()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn signed_amount_checked_abs() {
        let amount = units_v0_5::SignedAmount::from_sat(-100).unwrap();
        assert_eq!(amount.checked_abs(), Some(amount.abs()));
    }
}
