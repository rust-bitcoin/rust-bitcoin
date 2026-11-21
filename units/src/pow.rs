// SPDX-License-Identifier: CC0-1.0

//! Proof-of-work related integer types, [`Target`], [`Work`] and [`CompactTarget`].
//!
//! Forwarded from `bitcoin-units` 0.5.0 (see the crate-level docs on the semver trick), plus a
//! compat shim restoring the `CompactTarget` method that 0.5.0 removed.

#[doc(inline)]
pub use units_v0_5::pow::*;

/// Restores `CompactTarget::to_hex`, removed from `bitcoin-units` in 0.5.0.
#[cfg(feature = "alloc")]
pub trait CompactTargetExt: crate::sealed::Sealed {
    /// Gets the hex representation of this [`CompactTarget`].
    #[deprecated(since = "1.0.0-rc.0", note = "use `format!(\"{var:x}\")` instead")]
    fn to_hex(self) -> alloc::string::String;
}

#[cfg(feature = "alloc")]
impl CompactTargetExt for units_v0_5::CompactTarget {
    fn to_hex(self) -> alloc::string::String { alloc::format!("{:x}", self) }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn compact_target_to_hex() {
        let compact_target = units_v0_5::CompactTarget::from_consensus(0x1d00_ffff);
        assert_eq!(compact_target.to_hex(), alloc::format!("{:x}", compact_target));
    }
}
