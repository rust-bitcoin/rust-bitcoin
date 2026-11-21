// SPDX-License-Identifier: CC0-1.0

//! Bitcoin transaction input sequence number.
//!
//! Forwarded from `bitcoin-units` 0.5.0 (see the crate-level docs on the semver trick), plus a
//! compat shim restoring the `Sequence` items that 0.5.0 removed.

#[doc(inline)]
pub use units_v0_5::sequence::*;

/// Restores `Sequence` items that `bitcoin-units` removed in 0.5.0.
pub trait SequenceExt: Sized + crate::sealed::Sealed {
    /// The sequence number that enables replace-by-fee and absolute lock time but
    /// disables relative lock time.
    #[deprecated(since = "1.0.0-rc.0", note = "use `ENABLE_LOCKTIME_AND_RBF` instead")]
    const ENABLE_RBF_NO_LOCKTIME: Self;

    /// Gets the hex representation of this [`Sequence`].
    #[cfg(feature = "alloc")]
    #[deprecated(since = "1.0.0-rc.0", note = "use `format!(\"{var:x}\")` instead")]
    fn to_hex(self) -> alloc::string::String;
}

impl SequenceExt for units_v0_5::Sequence {
    const ENABLE_RBF_NO_LOCKTIME: Self = Self::ENABLE_LOCKTIME_AND_RBF;

    #[cfg(feature = "alloc")]
    fn to_hex(self) -> alloc::string::String { alloc::format!("{:x}", self) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn enable_rbf_no_locktime() {
        let seq = units_v0_5::Sequence::ENABLE_RBF_NO_LOCKTIME;
        assert_eq!(seq, units_v0_5::Sequence::ENABLE_LOCKTIME_AND_RBF);
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[allow(deprecated)]
    fn sequence_to_hex() {
        let seq = units_v0_5::Sequence::from_consensus(0xFFFF_FFFD);
        assert_eq!(seq.to_hex(), alloc::format!("{:x}", seq));
    }
}
