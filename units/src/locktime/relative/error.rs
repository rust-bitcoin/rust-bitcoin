// SPDX-License-Identifier: CC0-1.0

//! Error types for the relative locktime module.

use core::fmt;

/// Error returned when the input time in seconds was too large to be encoded to a 16 bit 512 second interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeOverflowError {
    /// Time interval value in seconds that overflowed.
    // Private because we maintain an invariant that the `seconds` value does actually overflow.
    pub(crate) seconds: u32,
}

impl fmt::Display for TimeOverflowError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} seconds is too large to be encoded to a 16 bit 512 second interval",
            self.seconds
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TimeOverflowError {}

/// Error returned when `NumberOfBlocks::is_satisfied_by` is incorrectly called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidHeightError {
    /// The `chain_tip` argument.
    pub(crate) chain_tip: crate::BlockHeight,
    /// The `utxo_mined_at` argument.
    pub(crate) utxo_mined_at: crate::BlockHeight,
}

impl fmt::Display for InvalidHeightError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "is_satisfied_by arguments invalid (probably the wrong way around) chain_tip: {} utxo_mined_at: {}", self.chain_tip, self.utxo_mined_at
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidHeightError {}

/// Error returned when `NumberOf512Seconds::is_satisfied_by` is incorrectly called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidTimeError {
    /// The `chain_tip` argument.
    pub(crate) chain_tip: crate::BlockMtp,
    /// The `utxo_mined_at` argument.
    pub(crate) utxo_mined_at: crate::BlockMtp,
}

impl fmt::Display for InvalidTimeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "is_satisfied_by arguments invalid (probably the wrong way around) chain_tip: {} utxo_mined_at: {}", self.chain_tip, self.utxo_mined_at
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidTimeError {}
