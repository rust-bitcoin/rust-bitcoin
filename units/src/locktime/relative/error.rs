// SPDX-License-Identifier: CC0-1.0

//! Error types for the relative locktime module.

use core::fmt;

use internals::write_err;

use super::{NumberOf512Seconds, NumberOfBlocks};

/// Error returned when a sequence number is parsed as a lock time, but its
/// "disable" flag is set.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DisabledLockTimeError(pub(super) u32);

impl DisabledLockTimeError {
    /// Accessor for the `u32` whose "disable" flag was set, preventing
    /// it from being parsed as a relative locktime.
    #[inline]
    pub fn disabled_locktime_value(&self) -> u32 { self.0 }
}

impl fmt::Display for DisabledLockTimeError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "lock time 0x{:08x} has disable flag set", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DisabledLockTimeError {}

/// Error returned when attempting to satisfy lock fails.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IsSatisfiedByError {
    /// Error when attempting to satisfy lock by height.
    Blocks(InvalidHeightError),
    /// Error when attempting to satisfy lock by time.
    Time(InvalidTimeError),
}

impl fmt::Display for IsSatisfiedByError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Blocks(ref e) => write_err!(f, "blocks"; e),
            Self::Time(ref e) => write_err!(f, "time"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IsSatisfiedByError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::Blocks(ref e) => Some(e),
            Self::Time(ref e) => Some(e),
        }
    }
}

/// Error returned when `is_satisfied_by_height` fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsSatisfiedByHeightError {
    /// Satisfaction of the lock height value failed.
    Satisfaction(InvalidHeightError),
    /// Tried to satisfy a lock-by-height locktime using seconds.
    // TODO: Hide inner value in a new struct error type.
    Incompatible(NumberOf512Seconds),
}

impl fmt::Display for IsSatisfiedByHeightError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Satisfaction(ref e) => write_err!(f, "satisfaction"; e),
            Self::Incompatible(time) =>
                write!(f, "tried to satisfy a lock-by-height locktime using seconds {}", time),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IsSatisfiedByHeightError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::Satisfaction(ref e) => Some(e),
            Self::Incompatible(_) => None,
        }
    }
}

/// Error returned when `is_satisfied_by_time` fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsSatisfiedByTimeError {
    /// Satisfaction of the lock time value failed.
    Satisfaction(InvalidTimeError),
    /// Tried to satisfy a lock-by-time locktime using number of blocks.
    // TODO: Hide inner value in a new struct error type.
    Incompatible(NumberOfBlocks),
}

impl fmt::Display for IsSatisfiedByTimeError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Satisfaction(ref e) => write_err!(f, "satisfaction"; e),
            Self::Incompatible(blocks) =>
                write!(f, "tried to satisfy a lock-by-time locktime using blocks {}", blocks),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IsSatisfiedByTimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::Satisfaction(ref e) => Some(e),
            Self::Incompatible(_) => None,
        }
    }
}

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
