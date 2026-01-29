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

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::string::ToString;
    #[cfg(feature = "std")]
    use std::error::Error;

    #[cfg(feature = "alloc")]
    use crate::{
        BlockHeight, BlockMtp, BlockMtpInterval, Sequence,
        locktime::relative::{LockTime, NumberOf512Seconds, NumberOfBlocks}
    };

    #[test]
    #[cfg(feature = "alloc")]
    fn error_display_is_non_empty() {
        // DisabledLockTimeError - parse disabled lock time
        let disabled = Sequence::MAX; // Sequence with disable flag set
        let e = LockTime::from_sequence(disabled).unwrap_err();
        assert!(!e.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(e.source().is_none());

        // TimeOverflowError - time too large for relative locktime
        let too_big = BlockMtpInterval::MAX;
        let e = too_big.to_relative_mtp_interval_floor().unwrap_err();
        assert!(!e.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(e.source().is_none());

        // InvalidHeightError - is_satisfied_by with invalid args
        let blocks = NumberOfBlocks::from(10u16);
        let e = blocks.is_satisfied_by(BlockHeight::from_u32(5), BlockHeight::from_u32(10)).unwrap_err();
        assert!(!e.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(e.source().is_none());

        // InvalidTimeError - is_satisfied_by with invalid args
        let time = NumberOf512Seconds::from_512_second_intervals(10);
        let e = time.is_satisfied_by(BlockMtp::from_u32(5), BlockMtp::from_u32(10)).unwrap_err();
        assert!(!e.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(e.source().is_none());

        // IsSatisfiedBy*Error
        let time_lock = LockTime::from_512_second_intervals(10);
        let height_lock = LockTime::from_height(10);

        // IsSatisfiedByError - wraps InvalidHeightError or InvalidTimeError
        // Error when chain_tip < utxo_mined_at (args wrong way around)
        // blocks type
        let e = height_lock
            .is_satisfied_by(
                BlockHeight::from_u32(5),
                BlockMtp::ZERO,
                BlockHeight::from_u32(10),
                BlockMtp::ZERO,
            )
            .unwrap_err();
        assert!(!e.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(e.source().is_some());
        // time type
        let e = time_lock
            .is_satisfied_by(
                BlockHeight::ZERO,
                BlockMtp::from_u32(5),
                BlockHeight::ZERO,
                BlockMtp::from_u32(10),
            )
            .unwrap_err();
        assert!(!e.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(e.source().is_some());

        // IsSatisfiedByHeightError
        // Incompatible type
        let e = time_lock.is_satisfied_by_height(
            BlockHeight::from_u32(5),
            BlockHeight::from_u32(10)
        ).unwrap_err();
        assert!(!e.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(e.source().is_none());
        // Satisfaction type
        let e = height_lock.is_satisfied_by_height(
            BlockHeight::from_u32(5),
            BlockHeight::from_u32(10)
        ).unwrap_err();
        assert!(!e.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(e.source().is_some());

        // IsSatisfiedByTimeError
        // Incompatible type
        let e = height_lock.is_satisfied_by_time(
            BlockMtp::from_u32(5),
            BlockMtp::from_u32(10)
        ).unwrap_err();
        assert!(!e.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(e.source().is_none());
        // Satisfaction type
        let e = time_lock.is_satisfied_by_time(
            BlockMtp::from_u32(5),
            BlockMtp::from_u32(10)
        ).unwrap_err();
        assert!(!e.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(e.source().is_some());
    }
}
