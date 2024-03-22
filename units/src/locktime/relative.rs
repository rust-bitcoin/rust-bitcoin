// SPDX-License-Identifier: CC0-1.0

//! Provides type `Height` and `Time` types used by the `rust-bitcoin` `relative::LockTime` type.

use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A relative lock time lock-by-blockheight value.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Height(u16);

impl Height {
    /// Relative block height 0, can be included in any block.
    pub const ZERO: Self = Height(0);

    /// The minimum relative block height (0), can be included in any block.
    pub const MIN: Self = Self::ZERO;

    /// The maximum relative block height.
    pub const MAX: Self = Height(u16::max_value());

    /// Create a [`Height`] using a count of blocks.
    #[inline]
    pub const fn from_height(blocks: u16) -> Self { Height(blocks) }

    /// Returns the inner `u16` value.
    #[inline]
    pub fn value(self) -> u16 { self.0 }

    /// Returns the `u32` value used to encode this locktime in an nSequence field or
    /// argument to `OP_CHECKSEQUENCEVERIFY`.
    #[inline]
    pub fn to_consensus_u32(&self) -> u32 { self.0.into() }
}

impl From<u16> for Height {
    #[inline]
    fn from(value: u16) -> Self { Height(value) }
}

crate::impl_parse_str_from_int_infallible!(Height, u16, from);

impl fmt::Display for Height {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

/// A relative lock time lock-by-blocktime value.
///
/// For BIP 68 relative lock-by-blocktime locks, time is measure in 512 second intervals.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Time(u16);

impl Time {
    /// Relative block time 0, can be included in any block.
    pub const ZERO: Self = Time(0);

    /// The minimum relative block time (0), can be included in any block.
    pub const MIN: Self = Time::ZERO;

    /// The maximum relative block time (33,554,432 seconds or approx 388 days).
    pub const MAX: Self = Time(u16::max_value());

    /// Create a [`Time`] using time intervals where each interval is equivalent to 512 seconds.
    ///
    /// Encoding finer granularity of time for relative lock-times is not supported in Bitcoin.
    #[inline]
    pub const fn from_512_second_intervals(intervals: u16) -> Self { Time(intervals) }

    /// Create a [`Time`] from seconds, converting the seconds into 512 second interval with
    /// truncating division.
    ///
    /// # Errors
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    #[inline]
    #[rustfmt::skip] // moves comments to unrelated code
    pub const fn from_seconds_floor(seconds: u32) -> Result<Self, TimeOverflowError> {
        let interval = seconds / 512;
        if interval <= u16::MAX as u32 { // infallible cast, needed by const code
            Ok(Time::from_512_second_intervals(interval as u16)) // cast checked above, needed by const code
        } else {
            Err(TimeOverflowError { seconds })
        }
    }

    /// Create a [`Time`] from seconds, converting the seconds into 512 second interval with ceiling
    /// division.
    ///
    /// # Errors
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    #[inline]
    #[rustfmt::skip] // moves comments to unrelated code
    pub const fn from_seconds_ceil(seconds: u32) -> Result<Self, TimeOverflowError> {
        let interval = (seconds + 511) / 512;
        if interval <= u16::MAX as u32 { // infallible cast, needed by const code
            Ok(Time::from_512_second_intervals(interval as u16)) // cast checked above, needed by const code
        } else {
            Err(TimeOverflowError { seconds })
        }
    }

    /// Returns the inner `u16` value.
    #[inline]
    pub fn value(self) -> u16 { self.0 }

    /// Returns the `u32` value used to encode this locktime in an nSequence field or
    /// argument to `OP_CHECKSEQUENCEVERIFY`.
    #[inline]
    pub fn to_consensus_u32(&self) -> u32 { (1u32 << 22) | u32::from(self.0) }
}

crate::impl_parse_str_from_int_infallible!(Time, u16, from_512_second_intervals);

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

/// Input time in seconds was too large to be encoded to a 16 bit 512 second interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeOverflowError {
    /// Time value in seconds that overflowed.
    // Private because we maintain an invariant that the `seconds` value does actually overflow.
    pub(crate) seconds: u32,
}

impl TimeOverflowError {
    /// Creates a new `TimeOverflowError` using `seconds`.
    ///
    /// # Panics
    ///
    /// If `seconds` would not actually overflow a `u16`.
    pub fn new(seconds: u32) -> Self {
        assert!(u16::try_from((seconds + 511) / 512).is_err());
        Self { seconds }
    }
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
