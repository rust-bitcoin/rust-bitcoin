// SPDX-License-Identifier: CC0-1.0

//! Provides [`Height`] and [`Time`] types used by the `rust-bitcoin` `relative::LockTime` type.

use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
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
    pub const MAX: Self = Height(u16::MAX);

    /// Constructs a new [`Height`] using a count of blocks.
    #[inline]
    pub const fn from_height(blocks: u16) -> Self { Height(blocks) }

    /// Returns the inner `u16` value.
    #[inline]
    #[must_use]
    pub const fn value(self) -> u16 { self.0 }

    /// Returns the `u32` value used to encode this locktime in an nSequence field or
    /// argument to `OP_CHECKSEQUENCEVERIFY`.
    #[inline]
    pub const fn to_consensus_u32(self) -> u32 {
        self.0 as u32 // cast safety: u32 is wider than u16 on all architectures
    }
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
/// For BIP 68 relative lock-by-blocktime locks, time is measured in 512 second intervals.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Time(u16);

impl Time {
    /// Relative block time 0, can be included in any block.
    pub const ZERO: Self = Time(0);

    /// The minimum relative block time (0), can be included in any block.
    pub const MIN: Self = Time::ZERO;

    /// The maximum relative block time (33,554,432 seconds or approx 388 days).
    pub const MAX: Self = Time(u16::MAX);

    /// Constructs a new [`Time`] using time intervals where each interval is equivalent to 512 seconds.
    ///
    /// Encoding finer granularity of time for relative lock-times is not supported in Bitcoin.
    #[inline]
    pub const fn from_512_second_intervals(intervals: u16) -> Self { Time(intervals) }

    /// Constructs a new [`Time`] from seconds, converting the seconds into 512 second interval with
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
            Ok(Time::from_512_second_intervals(interval as u16)) // Cast checked above, needed by const code.
        } else {
            Err(TimeOverflowError { seconds })
        }
    }

    /// Constructs a new [`Time`] from seconds, converting the seconds into 512 second intervals with
    /// ceiling division.
    ///
    /// # Errors
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    #[inline]
    #[rustfmt::skip] // moves comments to unrelated code
    pub const fn from_seconds_ceil(seconds: u32) -> Result<Self, TimeOverflowError> {
        if seconds <= u16::MAX as u32 * 512 {
            let interval = (seconds + 511) / 512;
            Ok(Time::from_512_second_intervals(interval as u16)) // Cast checked above, needed by const code.
        } else {
            Err(TimeOverflowError { seconds })
        }
    }

    /// Returns the inner `u16` value.
    #[inline]
    #[must_use]
    pub const fn value(self) -> u16 { self.0 }

    /// Returns the `u32` value used to encode this locktime in an nSequence field or
    /// argument to `OP_CHECKSEQUENCEVERIFY`.
    #[inline]
    pub const fn to_consensus_u32(self) -> u32 {
        (1u32 << 22) | self.0 as u32 // cast safety: u32 is wider than u16 on all architectures
    }
}

crate::impl_parse_str_from_int_infallible!(Time, u16, from_512_second_intervals);

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

/// Error returned when the input time in seconds was too large to be encoded to a 16 bit 512 second interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeOverflowError {
    /// Time value in seconds that overflowed.
    // Private because we maintain an invariant that the `seconds` value does actually overflow.
    pub(crate) seconds: u32,
}

impl TimeOverflowError {
    /// Constructs a new `TimeOverflowError` using `seconds`.
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

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Height {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;

        match choice {
            0 => Ok(Height::MIN),
            1 => Ok(Height::MAX),
            _ => Ok(Height::from_height(u16::arbitrary(u)?)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Time {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;

        match choice {
            0 => Ok(Time::MIN),
            1 => Ok(Time::MAX),
            _ => Ok(Time::from_512_second_intervals(u16::arbitrary(u)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "serde")]
    use internals::serde_round_trip;

    use super::*;

    const MAXIMUM_ENCODABLE_SECONDS: u32 = u16::MAX as u32 * 512;

    #[test]
    fn sanity_check() {
        assert_eq!(Height::MAX.to_consensus_u32(), u32::from(u16::MAX));
        assert_eq!(Time::from_512_second_intervals(100).value(), 100u16);
        assert_eq!(Time::from_512_second_intervals(100).to_consensus_u32(), 4_194_404u32); // 0x400064
    }

    #[test]
    fn from_seconds_ceil_success() {
        let actual = Time::from_seconds_ceil(100).unwrap();
        let expected = Time(1_u16);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_seconds_ceil_with_maximum_encodable_seconds_success() {
        let actual = Time::from_seconds_ceil(MAXIMUM_ENCODABLE_SECONDS).unwrap();
        let expected = Time(u16::MAX);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_seconds_ceil_causes_time_overflow_error() {
        let result = Time::from_seconds_ceil(MAXIMUM_ENCODABLE_SECONDS + 1);
        assert!(result.is_err());
    }

    #[test]
    fn from_seconds_floor_success() {
        let actual = Time::from_seconds_floor(100).unwrap();
        let expected = Time(0_u16);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_seconds_floor_with_exact_interval() {
        let actual = Time::from_seconds_floor(512).unwrap();
        let expected = Time(1_u16);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_seconds_floor_with_maximum_encodable_seconds_success() {
        let actual = Time::from_seconds_floor(MAXIMUM_ENCODABLE_SECONDS + 511).unwrap();
        let expected = Time(u16::MAX);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_seconds_floor_causes_time_overflow_error() {
        let result = Time::from_seconds_floor(MAXIMUM_ENCODABLE_SECONDS + 512);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "serde")]
    pub fn encode_decode_height() {
        serde_round_trip!(Height::ZERO);
        serde_round_trip!(Height::MIN);
        serde_round_trip!(Height::MAX);
    }

    #[test]
    #[cfg(feature = "serde")]
    pub fn encode_decode_time() {
        serde_round_trip!(Time::ZERO);
        serde_round_trip!(Time::MIN);
        serde_round_trip!(Time::MAX);
    }
}
