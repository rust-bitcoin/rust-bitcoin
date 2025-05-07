// SPDX-License-Identifier: CC0-1.0

//! Provides [`Height`] and [`MtpInterval`] types used by the `rust-bitcoin` `relative::LockTime` type.

use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[deprecated(since = "TBD", note = "use `HeightIterval` instead")]
#[doc(hidden)]
pub type Height = NumberOfBlocks;

/// A relative lock time lock-by-blockheight value.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NumberOfBlocks(u16);

impl NumberOfBlocks {
    /// Relative block height 0, can be included in any block.
    pub const ZERO: Self = Self(0);

    /// The minimum relative block height (0), can be included in any block.
    pub const MIN: Self = Self::ZERO;

    /// The maximum relative block height.
    pub const MAX: Self = Self(u16::MAX);

    /// Constructs a new [`NumberOfBlocks`] using a count of blocks.
    #[inline]
    pub const fn from_interval(blocks: u16) -> Self { Self(blocks) }

    /// Express the [`NumberOfBlocks`] as a count of blocks.
    #[inline]
    #[must_use]
    pub const fn to_interval(self) -> u16 { self.0 }

    /// Returns the inner `u16` value.
    #[inline]
    #[must_use]
    #[deprecated(since = "TBD", note = "use `to_height` instead")]
    #[doc(hidden)]
    pub const fn value(self) -> u16 { self.0 }

    /// Returns the `u32` value used to encode this locktime in an nSequence field or
    /// argument to `OP_CHECKSEQUENCEVERIFY`.
    #[deprecated(
        since = "TBD",
        note = "use `LockTime::from` followed by `to_consensus_u32` instead"
    )]
    pub const fn to_consensus_u32(self) -> u32 {
        self.0 as u32 // cast safety: u32 is wider than u16 on all architectures
    }
}

impl From<u16> for NumberOfBlocks {
    #[inline]
    fn from(value: u16) -> Self { NumberOfBlocks(value) }
}

crate::impl_parse_str_from_int_infallible!(NumberOfBlocks, u16, from);

impl fmt::Display for NumberOfBlocks {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

#[deprecated(since = "TBD", note = "use `Mtp` instead")]
#[doc(hidden)]
pub type Time = MtpInterval;

/// A relative lock time lock-by-blocktime value.
///
/// For BIP 68 relative lock-by-blocktime locks, time is measured in 512 second intervals.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MtpInterval(u16);

impl MtpInterval {
    /// Relative block time 0, can be included in any block.
    pub const ZERO: Self = MtpInterval(0);

    /// The minimum relative block time (0), can be included in any block.
    pub const MIN: Self = MtpInterval::ZERO;

    /// The maximum relative block time (33,554,432 seconds or approx 388 days).
    pub const MAX: Self = MtpInterval(u16::MAX);

    /// Constructs a new [`MtpInterval`] using time intervals where each interval is equivalent to 512 seconds.
    ///
    /// Encoding finer granularity of time for relative lock-times is not supported in Bitcoin.
    #[inline]
    pub const fn from_512_second_intervals(intervals: u16) -> Self { MtpInterval(intervals) }

    /// Express the [`MtpInterval`] as an integer number of 512-second intervals.
    #[inline]
    #[must_use]
    pub const fn to_512_second_intervals(self) -> u16 { self.0 }

    /// Constructs a new [`MtpInterval`] from seconds, converting the seconds into 512 second interval with
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
            Ok(MtpInterval::from_512_second_intervals(interval as u16)) // Cast checked above, needed by const code.
        } else {
            Err(TimeOverflowError { seconds })
        }
    }

    /// Constructs a new [`MtpInterval`] from seconds, converting the seconds into 512 second intervals with
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
            Ok(MtpInterval::from_512_second_intervals(interval as u16)) // Cast checked above, needed by const code.
        } else {
            Err(TimeOverflowError { seconds })
        }
    }

    /// Returns the inner `u16` value.
    #[inline]
    #[must_use]
    #[deprecated(since = "TBD", note = "use `to_512_second_intervals` instead")]
    #[doc(hidden)]
    pub const fn value(self) -> u16 { self.0 }

    /// Returns the `u32` value used to encode this locktime in an nSequence field or
    /// argument to `OP_CHECKSEQUENCEVERIFY`.
    #[deprecated(
        since = "TBD",
        note = "use `LockTime::from` followed by `to_consensus_u32` instead"
    )]
    pub const fn to_consensus_u32(self) -> u32 {
        (1u32 << 22) | self.0 as u32 // cast safety: u32 is wider than u16 on all architectures
    }
}

crate::impl_parse_str_from_int_infallible!(MtpInterval, u16, from_512_second_intervals);

impl fmt::Display for MtpInterval {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

/// Error returned when the input time in seconds was too large to be encoded to a 16 bit 512 second interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeOverflowError {
    /// Time interval value in seconds that overflowed.
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
impl<'a> Arbitrary<'a> for NumberOfBlocks {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;

        match choice {
            0 => Ok(NumberOfBlocks::MIN),
            1 => Ok(NumberOfBlocks::MAX),
            _ => Ok(NumberOfBlocks::from_interval(u16::arbitrary(u)?)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for MtpInterval {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;

        match choice {
            0 => Ok(MtpInterval::MIN),
            1 => Ok(MtpInterval::MAX),
            _ => Ok(MtpInterval::from_512_second_intervals(u16::arbitrary(u)?)),
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
    #[allow(deprecated_in_future)]
    fn sanity_check() {
        assert_eq!(NumberOfBlocks::MAX.to_consensus_u32(), u32::from(u16::MAX));
        assert_eq!(MtpInterval::from_512_second_intervals(100).value(), 100u16);
        assert_eq!(MtpInterval::from_512_second_intervals(100).to_consensus_u32(), 4_194_404u32); // 0x400064
    }

    #[test]
    fn from_seconds_ceil_success() {
        let actual = MtpInterval::from_seconds_ceil(100).unwrap();
        let expected = MtpInterval(1_u16);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_seconds_ceil_with_maximum_encodable_seconds_success() {
        let actual = MtpInterval::from_seconds_ceil(MAXIMUM_ENCODABLE_SECONDS).unwrap();
        let expected = MtpInterval(u16::MAX);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_seconds_ceil_causes_time_overflow_error() {
        let result = MtpInterval::from_seconds_ceil(MAXIMUM_ENCODABLE_SECONDS + 1);
        assert!(result.is_err());
    }

    #[test]
    fn from_seconds_floor_success() {
        let actual = MtpInterval::from_seconds_floor(100).unwrap();
        let expected = MtpInterval(0_u16);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_seconds_floor_with_exact_interval() {
        let actual = MtpInterval::from_seconds_floor(512).unwrap();
        let expected = MtpInterval(1_u16);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_seconds_floor_with_maximum_encodable_seconds_success() {
        let actual = MtpInterval::from_seconds_floor(MAXIMUM_ENCODABLE_SECONDS + 511).unwrap();
        let expected = MtpInterval(u16::MAX);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_seconds_floor_causes_time_overflow_error() {
        let result = MtpInterval::from_seconds_floor(MAXIMUM_ENCODABLE_SECONDS + 512);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "serde")]
    pub fn encode_decode_height() {
        serde_round_trip!(NumberOfBlocks::ZERO);
        serde_round_trip!(NumberOfBlocks::MIN);
        serde_round_trip!(NumberOfBlocks::MAX);
    }

    #[test]
    #[cfg(feature = "serde")]
    pub fn encode_decode_time() {
        serde_round_trip!(MtpInterval::ZERO);
        serde_round_trip!(MtpInterval::MIN);
        serde_round_trip!(MtpInterval::MAX);
    }
}
