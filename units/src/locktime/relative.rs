// SPDX-License-Identifier: CC0-1.0

//! Provides [`NumberOfBlocks`] and [`NumberOf512Seconds`] types used by the
//! `rust-bitcoin` `relative::LockTime` type.

use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

#[deprecated(since = "TBD", note = "use `NumberOfBlocks` instead")]
#[doc(hidden)]
pub type Height = NumberOfBlocks;

/// A relative lock time lock-by-height value.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    pub const fn from_height(blocks: u16) -> Self { Self(blocks) }

    /// Express the [`NumberOfBlocks`] as a count of blocks.
    #[inline]
    #[must_use]
    pub const fn to_height(self) -> u16 { self.0 }

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

    /// Returns true if an output locked by height can be spent in the next block.
    ///
    /// # Errors
    ///
    /// If `chain_tip` as not _after_ `utxo_mined_at` i.e., if you get the args mixed up.
    pub fn is_satisfied_by(
        self,
        chain_tip: crate::BlockHeight,
        utxo_mined_at: crate::BlockHeight,
    ) -> Result<bool, InvalidHeightError> {
        match chain_tip.checked_sub(utxo_mined_at) {
            Some(diff) => {
                if diff.to_u32() == u32::MAX {
                    // Weird but ok none the less - protects against overflow below.
                    return Ok(true);
                }
                // +1 because the next block will have height 1 higher than `chain_tip`.
                Ok(u32::from(self.to_height()) <= diff.to_u32() + 1)
            }
            None => Err(InvalidHeightError { chain_tip, utxo_mined_at }),
        }
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

#[deprecated(since = "TBD", note = "use `NumberOf512Seconds` instead")]
#[doc(hidden)]
pub type Time = NumberOf512Seconds;

/// A relative lock time lock-by-time value.
///
/// For BIP 68 relative lock-by-time locks, time is measured in 512 second intervals.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NumberOf512Seconds(u16);

impl NumberOf512Seconds {
    /// Relative block time 0, can be included in any block.
    pub const ZERO: Self = NumberOf512Seconds(0);

    /// The minimum relative block time (0), can be included in any block.
    pub const MIN: Self = NumberOf512Seconds::ZERO;

    /// The maximum relative block time (33,554,432 seconds or approx 388 days).
    pub const MAX: Self = NumberOf512Seconds(u16::MAX);

    /// Constructs a new [`NumberOf512Seconds`] using time intervals where each interval is
    /// equivalent to 512 seconds.
    ///
    /// Encoding finer granularity of time for relative lock-times is not supported in Bitcoin.
    #[inline]
    pub const fn from_512_second_intervals(intervals: u16) -> Self { NumberOf512Seconds(intervals) }

    /// Express the [`NumberOf512Seconds`] as an integer number of 512-second intervals.
    #[inline]
    #[must_use]
    pub const fn to_512_second_intervals(self) -> u16 { self.0 }

    /// Constructs a new [`NumberOf512Seconds`] from seconds, converting the seconds into a 512
    /// second interval using truncating division.
    ///
    /// # Errors
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    #[inline]
    #[rustfmt::skip] // moves comments to unrelated code
    pub const fn from_seconds_floor(seconds: u32) -> Result<Self, TimeOverflowError> {
        let interval = seconds / 512;
        if interval <= u16::MAX as u32 { // infallible cast, needed by const code
            Ok(NumberOf512Seconds::from_512_second_intervals(interval as u16)) // Cast checked above, needed by const code.
        } else {
            Err(TimeOverflowError { seconds })
        }
    }

    /// Constructs a new [`NumberOf512Seconds`] from seconds, converting the seconds into a 512
    /// second interval using ceiling division.
    ///
    /// # Errors
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    #[inline]
    #[rustfmt::skip] // moves comments to unrelated code
    pub const fn from_seconds_ceil(seconds: u32) -> Result<Self, TimeOverflowError> {
        if seconds <= u16::MAX as u32 * 512 {
            let interval = (seconds + 511) / 512;
            Ok(NumberOf512Seconds::from_512_second_intervals(interval as u16)) // Cast checked above, needed by const code.
        } else {
            Err(TimeOverflowError { seconds })
        }
    }

    /// Represents the [`NumberOf512Seconds`] as an integer number of seconds.
    #[inline]
    pub const fn to_seconds(self) -> u32 {
        self.0 as u32 * 512 // u16->u32 cast ok, const context
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

    /// Returns true if an output locked by time can be spent in the next block.
    ///
    /// # Errors
    ///
    /// If `chain_tip` as not _after_ `utxo_mined_at` i.e., if you get the args mixed up.
    pub fn is_satisfied_by(
        self,
        chain_tip: crate::BlockMtp,
        utxo_mined_at: crate::BlockMtp,
    ) -> Result<bool, InvalidTimeError> {
        match chain_tip.checked_sub(utxo_mined_at) {
            Some(diff) => {
                // The locktime check in Core during block validation uses the MTP of the previous
                // block - which is `chain_tip` here.
                Ok(self.to_seconds() <= diff.to_u32())
            }
            None => Err(InvalidTimeError { chain_tip, utxo_mined_at }),
        }
    }
}

crate::impl_parse_str_from_int_infallible!(NumberOf512Seconds, u16, from_512_second_intervals);

impl fmt::Display for NumberOf512Seconds {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
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

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for NumberOfBlocks {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;

        match choice {
            0 => Ok(NumberOfBlocks::MIN),
            1 => Ok(NumberOfBlocks::MAX),
            _ => Ok(NumberOfBlocks::from_height(u16::arbitrary(u)?)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for NumberOf512Seconds {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;

        match choice {
            0 => Ok(NumberOf512Seconds::MIN),
            1 => Ok(NumberOf512Seconds::MAX),
            _ => Ok(NumberOf512Seconds::from_512_second_intervals(u16::arbitrary(u)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlockTime;

    const MAXIMUM_ENCODABLE_SECONDS: u32 = u16::MAX as u32 * 512;

    #[test]
    #[allow(deprecated_in_future)]
    fn sanity_check() {
        assert_eq!(NumberOfBlocks::MAX.to_consensus_u32(), u32::from(u16::MAX));
        assert_eq!(NumberOf512Seconds::from_512_second_intervals(100).value(), 100u16);
        assert_eq!(
            NumberOf512Seconds::from_512_second_intervals(100).to_consensus_u32(),
            4_194_404u32
        ); // 0x400064
        assert_eq!(NumberOf512Seconds::from_512_second_intervals(1).to_seconds(), 512);
    }

    #[test]
    fn from_512_second_intervals_roundtrip() {
        let intervals = 100_u16;
        let locktime = NumberOf512Seconds::from_512_second_intervals(intervals);
        assert_eq!(locktime.to_512_second_intervals(), intervals);
    }

    #[test]
    fn from_seconds_ceil_success() {
        let actual = NumberOf512Seconds::from_seconds_ceil(100).unwrap();
        let expected = NumberOf512Seconds(1_u16);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_seconds_ceil_with_maximum_encodable_seconds_success() {
        let actual = NumberOf512Seconds::from_seconds_ceil(MAXIMUM_ENCODABLE_SECONDS).unwrap();
        let expected = NumberOf512Seconds(u16::MAX);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_seconds_ceil_causes_time_overflow_error() {
        let result = NumberOf512Seconds::from_seconds_ceil(MAXIMUM_ENCODABLE_SECONDS + 1);
        assert!(result.is_err());
    }

    #[test]
    fn from_seconds_floor_success() {
        let actual = NumberOf512Seconds::from_seconds_floor(100).unwrap();
        let expected = NumberOf512Seconds(0_u16);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_seconds_floor_with_exact_interval() {
        let actual = NumberOf512Seconds::from_seconds_floor(512).unwrap();
        let expected = NumberOf512Seconds(1_u16);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_seconds_floor_with_maximum_encodable_seconds_success() {
        let actual =
            NumberOf512Seconds::from_seconds_floor(MAXIMUM_ENCODABLE_SECONDS + 511).unwrap();
        let expected = NumberOf512Seconds(u16::MAX);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_seconds_floor_causes_time_overflow_error() {
        let result = NumberOf512Seconds::from_seconds_floor(MAXIMUM_ENCODABLE_SECONDS + 512);
        assert!(result.is_err());
    }

    fn generate_timestamps(start: u32, step: u16) -> [BlockTime; 11] {
        let mut timestamps = [BlockTime::from_u32(0); 11];
        for (i, ts) in timestamps.iter_mut().enumerate() {
            *ts = BlockTime::from_u32(start.saturating_sub((step * i as u16).into()));
        }
        timestamps
    }

    #[test]
    fn test_time_chain_state() {
        use crate::BlockMtp;

        let timestamps: [BlockTime; 11] = generate_timestamps(1_600_000_000, 200);
        let utxo_timestamps: [BlockTime; 11] = generate_timestamps(1_599_000_000, 200);

        let timestamps2: [BlockTime; 11] = generate_timestamps(1_599_995_119, 200);
        let utxo_timestamps2: [BlockTime; 11] = generate_timestamps(1_599_990_000, 200);

        let timestamps3: [BlockTime; 11] = generate_timestamps(1_600_050_000, 200);
        let utxo_timestamps3: [BlockTime; 11] = generate_timestamps(1_599_990_000, 200);

        // Test case 1: Satisfaction (current_mtp >= utxo_mtp + required_seconds)
        // 10 intervals × 512 seconds = 5120 seconds
        let time_lock = NumberOf512Seconds::from_512_second_intervals(10);
        let chain_state1 = BlockMtp::new(timestamps);
        let utxo_state1 = BlockMtp::new(utxo_timestamps);
        assert!(time_lock.is_satisfied_by(chain_state1, utxo_state1).unwrap());

        // Test case 2: Not satisfied (current_mtp < utxo_mtp + required_seconds)
        let chain_state2 = BlockMtp::new(timestamps2);
        let utxo_state2 = BlockMtp::new(utxo_timestamps2);
        assert!(!time_lock.is_satisfied_by(chain_state2, utxo_state2).unwrap());

        // Test case 3: Test with a larger value (100 intervals = 51200 seconds)
        let larger_lock = NumberOf512Seconds::from_512_second_intervals(100);
        let chain_state3 = BlockMtp::new(timestamps3);
        let utxo_state3 = BlockMtp::new(utxo_timestamps3);
        assert!(larger_lock.is_satisfied_by(chain_state3, utxo_state3).unwrap());

        // Test case 4: Overflow handling - tests that is_satisfied_by handles overflow gracefully
        let max_time_lock = NumberOf512Seconds::MAX;
        let chain_state4 = BlockMtp::new(timestamps);
        let utxo_state4 = BlockMtp::new(utxo_timestamps);
        assert!(!max_time_lock.is_satisfied_by(chain_state4, utxo_state4).unwrap());
    }

    #[test]
    fn test_height_chain_state() {
        use crate::BlockHeight;

        let height_lock = NumberOfBlocks(10);

        // Test case 1: Satisfaction (current_height >= utxo_height + required)
        let chain_state1 = BlockHeight::from_u32(89);
        let utxo_state1 = BlockHeight::from_u32(80);
        assert!(height_lock.is_satisfied_by(chain_state1, utxo_state1).unwrap());

        // Test case 2: Not satisfied (current_height < utxo_height + required)
        let chain_state2 = BlockHeight::from_u32(88);
        let utxo_state2 = BlockHeight::from_u32(80);
        assert!(!height_lock.is_satisfied_by(chain_state2, utxo_state2).unwrap());

        // Test case 3: Overflow handling - tests that is_satisfied_by handles overflow gracefully
        let max_height_lock = NumberOfBlocks::MAX;
        let chain_state3 = BlockHeight::from_u32(1000);
        let utxo_state3 = BlockHeight::from_u32(80);
        assert!(!max_height_lock.is_satisfied_by(chain_state3, utxo_state3).unwrap());
    }
}
