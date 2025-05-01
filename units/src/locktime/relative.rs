// SPDX-License-Identifier: CC0-1.0

//! Provides [`Height`] and [`MtpInterval`] types used by the `rust-bitcoin` `relative::LockTime` type.

use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::mtp_height::MtpAndHeight;

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

    /// Determines whether a relative‐height locktime has matured, taking into account
    /// both the chain tip and the height at which the UTXO was confirmed.
    ///
    /// # Parameters
    /// - `self` – The relative block‐height delay (`h`) required after confirmation.
    /// - `chain_tip` – The current chain state (contains the tip height).
    /// - `utxo_mined_at` – The chain state at the UTXO’s confirmation block (contains that height).
    ///
    /// # Returns
    /// - `true` if a UTXO locked by `self` can be spent in a block after `chain_tip`.
    /// - `false` if the UTXO is still locked at `chain_tip`.
    pub fn is_satisfied_by(self, chain_tip: MtpAndHeight, utxo_mined_at: MtpAndHeight) -> bool {
        // let chain_tip_height = BlockHeight::from(chain_tip);
        // let utxo_mined_at_height = BlockHeight::from(utxo_mined_at);
        match self.to_consensus_u32().checked_add(utxo_mined_at.to_height().to_u32()) {
            Some(target_height) => chain_tip.to_height().to_u32() >= target_height,
            None => false,
        }
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
    pub const fn value(self) -> u16 { self.0 }

    /// Returns the `u32` value used to encode this locktime in an nSequence field or
    /// argument to `OP_CHECKSEQUENCEVERIFY`.
    #[inline]
    pub const fn to_consensus_u32(self) -> u32 {
        (1u32 << 22) | self.0 as u32 // cast safety: u32 is wider than u16 on all architectures
    }

    /// Determines whether a relative‑time lock has matured, taking into account both
    /// the UTXO’s Median Time Past at confirmation and the required delay.
    ///
    /// # Parameters
    /// - `self` – The relative time delay (`t`) in 512‑second intervals.
    /// - `chain_tip` – The current chain state, providing the tip’s MTP.
    /// - `utxo_mined_at` – The chain state at the UTXO’s confirmation, providing its MTP.
    ///
    /// # Returns
    /// - `true` if the relative‐time lock has expired by the tip’s MTP
    /// - `false` if the lock has not yet expired by the tip’s MTP
    pub fn is_satisfied_by(self, chain_tip: MtpAndHeight, utxo_mined_at: MtpAndHeight) -> bool {
        match u32::from(self.value()).checked_mul(512) {
            Some(seconds) => match seconds.checked_add(utxo_mined_at.to_mtp().to_u32()) {
                Some(required_seconds) => chain_tip.to_mtp().to_u32() >= required_seconds,
                None => false,
            },
            None => false,
        }
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
    use crate::{BlockHeight, BlockTime};

    const MAXIMUM_ENCODABLE_SECONDS: u32 = u16::MAX as u32 * 512;

    #[test]
    fn sanity_check() {
        assert_eq!(Height::MAX.to_consensus_u32(), u32::from(u16::MAX));
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
        serde_round_trip!(Height::ZERO);
        serde_round_trip!(Height::MIN);
        serde_round_trip!(Height::MAX);
    }

    #[test]
    #[cfg(feature = "serde")]
    pub fn encode_decode_time() {
        serde_round_trip!(MtpInterval::ZERO);
        serde_round_trip!(MtpInterval::MIN);
        serde_round_trip!(MtpInterval::MAX);
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
        let timestamps: [BlockTime; 11] = generate_timestamps(1_600_000_000, 200);
        let utxo_timestamps: [BlockTime; 11] = generate_timestamps(1_599_000_000, 200);

        let timestamps2: [BlockTime; 11] = generate_timestamps(1_599_995_119, 200);
        let utxo_timestamps2: [BlockTime; 11] = generate_timestamps(1_599_990_000, 200);

        let timestamps3: [BlockTime; 11] = generate_timestamps(1_600_050_000, 200);
        let utxo_timestamps3: [BlockTime; 11] = generate_timestamps(1_599_990_000, 200);

        // Test case 1: Satisfaction (current_mtp >= utxo_mtp + required_seconds)
        // 10 intervals × 512 seconds = 5120 seconds
        let time_lock = MtpInterval::from_512_second_intervals(10);
        let chain_state1 = MtpAndHeight::new(BlockHeight::from_u32(100), timestamps);
        let utxo_state1 = MtpAndHeight::new(BlockHeight::from_u32(80), utxo_timestamps);
        assert!(time_lock.is_satisfied_by(chain_state1, utxo_state1));

        // Test case 2: Not satisfied (current_mtp < utxo_mtp + required_seconds)
        let chain_state2 = MtpAndHeight::new(BlockHeight::from_u32(100), timestamps2);
        let utxo_state2 = MtpAndHeight::new(BlockHeight::from_u32(80), utxo_timestamps2);
        assert!(!time_lock.is_satisfied_by(chain_state2, utxo_state2));

        // Test case 3: Test with a larger value (100 intervals = 51200 seconds)
        let larger_lock = MtpInterval::from_512_second_intervals(100);
        let chain_state3 = MtpAndHeight::new(BlockHeight::from_u32(100), timestamps3);
        let utxo_state3 = MtpAndHeight::new(BlockHeight::from_u32(80), utxo_timestamps3);
        assert!(larger_lock.is_satisfied_by(chain_state3, utxo_state3));

        // Test case 4: Overflow handling - tests that is_satisfied_by handles overflow gracefully
        let max_time_lock = MtpInterval::MAX;
        let chain_state4 = MtpAndHeight::new(BlockHeight::from_u32(100), timestamps);
        let utxo_state4 = MtpAndHeight::new(BlockHeight::from_u32(80), utxo_timestamps);
        assert!(!max_time_lock.is_satisfied_by(chain_state4, utxo_state4));
    }

    #[test]
    fn test_height_chain_state() {
        let timestamps: [BlockTime; 11] = generate_timestamps(1_600_000_000, 200);
        let utxo_timestamps: [BlockTime; 11] = generate_timestamps(1_599_000_000, 200);

        let height_lock = Height(10);

        // Test case 1: Satisfaction (current_height >= utxo_height + required)
        let chain_state1 = MtpAndHeight::new(BlockHeight::from_u32(100), timestamps);
        let utxo_state1 = MtpAndHeight::new(BlockHeight::from_u32(80), utxo_timestamps);
        assert!(height_lock.is_satisfied_by(chain_state1, utxo_state1));

        // Test case 2: Not satisfied (current_height < utxo_height + required)
        let chain_state2 = MtpAndHeight::new(BlockHeight::from_u32(89), timestamps);
        let utxo_state2 = MtpAndHeight::new(BlockHeight::from_u32(80), utxo_timestamps);
        assert!(!height_lock.is_satisfied_by(chain_state2, utxo_state2));

        // Test case 3: Overflow handling - tests that is_satisfied_by handles overflow gracefully
        let max_height_lock = Height::MAX;
        let chain_state3 = MtpAndHeight::new(BlockHeight::from_u32(1000), timestamps);
        let utxo_state3 = MtpAndHeight::new(BlockHeight::from_u32(80), utxo_timestamps);
        assert!(!max_height_lock.is_satisfied_by(chain_state3, utxo_state3));
    }
}
