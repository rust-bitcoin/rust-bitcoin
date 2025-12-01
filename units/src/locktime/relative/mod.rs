// SPDX-License-Identifier: CC0-1.0

//! Provides type [`LockTime`] that implements the logic around `nSequence`/`OP_CHECKSEQUENCEVERIFY`.
//!
//! There are two types of lock time: lock-by-height and lock-by-time, distinguished by whether bit
//! 22 of the `u32` consensus value is set. To support these we provide the [`NumberOfBlocks`] and
//! [`NumberOf512Seconds`] types.

pub mod error;

use core::{convert, fmt};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use internals::const_casts;

#[cfg(doc)]
use crate::relative;
use crate::{parse_int, BlockHeight, BlockMtp, Sequence};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(no_inline)]
pub use self::error::{
    DisabledLockTimeError, InvalidHeightError, InvalidTimeError, IsSatisfiedByError,
    IsSatisfiedByHeightError, IsSatisfiedByTimeError, TimeOverflowError,
};

/// A relative lock time value, representing either a block height or time (512 second intervals).
///
/// Used for sequence numbers (`nSequence` in Bitcoin Core and `TxIn::sequence`
/// in `rust-bitcoin`) and also for the argument to opcode `OP_CHECKSEQUENCEVERIFY`.
///
/// # Note on ordering
///
/// Locktimes may be height- or time-based, and these metrics are incommensurate; there is no total
/// ordering on locktimes. In order to compare locktimes, instead of using `<` or `>` we provide the
/// [`LockTime::is_satisfied_by`] API.
///
/// # Relevant BIPs
///
/// * [BIP-0068 Relative lock-time using consensus-enforced sequence numbers](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki)
/// * [BIP-0112 CHECKSEQUENCEVERIFY](https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockTime {
    /// A block height lock time value.
    Blocks(NumberOfBlocks),
    /// A 512 second time interval value.
    Time(NumberOf512Seconds),
}

impl LockTime {
    /// A relative locktime of 0 is always valid, and is assumed valid for inputs that
    /// are not yet confirmed.
    pub const ZERO: Self = Self::Blocks(NumberOfBlocks::ZERO);

    /// The number of bytes that the locktime contributes to the size of a transaction.
    pub const SIZE: usize = 4; // Serialized length of a u32.

    /// Constructs a new `LockTime` from an `nSequence` value or the argument to `OP_CHECKSEQUENCEVERIFY`.
    ///
    /// This method will **not** round-trip with [`Self::to_consensus_u32`], because relative
    /// locktimes only use some bits of the underlying `u32` value and discard the rest. If
    /// you want to preserve the full value, you should use the [`Sequence`] type instead.
    ///
    /// # Errors
    ///
    /// If `n`, interpreted as a [`Sequence`] number does not encode a relative lock time.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin_units::relative;
    ///
    /// // Values with bit 22 set to 0 will be interpreted as height-based lock times.
    /// let height: u32 = 144; // 144 blocks, approx 24h.
    /// let lock_time = relative::LockTime::from_consensus(height)?;
    /// assert!(lock_time.is_block_height());
    /// assert_eq!(lock_time.to_consensus_u32(), height);
    ///
    /// // Values with bit 22 set to 1 will be interpreted as time-based lock times.
    /// let time: u32 = 168 | (1 << 22) ; // Bit 22 is 1 with time approx 24h.
    /// let lock_time = relative::LockTime::from_consensus(time)?;
    /// assert!(lock_time.is_block_time());
    /// assert_eq!(lock_time.to_consensus_u32(), time);
    ///
    /// # Ok::<_, relative::error::DisabledLockTimeError>(())
    /// ```
    #[inline]
    pub fn from_consensus(n: u32) -> Result<Self, DisabledLockTimeError> {
        let sequence = crate::Sequence::from_consensus(n);
        sequence.to_relative_lock_time().ok_or(DisabledLockTimeError(n))
    }

    /// Returns the `u32` value used to encode this locktime in an `nSequence` field or
    /// argument to `OP_CHECKSEQUENCEVERIFY`.
    ///
    /// # Warning
    ///
    /// Locktimes are not ordered by the natural ordering on `u32`. If you want to
    /// compare locktimes, use [`Self::is_implied_by`] or similar methods.
    #[inline]
    pub fn to_consensus_u32(self) -> u32 {
        match self {
            Self::Blocks(ref h) => u32::from(h.to_height()),
            Self::Time(ref t) => Sequence::LOCK_TYPE_MASK | u32::from(t.to_512_second_intervals()),
        }
    }

    /// Constructs a new `LockTime` from the sequence number of a Bitcoin input.
    ///
    /// This method will **not** round-trip with [`Self::to_sequence`]. See the
    /// docs for [`Self::from_consensus`] for more information.
    ///
    /// # Errors
    ///
    /// If `n` does not encode a relative lock time.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin_units::{Sequence, relative};
    ///
    /// // Interpret a sequence number from a Bitcoin transaction input as a relative lock time
    /// let sequence_number = Sequence::from_consensus(144); // 144 blocks, approx 24h.
    /// let lock_time = relative::LockTime::from_sequence(sequence_number)?;
    /// assert!(lock_time.is_block_height());
    ///
    /// # Ok::<_, relative::error::DisabledLockTimeError>(())
    /// ```
    #[inline]
    pub fn from_sequence(n: Sequence) -> Result<Self, DisabledLockTimeError> {
        Self::from_consensus(n.to_consensus_u32())
    }

    /// Encodes the locktime as a sequence number.
    #[inline]
    pub fn to_sequence(self) -> Sequence { Sequence::from_consensus(self.to_consensus_u32()) }

    /// Constructs a new `LockTime` from `n`, expecting `n` to be a 16-bit count of blocks.
    #[inline]
    pub const fn from_height(n: u16) -> Self { Self::Blocks(NumberOfBlocks::from_height(n)) }

    /// Constructs a new `LockTime` from `n`, expecting `n` to be a count of 512-second intervals.
    ///
    /// This function is a little awkward to use, and users may wish to instead use
    /// [`Self::from_seconds_floor`] or [`Self::from_seconds_ceil`].
    #[inline]
    pub const fn from_512_second_intervals(intervals: u16) -> Self {
        Self::Time(NumberOf512Seconds::from_512_second_intervals(intervals))
    }

    /// Constructs a new [`LockTime`] from seconds, converting the seconds into 512 second interval
    /// with truncating division.
    ///
    /// # Errors
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    #[inline]
    pub const fn from_seconds_floor(seconds: u32) -> Result<Self, TimeOverflowError> {
        match NumberOf512Seconds::from_seconds_floor(seconds) {
            Ok(time) => Ok(Self::Time(time)),
            Err(e) => Err(e),
        }
    }

    /// Constructs a new [`LockTime`] from seconds, converting the seconds into 512 second interval
    /// with ceiling division.
    ///
    /// # Errors
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    #[inline]
    pub const fn from_seconds_ceil(seconds: u32) -> Result<Self, TimeOverflowError> {
        match NumberOf512Seconds::from_seconds_ceil(seconds) {
            Ok(time) => Ok(Self::Time(time)),
            Err(e) => Err(e),
        }
    }

    /// Returns true if both lock times use the same unit i.e., both height based or both time based.
    #[inline]
    pub const fn is_same_unit(self, other: Self) -> bool {
        matches!((self, other), (Self::Blocks(_), Self::Blocks(_)) | (Self::Time(_), Self::Time(_)))
    }

    /// Returns true if this lock time value is in units of block height.
    #[inline]
    pub const fn is_block_height(self) -> bool { matches!(self, Self::Blocks(_)) }

    /// Returns true if this lock time value is in units of time.
    #[inline]
    pub const fn is_block_time(self) -> bool { !self.is_block_height() }

    /// Returns true if this [`relative::LockTime`] is satisfied by the given chain state.
    ///
    /// If this function returns true then an output with this locktime can be spent in the next
    /// block.
    ///
    /// # Errors
    ///
    /// If `chain_tip` as not _after_ `utxo_mined_at` i.e., if you get the args mixed up.
    pub fn is_satisfied_by(
        self,
        chain_tip_height: BlockHeight,
        chain_tip_mtp: BlockMtp,
        utxo_mined_at_height: BlockHeight,
        utxo_mined_at_mtp: BlockMtp,
    ) -> Result<bool, IsSatisfiedByError> {
        match self {
            Self::Blocks(blocks) => blocks
                .is_satisfied_by(chain_tip_height, utxo_mined_at_height)
                .map_err(IsSatisfiedByError::Blocks),
            Self::Time(time) => time
                .is_satisfied_by(chain_tip_mtp, utxo_mined_at_mtp)
                .map_err(IsSatisfiedByError::Time),
        }
    }

    /// Returns true if an output with this locktime can be spent in the next block.
    ///
    /// If this function returns true then an output with this locktime can be spent in the next
    /// block.
    ///
    /// # Errors
    ///
    /// Returns an error if this lock is not lock-by-height.
    #[inline]
    pub fn is_satisfied_by_height(
        self,
        chain_tip: BlockHeight,
        utxo_mined_at: BlockHeight,
    ) -> Result<bool, IsSatisfiedByHeightError> {
        match self {
            Self::Blocks(blocks) => blocks
                .is_satisfied_by(chain_tip, utxo_mined_at)
                .map_err(IsSatisfiedByHeightError::Satisfaction),
            Self::Time(time) => Err(IsSatisfiedByHeightError::Incompatible(time)),
        }
    }

    /// Returns true if an output with this locktime can be spent in the next block.
    ///
    /// If this function returns true then an output with this locktime can be spent in the next
    /// block.
    ///
    /// # Errors
    ///
    /// Returns an error if this lock is not lock-by-time.
    #[inline]
    pub fn is_satisfied_by_time(
        self,
        chain_tip: BlockMtp,
        utxo_mined_at: BlockMtp,
    ) -> Result<bool, IsSatisfiedByTimeError> {
        match self {
            Self::Time(time) => time
                .is_satisfied_by(chain_tip, utxo_mined_at)
                .map_err(IsSatisfiedByTimeError::Satisfaction),
            Self::Blocks(blocks) => Err(IsSatisfiedByTimeError::Incompatible(blocks)),
        }
    }

    /// Returns true if satisfaction of `other` lock time implies satisfaction of this
    /// [`relative::LockTime`].
    ///
    /// A lock time can only be satisfied by n blocks being mined or n seconds passing. If you have
    /// two lock times (same unit) then the larger lock time being satisfied implies (in a
    /// mathematical sense) the smaller one being satisfied.
    ///
    /// This function is useful when checking sequence values against a lock, first one checks the
    /// sequence represents a relative lock time by converting to `LockTime` then use this function
    /// to see if satisfaction of the newly created lock time would imply satisfaction of `self`.
    ///
    /// Can also be used to remove the smaller value of two `OP_CHECKSEQUENCEVERIFY` operations
    /// within one branch of the script.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin_units::Sequence;
    ///
    /// # let required_height = 100;       // 100 blocks.
    /// # let lock = Sequence::from_height(required_height).to_relative_lock_time().expect("valid height");
    /// # let test_sequence = Sequence::from_height(required_height + 10);
    ///
    /// let satisfied = match test_sequence.to_relative_lock_time() {
    ///     None => false, // Handle non-lock-time case.
    ///     Some(test_lock) => lock.is_implied_by(test_lock),
    /// };
    /// assert!(satisfied);
    /// ```
    #[inline]
    pub fn is_implied_by(self, other: Self) -> bool {
        match (self, other) {
            (Self::Blocks(this), Self::Blocks(other)) => this <= other,
            (Self::Time(this), Self::Time(other)) => this <= other,
            _ => false, // Not the same units.
        }
    }

    /// Returns true if satisfaction of the sequence number implies satisfaction of this lock time.
    ///
    /// When deciding whether an instance of `<n> CHECKSEQUENCEVERIFY` will pass, this
    /// method can be used by parsing `n` as a [`LockTime`] and calling this method
    /// with the sequence number of the input which spends the script.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::{Sequence, relative};
    ///
    /// let sequence = Sequence::from_consensus(1 << 22 | 168); // Bit 22 is 1 with time approx 24h.
    /// let lock_time = relative::LockTime::from_sequence(sequence)?;
    /// let input_sequence = Sequence::from_consensus(1 << 22 | 336); // Approx 48h.
    /// assert!(lock_time.is_block_time());
    ///
    /// assert!(lock_time.is_implied_by_sequence(input_sequence));
    ///
    /// # Ok::<_, relative::error::DisabledLockTimeError>(())
    /// ```
    #[inline]
    pub fn is_implied_by_sequence(self, other: Sequence) -> bool {
        if let Ok(other) = Self::from_sequence(other) {
            self.is_implied_by(other)
        } else {
            false
        }
    }
}

impl From<NumberOfBlocks> for LockTime {
    #[inline]
    fn from(h: NumberOfBlocks) -> Self { Self::Blocks(h) }
}

impl From<NumberOf512Seconds> for LockTime {
    #[inline]
    fn from(t: NumberOf512Seconds) -> Self { Self::Time(t) }
}

impl fmt::Display for LockTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            match *self {
                Self::Blocks(ref h) => write!(f, "block-height {}", h),
                Self::Time(ref t) => write!(f, "block-time {} (512 second intervals)", t),
            }
        } else {
            match *self {
                Self::Blocks(ref h) => fmt::Display::fmt(h, f),
                Self::Time(ref t) => fmt::Display::fmt(t, f),
            }
        }
    }
}

impl convert::TryFrom<Sequence> for LockTime {
    type Error = DisabledLockTimeError;
    #[inline]
    fn try_from(seq: Sequence) -> Result<Self, DisabledLockTimeError> { Self::from_sequence(seq) }
}

impl From<LockTime> for Sequence {
    #[inline]
    fn from(lt: LockTime) -> Self { lt.to_sequence() }
}

#[cfg(feature = "serde")]
impl serde::Serialize for LockTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_consensus_u32().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for LockTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u32::deserialize(deserializer)
            .and_then(|n| Self::from_consensus(n).map_err(serde::de::Error::custom))
    }
}

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
    fn from(value: u16) -> Self { Self(value) }
}

parse_int::impl_parse_str_from_int_infallible!(NumberOfBlocks, u16, from);

impl fmt::Display for NumberOfBlocks {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

#[deprecated(since = "TBD", note = "use `NumberOf512Seconds` instead")]
#[doc(hidden)]
pub type Time = NumberOf512Seconds;

/// A relative lock time lock-by-time value.
///
/// For BIP-0068 relative lock-by-time locks, time is measured in 512 second intervals.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NumberOf512Seconds(u16);

impl NumberOf512Seconds {
    /// Relative block time 0, can be included in any block.
    pub const ZERO: Self = Self(0);

    /// The minimum relative block time (0), can be included in any block.
    pub const MIN: Self = Self::ZERO;

    /// The maximum relative block time (33,554,432 seconds or approx 388 days).
    pub const MAX: Self = Self(u16::MAX);

    /// Constructs a new [`NumberOf512Seconds`] using time intervals where each interval is
    /// equivalent to 512 seconds.
    ///
    /// Encoding finer granularity of time for relative lock-times is not supported in Bitcoin.
    #[inline]
    pub const fn from_512_second_intervals(intervals: u16) -> Self { Self(intervals) }

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
            Ok(Self::from_512_second_intervals(interval as u16)) // Cast checked above, needed by const code.
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
            let interval = seconds.div_ceil(512);
            Ok(Self::from_512_second_intervals(interval as u16)) // Cast checked above, needed by const code.
        } else {
            Err(TimeOverflowError { seconds })
        }
    }

    /// Represents the [`NumberOf512Seconds`] as an integer number of seconds.
    #[inline]
    pub const fn to_seconds(self) -> u32 { const_casts::u16_to_u32(self.0) * 512 }

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

parse_int::impl_parse_str_from_int_infallible!(NumberOf512Seconds, u16, from_512_second_intervals);

impl fmt::Display for NumberOf512Seconds {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for NumberOfBlocks {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;

        match choice {
            0 => Ok(Self::MIN),
            1 => Ok(Self::MAX),
            _ => Ok(Self::from_height(u16::arbitrary(u)?)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for NumberOf512Seconds {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;

        match choice {
            0 => Ok(Self::MIN),
            1 => Ok(Self::MAX),
            _ => Ok(Self::from_512_second_intervals(u16::arbitrary(u)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::format;

    use super::*;
    use crate::{BlockHeight, BlockTime};

    const MAXIMUM_ENCODABLE_SECONDS: u32 = u16::MAX as u32 * 512;

    #[test]
    #[cfg(feature = "alloc")]
    fn display_and_alternate() {
        let lock_by_height = LockTime::from_height(10);
        let lock_by_time = LockTime::from_512_second_intervals(70);

        assert_eq!(format!("{}", lock_by_height), "10");
        assert_eq!(format!("{:#}", lock_by_height), "block-height 10");
        assert!(!format!("{:?}", lock_by_height).is_empty());

        assert_eq!(format!("{}", lock_by_time), "70");
        assert_eq!(format!("{:#}", lock_by_time), "block-time 70 (512 second intervals)");
        assert!(!format!("{:?}", lock_by_time).is_empty());
    }

    #[test]
    fn from_seconds_ceil_and_floor() {
        let time = 70 * 512 + 1;
        let lock_by_time = LockTime::from_seconds_ceil(time).unwrap();
        assert_eq!(lock_by_time, LockTime::from_512_second_intervals(71));

        let lock_by_time = LockTime::from_seconds_floor(time).unwrap();
        assert_eq!(lock_by_time, LockTime::from_512_second_intervals(70));

        let mut max_time = 0xffff * 512;
        assert_eq!(LockTime::from_seconds_ceil(max_time), LockTime::from_seconds_floor(max_time));
        max_time += 512;
        assert!(LockTime::from_seconds_ceil(max_time).is_err());
        assert!(LockTime::from_seconds_floor(max_time).is_err());
    }

    #[test]
    fn parses_correctly_to_height_or_time() {
        let height1 = NumberOfBlocks::from(10);
        let height2 = NumberOfBlocks::from(11);
        let time1 = NumberOf512Seconds::from_512_second_intervals(70);
        let time2 = NumberOf512Seconds::from_512_second_intervals(71);

        let lock_by_height1 = LockTime::from(height1);
        let lock_by_height2 = LockTime::from(height2);
        let lock_by_time1 = LockTime::from(time1);
        let lock_by_time2 = LockTime::from(time2);

        assert!(lock_by_height1.is_block_height());
        assert!(!lock_by_height1.is_block_time());

        assert!(!lock_by_time1.is_block_height());
        assert!(lock_by_time1.is_block_time());

        // Test is_same_unit() logic
        assert!(lock_by_height1.is_same_unit(lock_by_height2));
        assert!(!lock_by_height1.is_same_unit(lock_by_time1));
        assert!(lock_by_time1.is_same_unit(lock_by_time2));
        assert!(!lock_by_time1.is_same_unit(lock_by_height1));
    }

    #[test]
    fn height_correctly_implies() {
        let height = NumberOfBlocks::from(10);
        let lock_by_height = LockTime::from(height);

        assert!(!lock_by_height.is_implied_by(LockTime::from(NumberOfBlocks::from(9))));
        assert!(lock_by_height.is_implied_by(LockTime::from(NumberOfBlocks::from(10))));
        assert!(lock_by_height.is_implied_by(LockTime::from(NumberOfBlocks::from(11))));
    }

    #[test]
    fn time_correctly_implies() {
        let time = NumberOf512Seconds::from_512_second_intervals(70);
        let lock_by_time = LockTime::from(time);

        assert!(!lock_by_time
            .is_implied_by(LockTime::from(NumberOf512Seconds::from_512_second_intervals(69))));
        assert!(lock_by_time
            .is_implied_by(LockTime::from(NumberOf512Seconds::from_512_second_intervals(70))));
        assert!(lock_by_time
            .is_implied_by(LockTime::from(NumberOf512Seconds::from_512_second_intervals(71))));
    }

    #[test]
    fn sequence_correctly_implies() {
        let height = NumberOfBlocks::from(10);
        let time = NumberOf512Seconds::from_512_second_intervals(70);

        let lock_by_height = LockTime::from(height);
        let lock_by_time = LockTime::from(time);

        let seq_height = Sequence::from(lock_by_height);
        let seq_time = Sequence::from(lock_by_time);

        assert!(lock_by_height.is_implied_by_sequence(seq_height));
        assert!(!lock_by_height.is_implied_by_sequence(seq_time));

        assert!(lock_by_time.is_implied_by_sequence(seq_time));
        assert!(!lock_by_time.is_implied_by_sequence(seq_height));

        let disabled_sequence = Sequence::from_consensus(1 << 31);
        assert!(!lock_by_height.is_implied_by_sequence(disabled_sequence));
        assert!(!lock_by_time.is_implied_by_sequence(disabled_sequence));
    }

    #[test]
    fn incorrect_units_do_not_imply() {
        let time = NumberOf512Seconds::from_512_second_intervals(70);
        let height = NumberOfBlocks::from(10);

        let lock_by_time = LockTime::from(time);
        assert!(!lock_by_time.is_implied_by(LockTime::from(height)));
    }

    #[test]
    fn consensus_round_trip() {
        assert!(LockTime::from_consensus(1 << 31).is_err());
        assert!(LockTime::from_consensus(1 << 30).is_ok());
        // Relative locktimes do not care about bits 17 through 21.
        assert_eq!(LockTime::from_consensus(65536), LockTime::from_consensus(0));

        for val in [0u32, 1, 1000, 65535] {
            let seq = Sequence::from_consensus(val);
            let lt = LockTime::from_consensus(val).unwrap();
            assert_eq!(lt.to_consensus_u32(), val);
            assert_eq!(lt.to_sequence(), seq);
            assert_eq!(LockTime::from_sequence(seq).unwrap().to_sequence(), seq);

            let seq = Sequence::from_consensus(val + (1 << 22));
            let lt = LockTime::from_consensus(val + (1 << 22)).unwrap();
            assert_eq!(lt.to_consensus_u32(), val + (1 << 22));
            assert_eq!(lt.to_sequence(), seq);
            assert_eq!(LockTime::from_sequence(seq).unwrap().to_sequence(), seq);
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn disabled_locktime_error() {
        let disabled_sequence = Sequence::from_consensus(1 << 31);
        let err = LockTime::try_from(disabled_sequence).unwrap_err();

        assert_eq!(err.disabled_locktime_value(), 1 << 31);
        assert!(!format!("{}", err).is_empty());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn incompatible_height_error() {
        // This is an error test these values are not used in the error path.
        let mined_at = BlockHeight::from_u32(700_000);
        let chain_tip = BlockHeight::from_u32(800_000);

        let lock_by_time = LockTime::from_512_second_intervals(70); // Arbitrary value.
        let err = lock_by_time.is_satisfied_by_height(chain_tip, mined_at).unwrap_err();

        let expected_time = NumberOf512Seconds::from_512_second_intervals(70);
        assert_eq!(err, IsSatisfiedByHeightError::Incompatible(expected_time));
        assert!(!format!("{}", err).is_empty());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn incompatible_time_error() {
        // This is an error test these values are not used in the error path.
        let mined_at = BlockMtp::from_u32(1_234_567_890);
        let chain_tip = BlockMtp::from_u32(1_600_000_000);

        let lock_by_height = LockTime::from_height(10); // Arbitrary value.
        let err = lock_by_height.is_satisfied_by_time(chain_tip, mined_at).unwrap_err();

        let expected_height = NumberOfBlocks::from(10);
        assert_eq!(err, IsSatisfiedByTimeError::Incompatible(expected_height));
        assert!(!format!("{}", err).is_empty());
    }

    #[test]
    fn test_locktime_chain_state() {
        fn generate_timestamps(start: u32, step: u16) -> [BlockTime; 11] {
            let mut timestamps = [BlockTime::from_u32(0); 11];
            for (i, ts) in timestamps.iter_mut().enumerate() {
                *ts = BlockTime::from_u32(start.saturating_sub((step * i as u16).into()));
            }
            timestamps
        }

        let timestamps: [BlockTime; 11] = generate_timestamps(1_600_000_000, 200);
        let utxo_timestamps: [BlockTime; 11] = generate_timestamps(1_599_000_000, 200);

        let chain_height = BlockHeight::from_u32(100);
        let chain_mtp = BlockMtp::new(timestamps);
        let utxo_height = BlockHeight::from_u32(80);
        let utxo_mtp = BlockMtp::new(utxo_timestamps);

        let lock1 = LockTime::Blocks(NumberOfBlocks::from(10));
        assert!(lock1.is_satisfied_by(chain_height, chain_mtp, utxo_height, utxo_mtp).unwrap());

        let lock2 = LockTime::Blocks(NumberOfBlocks::from(21));
        assert!(lock2.is_satisfied_by(chain_height, chain_mtp, utxo_height, utxo_mtp).unwrap());

        let lock3 = LockTime::Time(NumberOf512Seconds::from_512_second_intervals(10));
        assert!(lock3.is_satisfied_by(chain_height, chain_mtp, utxo_height, utxo_mtp).unwrap());

        let lock4 = LockTime::Time(NumberOf512Seconds::from_512_second_intervals(20000));
        assert!(!lock4.is_satisfied_by(chain_height, chain_mtp, utxo_height, utxo_mtp).unwrap());

        assert!(LockTime::ZERO
            .is_satisfied_by(chain_height, chain_mtp, utxo_height, utxo_mtp)
            .unwrap());
        assert!(LockTime::from_512_second_intervals(0)
            .is_satisfied_by(chain_height, chain_mtp, utxo_height, utxo_mtp)
            .unwrap());

        let lock6 = LockTime::from_seconds_floor(5000).unwrap();
        assert!(lock6.is_satisfied_by(chain_height, chain_mtp, utxo_height, utxo_mtp).unwrap());

        let max_height_lock = LockTime::Blocks(NumberOfBlocks::MAX);
        assert!(!max_height_lock
            .is_satisfied_by(chain_height, chain_mtp, utxo_height, utxo_mtp)
            .unwrap());

        let max_time_lock = LockTime::Time(NumberOf512Seconds::MAX);
        assert!(!max_time_lock
            .is_satisfied_by(chain_height, chain_mtp, utxo_height, utxo_mtp)
            .unwrap());

        let max_chain_height = BlockHeight::from_u32(u32::MAX);
        let max_chain_mtp = BlockMtp::new(generate_timestamps(u32::MAX, 100));
        let max_utxo_height = BlockHeight::MAX;
        let max_utxo_mtp = max_chain_mtp;
        assert!(!max_height_lock
            .is_satisfied_by(max_chain_height, max_chain_mtp, max_utxo_height, max_utxo_mtp)
            .unwrap());
        assert!(!max_time_lock
            .is_satisfied_by(max_chain_height, max_chain_mtp, max_utxo_height, max_utxo_mtp)
            .unwrap());
    }

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
