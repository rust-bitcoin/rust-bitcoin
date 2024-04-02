// SPDX-License-Identifier: CC0-1.0

//! Provides type [`LockTime`] that implements the logic around nSequence/OP_CHECKSEQUENCEVERIFY.
//!
//! There are two types of lock time: lock-by-blockheight and lock-by-blocktime, distinguished by
//! whether bit 22 of the `u32` consensus value is set.
//!

#[cfg(feature = "ordered")]
use core::cmp::Ordering;
use core::{cmp, convert, fmt};

#[cfg(all(test, mutate))]
use mutagen::mutate;

#[cfg(doc)]
use crate::relative;
use crate::Sequence;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use units::locktime::relative::{Height, Time, TimeOverflowError};

/// A relative lock time value, representing either a block height or time (512 second intervals).
///
/// Used for sequence numbers (`nSequence` in Bitcoin Core and [`crate::TxIn::sequence`]
/// in this library) and also for the argument to opcode 'OP_CHECKSEQUENCEVERIFY`.
///
/// ### Note on ordering
///
/// Locktimes may be height- or time-based, and these metrics are incommensurate; there is no total
/// ordering on locktimes. We therefore have implemented [`PartialOrd`] but not [`Ord`]. We also
/// implement [`ordered::ArbitraryOrd`] if the "ordered" feature is enabled.
///
/// ### Relevant BIPs
///
/// * [BIP 68 Relative lock-time using consensus-enforced sequence numbers](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki)
/// * [BIP 112 CHECKSEQUENCEVERIFY](https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub enum LockTime {
    /// A block height lock time value.
    Blocks(Height),
    /// A 512 second time interval value.
    Time(Time),
}

impl LockTime {
    /// A relative locktime of 0 is always valid, and is assumed valid for inputs that
    /// are not yet confirmed.
    pub const ZERO: LockTime = LockTime::Blocks(Height::ZERO);

    /// The number of bytes that the locktime contributes to the size of a transaction.
    pub const SIZE: usize = 4; // Serialized length of a u32.

    /// Constructs a `LockTime` from an nSequence value or the argument to OP_CHECKSEQUENCEVERIFY.
    ///
    /// This method will **not** round-trip with [`Self::to_consensus_u32`], because relative
    /// locktimes only use some bits of the underlying `u32` value and discard the rest. If
    /// you want to preserve the full value, you should use the [`Sequence`] type instead.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin::relative::LockTime;
    ///
    /// // `from_consensus` roundtrips with `to_consensus_u32` for small values.
    /// let n_lock_time: u32 = 7000;
    /// let lock_time = LockTime::from_consensus(n_lock_time).unwrap();
    /// assert_eq!(lock_time.to_consensus_u32(), n_lock_time);
    /// ```
    pub fn from_consensus(n: u32) -> Result<Self, DisabledLockTimeError> {
        let sequence = crate::Sequence::from_consensus(n);
        sequence.to_relative_lock_time().ok_or(DisabledLockTimeError(n))
    }

    /// Returns the `u32` value used to encode this locktime in an nSequence field or
    /// argument to `OP_CHECKSEQUENCEVERIFY`.
    ///
    /// # Warning
    ///
    /// Locktimes are not ordered by the natural ordering on `u32`. If you want to
    /// compare locktimes, use [`Self::is_implied_by`] or similar methods.
    #[inline]
    pub fn to_consensus_u32(&self) -> u32 {
        match self {
            LockTime::Blocks(ref h) => h.to_consensus_u32(),
            LockTime::Time(ref t) => t.to_consensus_u32(),
        }
    }

    /// Constructs a `LockTime` from the sequence number of a Bitcoin input.
    ///
    /// This method will **not** round-trip with [`Self::to_sequence`]. See the
    /// docs for [`Self::from_consensus`] for more information.
    #[inline]
    pub fn from_sequence(n: Sequence) -> Result<Self, DisabledLockTimeError> {
        Self::from_consensus(n.to_consensus_u32())
    }

    /// Encodes the locktime as a sequence number.
    #[inline]
    pub fn to_sequence(&self) -> Sequence { Sequence::from_consensus(self.to_consensus_u32()) }

    /// Constructs a `LockTime` from `n`, expecting `n` to be a 16-bit count of blocks.
    #[inline]
    pub const fn from_height(n: u16) -> Self { LockTime::Blocks(Height::from_height(n)) }

    /// Constructs a `LockTime` from `n`, expecting `n` to be a count of 512-second intervals.
    ///
    /// This function is a little awkward to use, and users may wish to instead use
    /// [`Self::from_seconds_floor`] or [`Self::from_seconds_ceil`].
    #[inline]
    pub const fn from_512_second_intervals(intervals: u16) -> Self {
        LockTime::Time(Time::from_512_second_intervals(intervals))
    }

    /// Create a [`LockTime`] from seconds, converting the seconds into 512 second interval
    /// with truncating division.
    ///
    /// # Errors
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    #[inline]
    pub const fn from_seconds_floor(seconds: u32) -> Result<Self, TimeOverflowError> {
        match Time::from_seconds_floor(seconds) {
            Ok(time) => Ok(LockTime::Time(time)),
            Err(e) => Err(e),
        }
    }

    /// Create a [`LockTime`] from seconds, converting the seconds into 512 second interval
    /// with ceiling division.
    ///
    /// # Errors
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    #[inline]
    pub const fn from_seconds_ceil(seconds: u32) -> Result<Self, TimeOverflowError> {
        match Time::from_seconds_ceil(seconds) {
            Ok(time) => Ok(LockTime::Time(time)),
            Err(e) => Err(e),
        }
    }

    /// Returns true if both lock times use the same unit i.e., both height based or both time based.
    #[inline]
    pub const fn is_same_unit(&self, other: LockTime) -> bool {
        matches!(
            (self, other),
            (LockTime::Blocks(_), LockTime::Blocks(_)) | (LockTime::Time(_), LockTime::Time(_))
        )
    }

    /// Returns true if this lock time value is in units of block height.
    #[inline]
    pub const fn is_block_height(&self) -> bool { matches!(*self, LockTime::Blocks(_)) }

    /// Returns true if this lock time value is in units of time.
    #[inline]
    pub const fn is_block_time(&self) -> bool { !self.is_block_height() }

    /// Returns true if this [`relative::LockTime`] is satisfied by either height or time.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin::Sequence;
    /// # use bitcoin::locktime::relative::{LockTime, Height, Time};
    ///
    /// # let height = 100;       // 100 blocks.
    /// # let intervals = 70;     // Approx 10 hours.
    /// # let current_height = || Height::from(height + 10);
    /// # let current_time = || Time::from_512_second_intervals(intervals + 10);
    /// # let lock = Sequence::from_height(height).to_relative_lock_time().expect("valid height");
    ///
    /// // Users that have chain data can get the current height and time to check against a lock.
    /// let height_and_time = (current_time(), current_height());  // tuple order does not matter.
    /// assert!(lock.is_satisfied_by(current_height(), current_time()));
    /// ```
    #[inline]
    #[cfg_attr(all(test, mutate), mutate)]
    pub fn is_satisfied_by(&self, h: Height, t: Time) -> bool {
        if let Ok(true) = self.is_satisfied_by_height(h) {
            true
        } else {
            matches!(self.is_satisfied_by_time(t), Ok(true))
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
    /// # use bitcoin::Sequence;
    /// # use bitcoin::locktime::relative::{LockTime, Height, Time};
    ///
    /// # let height = 100;       // 100 blocks.
    /// # let lock = Sequence::from_height(height).to_relative_lock_time().expect("valid height");
    /// # let test_sequence = Sequence::from_height(height + 10);
    ///
    /// let satisfied = match test_sequence.to_relative_lock_time() {
    ///     None => false, // Handle non-lock-time case.
    ///     Some(test_lock) => lock.is_implied_by(test_lock),
    /// };
    /// assert!(satisfied);
    /// ```
    #[inline]
    #[cfg_attr(all(test, mutate), mutate)]
    pub fn is_implied_by(&self, other: LockTime) -> bool {
        use LockTime::*;

        match (*self, other) {
            (Blocks(this), Blocks(other)) => this.value() <= other.value(),
            (Time(this), Time(other)) => this.value() <= other.value(),
            _ => false, // Not the same units.
        }
    }

    /// Returns true if satisfaction of the sequence number implies satisfaction of this lock time.
    ///
    /// When deciding whether an instance of `<n> CHECKSEQUENCEVERIFY` will pass, this
    /// method can be used by parsing `n` as a [`LockTime`] and calling this method
    /// with the sequence number of the input which spends the script.
    #[inline]
    pub fn is_implied_by_sequence(&self, other: Sequence) -> bool {
        if let Ok(other) = LockTime::from_sequence(other) {
            self.is_implied_by(other)
        } else {
            false
        }
    }

    /// Returns true if this [`relative::LockTime`] is satisfied by [`Height`].
    ///
    /// # Errors
    ///
    /// Returns an error if this lock is not lock-by-height.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin::Sequence;
    /// # use bitcoin::locktime::relative::{LockTime, Height, Time};
    ///
    /// let height: u16 = 100;
    /// let lock = Sequence::from_height(height).to_relative_lock_time().expect("valid height");
    /// assert!(lock.is_satisfied_by_height(Height::from(height+1)).expect("a height"));
    /// ```
    #[inline]
    #[cfg_attr(all(test, mutate), mutate)]
    pub fn is_satisfied_by_height(&self, height: Height) -> Result<bool, IncompatibleHeightError> {
        use LockTime::*;

        match *self {
            Blocks(ref h) => Ok(h.value() <= height.value()),
            Time(time) => Err(IncompatibleHeightError { height, time }),
        }
    }

    /// Returns true if this [`relative::LockTime`] is satisfied by [`Time`].
    ///
    /// # Errors
    ///
    /// Returns an error if this lock is not lock-by-time.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin::Sequence;
    /// # use bitcoin::locktime::relative::{LockTime, Height, Time};
    ///
    /// let intervals: u16 = 70; // approx 10 hours;
    /// let lock = Sequence::from_512_second_intervals(intervals).to_relative_lock_time().expect("valid time");
    /// assert!(lock.is_satisfied_by_time(Time::from_512_second_intervals(intervals + 10)).expect("a time"));
    /// ```
    #[inline]
    #[cfg_attr(all(test, mutate), mutate)]
    pub fn is_satisfied_by_time(&self, time: Time) -> Result<bool, IncompatibleTimeError> {
        use LockTime::*;

        match *self {
            Time(ref t) => Ok(t.value() <= time.value()),
            Blocks(height) => Err(IncompatibleTimeError { time, height }),
        }
    }
}

impl From<Height> for LockTime {
    #[inline]
    fn from(h: Height) -> Self { LockTime::Blocks(h) }
}

impl From<Time> for LockTime {
    #[inline]
    fn from(t: Time) -> Self { LockTime::Time(t) }
}

impl PartialOrd for LockTime {
    #[inline]
    fn partial_cmp(&self, other: &LockTime) -> Option<cmp::Ordering> {
        use LockTime::*;

        match (*self, *other) {
            (Blocks(ref a), Blocks(ref b)) => a.partial_cmp(b),
            (Time(ref a), Time(ref b)) => a.partial_cmp(b),
            (_, _) => None,
        }
    }
}

impl fmt::Display for LockTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use LockTime::*;

        if f.alternate() {
            match *self {
                Blocks(ref h) => write!(f, "block-height {}", h),
                Time(ref t) => write!(f, "block-time {} (512 second intervals)", t),
            }
        } else {
            match *self {
                Blocks(ref h) => fmt::Display::fmt(h, f),
                Time(ref t) => fmt::Display::fmt(t, f),
            }
        }
    }
}

#[cfg(feature = "ordered")]
impl ordered::ArbitraryOrd for LockTime {
    fn arbitrary_cmp(&self, other: &Self) -> Ordering {
        use LockTime::*;

        match (self, other) {
            (Blocks(_), Time(_)) => Ordering::Less,
            (Time(_), Blocks(_)) => Ordering::Greater,
            (Blocks(this), Blocks(that)) => this.cmp(that),
            (Time(this), Time(that)) => this.cmp(that),
        }
    }
}

impl convert::TryFrom<Sequence> for LockTime {
    type Error = DisabledLockTimeError;
    fn try_from(seq: Sequence) -> Result<LockTime, DisabledLockTimeError> {
        LockTime::from_sequence(seq)
    }
}

impl From<LockTime> for Sequence {
    fn from(lt: LockTime) -> Sequence { lt.to_sequence() }
}

/// Error returned when a sequence number is parsed as a lock time, but its
/// "disable" flag is set.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DisabledLockTimeError(u32);

impl DisabledLockTimeError {
    /// Accessor for the `u32` whose "disable" flag was set, preventing
    /// it from being parsed as a relative locktime.
    pub fn disabled_locktime_value(&self) -> u32 { self.0 }
}

impl fmt::Display for DisabledLockTimeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "lock time 0x{:08x} has disable flag set", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DisabledLockTimeError {}

/// Tried to satisfy a lock-by-blocktime lock using a height value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IncompatibleHeightError {
    /// Attempted to satisfy a lock-by-blocktime lock with this height.
    pub height: Height,
    /// The inner time value of the lock-by-blocktime lock.
    pub time: Time,
}

impl fmt::Display for IncompatibleHeightError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "tried to satisfy a lock-by-blocktime lock {} with height: {}",
            self.time, self.height
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IncompatibleHeightError {}

/// Tried to satisfy a lock-by-blockheight lock using a time value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IncompatibleTimeError {
    /// Attempted to satisfy a lock-by-blockheight lock with this time.
    pub time: Time,
    /// The inner height value of the lock-by-blockheight lock.
    pub height: Height,
}

impl fmt::Display for IncompatibleTimeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "tried to satisfy a lock-by-blockheight lock {} with time: {}",
            self.height, self.time
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IncompatibleTimeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn satisfied_by_height() {
        let height = Height::from(10);
        let time = Time::from_512_second_intervals(70);

        let lock = LockTime::from(height);

        assert!(!lock.is_satisfied_by(Height::from(9), time));
        assert!(lock.is_satisfied_by(Height::from(10), time));
        assert!(lock.is_satisfied_by(Height::from(11), time));
    }

    #[test]
    fn satisfied_by_time() {
        let height = Height::from(10);
        let time = Time::from_512_second_intervals(70);

        let lock = LockTime::from(time);

        assert!(!lock.is_satisfied_by(height, Time::from_512_second_intervals(69)));
        assert!(lock.is_satisfied_by(height, Time::from_512_second_intervals(70)));
        assert!(lock.is_satisfied_by(height, Time::from_512_second_intervals(71)));
    }

    #[test]
    fn height_correctly_implies() {
        let height = Height::from(10);
        let lock = LockTime::from(height);

        assert!(!lock.is_implied_by(LockTime::from(Height::from(9))));
        assert!(lock.is_implied_by(LockTime::from(Height::from(10))));
        assert!(lock.is_implied_by(LockTime::from(Height::from(11))));
    }

    #[test]
    fn time_correctly_implies() {
        let time = Time::from_512_second_intervals(70);
        let lock = LockTime::from(time);

        assert!(!lock.is_implied_by(LockTime::from(Time::from_512_second_intervals(69))));
        assert!(lock.is_implied_by(LockTime::from(Time::from_512_second_intervals(70))));
        assert!(lock.is_implied_by(LockTime::from(Time::from_512_second_intervals(71))));
    }

    #[test]
    fn incorrect_units_do_not_imply() {
        let time = Time::from_512_second_intervals(70);
        let height = Height::from(10);

        let lock = LockTime::from(time);
        assert!(!lock.is_implied_by(LockTime::from(height)));
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
}
