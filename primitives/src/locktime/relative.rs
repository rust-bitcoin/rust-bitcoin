// SPDX-License-Identifier: CC0-1.0

//! Provides type [`LockTime`] that implements the logic around nSequence/OP_CHECKSEQUENCEVERIFY.
//!
//! There are two types of lock time: lock-by-blockheight and lock-by-blocktime, distinguished by
//! whether bit 22 of the `u32` consensus value is set.

#[cfg(feature = "ordered")]
use core::cmp::Ordering;
use core::{cmp, convert, fmt};

#[cfg(all(test, mutate))]
use mutagen::mutate;
use units::locktime::absolute::{Height, Time};

#[cfg(doc)]
use crate::relative;
use crate::Sequence;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use units::locktime::relative::*;

/// A relative lock time value, representing either a block height or time (512 second intervals).
///
/// Used for sequence numbers (`nSequence` in Bitcoin Core and `TxIn::sequence`
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
pub enum LockTime {
    /// A block height lock time value.
    Blocks(HeightSpan),
    /// Intervals of 512 seconds.
    Time(TimeSpan),
}

impl LockTime {
    /// A relative locktime of 0 is always valid, and is assumed valid for inputs that
    /// are not yet confirmed.
    pub const ZERO: LockTime = LockTime::Blocks(HeightSpan::ZERO);

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
    /// # use bitcoin_primitives::relative::LockTime;
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
    pub fn to_sequence(&self) -> Sequence {
        Sequence::from_consensus(self.to_consensus_u32())
    }

    /// Constructs a `LockTime` from `n`, expecting `n` to be a 16-bit count of blocks.
    #[inline]
    pub const fn from_height(n: u16) -> Self {
        LockTime::Blocks(HeightSpan::from_height(n))
    }

    /// Constructs a `LockTime` from `n`, expecting `n` to be a count of 512-second intervals.
    ///
    /// This function is a little awkward to use, and users may wish to instead use
    /// [`Self::from_seconds_floor`] or [`Self::from_seconds_ceil`].
    #[inline]
    pub const fn from_512_second_intervals(intervals: u16) -> Self {
        LockTime::Time(TimeSpan::from_512_second_intervals(intervals))
    }

    /// Create a [`LockTime`] from seconds, converting the seconds into 512 second interval
    /// with truncating division.
    ///
    /// # Errors
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    #[inline]
    pub const fn from_seconds_floor(seconds: u32) -> Result<Self, TimeOverflowError> {
        match TimeSpan::from_seconds_floor(seconds) {
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
        match TimeSpan::from_seconds_ceil(seconds) {
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
    pub const fn is_block_height(&self) -> bool {
        matches!(*self, LockTime::Blocks(_))
    }

    /// Returns true if this lock time value is in units of time.
    #[inline]
    pub const fn is_block_time(&self) -> bool {
        !self.is_block_height()
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
    /// # use bitcoin_primitives::Sequence;
    /// # use bitcoin_primitives::locktime::relative::LockTime;
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

    /// Returns true if this [`relative::LockTime`] is satisfied.
    ///
    /// > ... a relative block lock-time n can be included n blocks after the mining date of the
    /// > output it is spending, or any block thereafter.
    ///
    /// # Parameters
    ///
    /// * `prevout_mining_date`: The height of the block that mined the output we want to spend.
    /// * `last_block_height`: The height of the previous block (i.e. chain tip block height).
    ///
    /// # Errors
    ///
    /// Returns an error if this lock is not lock-by-height.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin_primitives::Sequence;
    /// use units::locktime::absolute::Height;
    ///
    /// // The span of blocks that the output we want to spend has to wait
    /// // before included in a block.
    /// let span: u16 = 100;
    ///
    /// // The height that the output we want to spend was mined.
    /// let prevout_mining_date = Height::from_consensus(100_000).expect("valid height");
    ///
    /// // The height of the tip of the chain.
    /// let last_block_height = Height::from_consensus(100_000 + span as u32).expect("valid height");
    ///
    /// let lock = Sequence::from_height(span).to_relative_lock_time().expect("valid relative height");
    /// assert!(lock.is_satisfied_by_height(prevout_mining_date, last_block_height).unwrap())
    /// ```
    #[inline]
    #[cfg_attr(all(test, mutate), mutate)]
    pub fn is_satisfied_by_height(
        &self,
        prevout_mining_date: Height,
        last_block_height: Height,
    ) -> Result<bool, IncompatibleHeightError> {
        use LockTime::*;
        match *self {
            Blocks(ref height) => {
                let required_height =
                    prevout_mining_date.to_consensus_u32() + u32::from(height.value());
                Ok(required_height <= last_block_height.to_consensus_u32())
            }
            Time(time) => Err(IncompatibleHeightError(time.value())),
        }
    }

    /// Returns true if this [`relative::LockTime`] is satisfied by [`Time`].
    ///
    /// > The relative lock-time specifies a timespan in units of 512 seconds granularity. The
    /// > timespan starts from the median-time-past of the output’s previous block, and ends at the
    /// > MTP of the previous block.
    /// >
    /// > ... a relative time-based lock-time n can be included into any block produced 512 * n
    /// > seconds after the mining date of the output it is spending, or any block thereafter. The
    /// > mining date of the output is equal to the median-time-past of the previous block which
    /// > mined it.
    ///
    /// > The block produced time is equal to the median-time-past of its previous block.
    ///
    /// # Parameters
    ///
    /// * `prevout_mining_date`: The mining date of the output (defined in quote above).
    /// * `chain_mtp`: The MTP of the previous block (defined in quote above).
    ///
    /// Both parameters are UNIX timestamps.
    ///
    /// # Errors
    ///
    /// Returns an error if this lock is not lock-by-time.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin_primitives::Sequence;
    /// use units::locktime::absolute::Time;
    ///
    /// // Units of 512 seconds that the output we want to spend has to wait.
    /// let span: u16 = 100;
    ///
    /// // Arbitrary UNIX timestamp representing the MTP of the block that created the prevout we want to spend.
    /// let prevout_mining_date = Time::from_consensus(1_000_000_000).expect("valid time");
    ///
    /// // A unix timestamp 512 seconds after the timespan since the MTP of the prevout block.
    /// let mtp_of_tip_of_chain = Time::from_consensus(1_000_000_000 + 512 * span as u32).expect("valid time");
    ///
    /// let lock = Sequence::from_512_second_intervals(span).to_relative_lock_time().expect("valid interval");
    /// assert!(lock.is_satisfied_by_time(prevout_mining_date, mtp_of_tip_of_chain).unwrap());
    /// ```
    #[inline]
    #[cfg_attr(all(test, mutate), mutate)]
    pub fn is_satisfied_by_time(
        &self,
        prevout_mining_date: Time,
        chain_mtp: Time,
    ) -> Result<bool, IncompatibleTimeError> {
        use LockTime::*;

        match *self {
            Time(ref t) => {
                let required_time =
                    prevout_mining_date.to_consensus_u32() + u32::from(t.value() * 512);
                Ok(required_time <= chain_mtp.to_consensus_u32())
            }
            Blocks(height) => Err(IncompatibleTimeError(height.value())),
        }
    }
}

impl From<HeightSpan> for LockTime {
    #[inline]
    fn from(h: HeightSpan) -> Self {
        LockTime::Blocks(h)
    }
}

impl From<TimeSpan> for LockTime {
    #[inline]
    fn from(t: TimeSpan) -> Self {
        LockTime::Time(t)
    }
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
    fn from(lt: LockTime) -> Sequence {
        lt.to_sequence()
    }
}

/// Error returned when a sequence number is parsed as a lock time, but its
/// "disable" flag is set.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DisabledLockTimeError(u32);

impl DisabledLockTimeError {
    /// Accessor for the `u32` whose "disable" flag was set, preventing
    /// it from being parsed as a relative locktime.
    pub fn disabled_locktime_value(&self) -> u32 {
        self.0
    }
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
pub struct IncompatibleHeightError(pub u16);

impl fmt::Display for IncompatibleHeightError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "tried to satisfy a time-locked Timelock with height {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IncompatibleHeightError {}

/// Tried to satisfy a lock-by-blockheight lock using a time value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IncompatibleTimeError(pub u16);
impl fmt::Display for IncompatibleTimeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "tried to satisfy a lock-by-blockheight Timelock with time {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IncompatibleTimeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn satisfied_by_height() {
        use units::locktime::absolute::Height;

        // The span of blocks that the output we want to spend has to wait
        // before included in a block.
        let span: u16 = 100;

        // The height that the output we want to spend was mined.
        let prevout_mining_date = Height::from_consensus(100_000).expect("valid height");

        // The height of the tip of the chain.
        let last_block_height =
            Height::from_consensus(100_000 + span as u32).expect("valid height");

        let lock =
            Sequence::from_height(span).to_relative_lock_time().expect("valid relative height");
        assert!(lock.is_satisfied_by_height(prevout_mining_date, last_block_height).unwrap())
    }

    #[test]
    fn satisfied_by_time() {
        use units::locktime::absolute::Time;

        // Units of 512 seconds that the output we want to spend has to wait.
        let span: u16 = 100;

        // Arbitrary UNIX timestamp representing the MTP of the block that created the prevout we want to spend.
        let prevout_mining_date = Time::from_consensus(1_000_000_000).expect("valid time");

        // A unix timestamp 512 seconds after the timespan since the MTP of the prevout block.
        let mtp_of_tip_of_chain =
            Time::from_consensus(1_000_000_000 + 512 * span as u32).expect("valid time");

        let lock = Sequence::from_512_second_intervals(span)
            .to_relative_lock_time()
            .expect("valid interval");
        assert!(lock.is_satisfied_by_time(prevout_mining_date, mtp_of_tip_of_chain).unwrap());
    }

    #[test]
    fn height_correctly_implies() {
        let height = HeightSpan::from(10);
        let lock = LockTime::from(height);

        assert!(!lock.is_implied_by(LockTime::from(HeightSpan::from(9))));
        assert!(lock.is_implied_by(LockTime::from(HeightSpan::from(10))));
        assert!(lock.is_implied_by(LockTime::from(HeightSpan::from(11))));
    }

    #[test]
    fn time_correctly_implies() {
        let time = TimeSpan::from_512_second_intervals(70);
        let lock = LockTime::from(time);

        assert!(!lock.is_implied_by(LockTime::from(TimeSpan::from_512_second_intervals(69))));
        assert!(lock.is_implied_by(LockTime::from(TimeSpan::from_512_second_intervals(70))));
        assert!(lock.is_implied_by(LockTime::from(TimeSpan::from_512_second_intervals(71))));
    }

    #[test]
    fn incorrect_units_do_not_imply() {
        let time = TimeSpan::from_512_second_intervals(70);
        let height = HeightSpan::from(10);

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
