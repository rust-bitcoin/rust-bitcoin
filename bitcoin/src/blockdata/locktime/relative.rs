// Rust Bitcoin Library - Written by the rust-bitcoin developers.
// SPDX-License-Identifier: CC0-1.0

//! Provides type [`LockTime`] that implements the logic around nSequence/OP_CHECKSEQUENCEVERIFY.
//!
//! There are two types of lock time: lock-by-blockheight and lock-by-blocktime, distinguished by
//! whether bit 22 of the `u32` consensus value is set.
//!

use core::fmt;
use core::convert::TryFrom;

#[cfg(all(test, mutate))]
use mutagen::mutate;

use crate::parse::impl_parse_str_from_int_infallible;
use crate::prelude::*;

#[cfg(doc)]
use crate::relative;

/// A relative lock time value, representing either a block height or time (512 second intervals).
///
/// The `relative::LockTime` type does not have any constructors, this is by design, please use
/// `Sequence::to_relative_lock_time` to create a relative lock time.
///
/// ### Relevant BIPs
///
/// * [BIP 68 Relative lock-time using consensus-enforced sequence numbers](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki)
/// * [BIP 112 CHECKSEQUENCEVERIFY](https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki)
#[allow(clippy::derive_ord_xor_partial_ord)]
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
        } else if let Ok(true) = self.is_satisfied_by_time(t) {
            true
        } else {
            false
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
    pub fn is_satisfied_by_height(&self, h: Height) -> Result<bool, Error> {
        use LockTime::*;

        match *self {
            Blocks(ref height) => Ok(height.value() <= h.value()),
            Time(ref time) => Err(Error::IncompatibleTime(*self, *time)),
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
    pub fn is_satisfied_by_time(&self, t: Time) -> Result<bool, Error> {
        use LockTime::*;

        match *self {
            Time(ref time) => Ok(time.value() <= t.value()),
            Blocks(ref height) => Err(Error::IncompatibleHeight(*self, *height)),
        }
    }
}

impl From<Height> for LockTime {
    #[inline]
    fn from(h: Height) -> Self {
        LockTime::Blocks(h)
    }
}

impl From<Time> for LockTime {
    #[inline]
    fn from(t: Time) -> Self {
        LockTime::Time(t)
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

/// A relative lock time lock-by-blockheight value.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Height(u16);

impl Height {
    /// Relative block height 0, can be included in any block.
    pub const ZERO: Self = Height(0);

    /// The minimum relative block height (0), can be included in any block.
    pub const MIN: Self = Self::ZERO;

    /// The maximum relative block height.
    pub const MAX: Self = Height(u16::max_value());

    /// The minimum relative block height (0), can be included in any block.
    ///
    /// This is provided for consistency with Rust 1.41.1, newer code should use [`Height::MIN`].
    pub const fn min_value() -> Self { Self::MIN }

    /// The maximum relative block height.
    ///
    /// This is provided for consistency with Rust 1.41.1, newer code should use [`Height::MAX`].
    pub const fn max_value() -> Self { Self::MAX }

    /// Returns the inner `u16` value.
    #[inline]
    pub fn value(self) -> u16 {
        self.0
    }
}

impl From<u16> for Height {
    #[inline]
    fn from(value: u16) -> Self {
        Height(value)
    }
}

impl_parse_str_from_int_infallible!(Height, u16, from);

impl fmt::Display for Height {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A relative lock time lock-by-blocktime value.
///
/// For BIP 68 relative lock-by-blocktime locks, time is measure in 512 second intervals.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Time(u16);

impl Time {
    /// Relative block time 0, can be included in any block.
    pub const ZERO: Self = Time(0);

    /// The minimum relative block time (0), can be included in any block.
    pub const MIN: Self = Time::ZERO;

    /// The maximum relative block time (33,554,432 seconds or approx 388 days).
    pub const MAX: Self = Time(u16::max_value());

    /// The minimum relative block time.
    ///
    /// This is provided for consistency with Rust 1.41.1, newer code should use [`Time::MIN`].
    pub const fn min_value() -> Self { Self::MIN }

    /// The maximum relative block time.
    ///
    /// This is provided for consistency with Rust 1.41.1, newer code should use [`Time::MAX`].
    pub const fn max_value() -> Self { Self::MAX }

    /// Create a [`Time`] using time intervals where each interval is equivalent to 512 seconds.
    ///
    /// Encoding finer granularity of time for relative lock-times is not supported in Bitcoin.
    #[inline]
    pub fn from_512_second_intervals(intervals: u16) -> Self {
        Time(intervals)
    }

    /// Create a [`Time`] from seconds, converting the seconds into 512 second interval with ceiling
    /// division.
    ///
    /// # Errors
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    #[inline]
    pub fn from_seconds_ceil(seconds: u32) -> Result<Self, Error> {
        if let Ok(interval) = u16::try_from((seconds + 511) / 512) {
            Ok(Time::from_512_second_intervals(interval))
        } else {
            Err(Error::IntegerOverflow(seconds))
        }
    }

    /// Returns the inner `u16` value.
    #[inline]
    pub fn value(self) -> u16 {
        self.0
    }
}

impl_parse_str_from_int_infallible!(Time, u16, from_512_second_intervals);

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Errors related to relative lock times.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Input time in seconds was too large to be encoded to a 16 bit 512 second interval.
    IntegerOverflow(u32),
    /// Tried to satisfy a lock-by-blocktime lock using a height value.
    IncompatibleHeight(LockTime, Height),
    /// Tried to satisfy a lock-by-blockheight lock using a time value.
    IncompatibleTime(LockTime, Time),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::IntegerOverflow(val) => write!(f, "{} seconds is too large to be encoded to a 16 bit 512 second interval", val),
            Self::IncompatibleHeight(lock, height) => write!(f, "tried to satisfy lock {} with height: {}", lock, height),
            Self::IncompatibleTime(lock, time) => write!(f, "tried to satisfy lock {} with time: {}", lock, time),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match *self {
            IntegerOverflow(_) | IncompatibleHeight(_, _) | IncompatibleTime(_, _) => None,
        }
    }
}

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
}
