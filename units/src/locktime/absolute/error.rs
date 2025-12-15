// SPDX-License-Identifier: CC0-1.0

//! Error types for the absolute locktime module.

use core::convert::Infallible;
use core::fmt;

use internals::error::InputString;
#[cfg(feature = "encoding")]
use internals::write_err;

use super::{Height, MedianTimePast, LOCK_TIME_THRESHOLD};
use crate::parse_int::ParseIntError;

/// An error consensus decoding an `LockTime`.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockTimeDecoderError(pub(super) encoding::UnexpectedEofError);

#[cfg(feature = "encoding")]
impl From<Infallible> for LockTimeDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for LockTimeDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "lock time decoder error"; self.0)
    }
}

#[cfg(all(feature = "std", feature = "encoding"))]
impl std::error::Error for LockTimeDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// Tried to satisfy a lock-by-time lock using a height value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncompatibleHeightError {
    /// The inner value of the lock-by-time lock.
    pub(super) lock: MedianTimePast,
    /// Attempted to satisfy a lock-by-time lock with this height.
    pub(super) incompatible: Height,
}

impl IncompatibleHeightError {
    /// Returns the value of the lock-by-time lock.
    pub fn lock(&self) -> MedianTimePast { self.lock }

    /// Returns the height that was erroneously used to try and satisfy a lock-by-time lock.
    pub fn incompatible(&self) -> Height { self.incompatible }
}

impl fmt::Display for IncompatibleHeightError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "tried to satisfy a lock-by-time lock {} with height: {}",
            self.lock, self.incompatible
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IncompatibleHeightError {}

/// Tried to satisfy a lock-by-height lock using a height value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncompatibleTimeError {
    /// The inner value of the lock-by-height lock.
    pub(super) lock: Height,
    /// Attempted to satisfy a lock-by-height lock with this MTP.
    pub(super) incompatible: MedianTimePast,
}

impl IncompatibleTimeError {
    /// Returns the value of the lock-by-height lock.
    pub fn lock(&self) -> Height { self.lock }

    /// Returns the MTP that was erroneously used to try and satisfy a lock-by-height lock.
    pub fn incompatible(&self) -> MedianTimePast { self.incompatible }
}

impl fmt::Display for IncompatibleTimeError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "tried to satisfy a lock-by-height lock {} with MTP: {}",
            self.lock, self.incompatible
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IncompatibleTimeError {}

/// Error returned when parsing block height fails.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParseHeightError(ParseError);

impl fmt::Display for ParseHeightError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.display(f, "block height", 0, LOCK_TIME_THRESHOLD - 1)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseHeightError {
    // To be consistent with `write_err` we need to **not** return source if overflow occurred
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { self.0.source() }
}

impl From<ParseError> for ParseHeightError {
    fn from(value: ParseError) -> Self { Self(value) }
}

/// Error returned when parsing block time fails.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParseTimeError(ParseError);

impl fmt::Display for ParseTimeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.display(f, "block time", LOCK_TIME_THRESHOLD, u32::MAX)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseTimeError {
    // To be consistent with `write_err` we need to **not** return source if overflow occurred
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { self.0.source() }
}

impl From<ParseError> for ParseTimeError {
    fn from(value: ParseError) -> Self { Self(value) }
}

/// Internal - common representation for height and time.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) enum ParseError {
    ParseInt(ParseIntError),
    // unit implied by outer type
    // we use i64 to have nicer messages for negative values
    Conversion(i64),
}

impl From<Infallible> for ParseError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl ParseError {
    pub(super) fn invalid_int<S: Into<InputString>>(
        s: S,
    ) -> impl FnOnce(core::num::ParseIntError) -> Self {
        move |source| {
            Self::ParseInt(ParseIntError { input: s.into(), bits: 32, is_signed: true, source })
        }
    }

    pub(super) fn display(
        &self,
        f: &mut fmt::Formatter<'_>,
        subject: &str,
        lower_bound: u32,
        upper_bound: u32,
    ) -> fmt::Result {
        use core::num::IntErrorKind;

        match self {
            Self::ParseInt(ParseIntError { input, bits: _, is_signed: _, source })
                if *source.kind() == IntErrorKind::PosOverflow =>
            {
                // Outputs "failed to parse <input_string> as absolute Height/MedianTimePast (<subject> is above limit <upper_bound>)"
                write!(
                    f,
                    "{} ({} is above limit {})",
                    input.display_cannot_parse("absolute Height/MedianTimePast"),
                    subject,
                    upper_bound
                )
            }
            Self::ParseInt(ParseIntError { input, bits: _, is_signed: _, source })
                if *source.kind() == IntErrorKind::NegOverflow =>
            {
                // Outputs "failed to parse <input_string> as absolute Height/MedianTimePast (<subject> is below limit <lower_bound>)"
                write!(
                    f,
                    "{} ({} is below limit {})",
                    input.display_cannot_parse("absolute Height/MedianTimePast"),
                    subject,
                    lower_bound
                )
            }
            Self::ParseInt(ParseIntError { input, bits: _, is_signed: _, source: _ }) => {
                write!(
                    f,
                    "{} ({})",
                    input.display_cannot_parse("absolute Height/MedianTimePast"),
                    subject
                )
            }
            Self::Conversion(value) if *value < i64::from(lower_bound) => {
                write!(f, "{} {} is below limit {}", subject, value, lower_bound)
            }
            Self::Conversion(value) => {
                write!(f, "{} {} is above limit {}", subject, value, upper_bound)
            }
        }
    }

    // To be consistent with `write_err` we need to **not** return source if overflow occurred
    #[cfg(feature = "std")]
    pub(super) fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use core::num::IntErrorKind;

        match self {
            Self::ParseInt(ParseIntError { source, .. })
                if *source.kind() == IntErrorKind::PosOverflow =>
                None,
            Self::ParseInt(ParseIntError { source, .. })
                if *source.kind() == IntErrorKind::NegOverflow =>
                None,
            Self::ParseInt(ParseIntError { source, .. }) => Some(source),
            Self::Conversion(_) => None,
        }
    }
}

impl From<ConversionError> for ParseError {
    fn from(value: ConversionError) -> Self { Self::Conversion(value.input.into()) }
}

/// Error returned when converting a `u32` to a lock time variant fails.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConversionError {
    /// The expected timelock unit, height (blocks) or time (seconds).
    unit: LockTimeUnit,
    /// The invalid input value.
    input: u32,
}

impl ConversionError {
    /// Constructs a new `ConversionError` from an invalid `n` when expecting a height value.
    pub(super) const fn invalid_height(n: u32) -> Self {
        Self { unit: LockTimeUnit::Blocks, input: n }
    }

    /// Constructs a new `ConversionError` from an invalid `n` when expecting a time value.
    pub(super) const fn invalid_time(n: u32) -> Self {
        Self { unit: LockTimeUnit::Seconds, input: n }
    }
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid lock time value {}, {}", self.input, self.unit)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ConversionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Describes the two types of locking, lock-by-height and lock-by-time.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
enum LockTimeUnit {
    /// Lock by blockheight.
    Blocks,
    /// Lock by blocktime.
    Seconds,
}

impl fmt::Display for LockTimeUnit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Blocks =>
                write!(f, "expected lock-by-height (must be < {})", LOCK_TIME_THRESHOLD),
            Self::Seconds =>
                write!(f, "expected lock-by-time (must be >= {})", LOCK_TIME_THRESHOLD),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "alloc")]
    fn locktime_unit_display() {
        use alloc::format;

        use super::LockTimeUnit;

        let blocks = LockTimeUnit::Blocks;
        let seconds = LockTimeUnit::Seconds;

        assert_eq!(format!("{}", blocks), "expected lock-by-height (must be < 500000000)");
        assert_eq!(format!("{}", seconds), "expected lock-by-time (must be >= 500000000)");
    }
}
