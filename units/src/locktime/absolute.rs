// SPDX-License-Identifier: CC0-1.0

//! Provides [`Height`] and [`MedianTimePast`] types used by the `rust-bitcoin` `absolute::LockTime` type.

use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use internals::error::InputString;

use crate::parse::{self, ParseIntError};

/// The Threshold for deciding whether a lock time value is a height or a time (see [Bitcoin Core]).
///
/// `LockTime` values _below_ the threshold are interpreted as block heights, values _above_ (or
/// equal to) the threshold are interpreted as block times (UNIX timestamp, seconds since epoch).
///
/// Bitcoin is able to safely use this value because a block height greater than 500,000,000 would
/// never occur because it would represent a height in approximately 9500 years. Conversely, block
/// times under 500,000,000 will never happen because they would represent times before 1986 which
/// are, for obvious reasons, not useful within the Bitcoin network.
///
/// [Bitcoin Core]: https://github.com/bitcoin/bitcoin/blob/9ccaee1d5e2e4b79b0a7c29aadb41b97e4741332/src/script/script.h#L39
pub const LOCK_TIME_THRESHOLD: u32 = 500_000_000;

/// An absolute block height, guaranteed to always contain a valid height value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Height(u32);

impl Height {
    /// Absolute block height 0, the genesis block.
    pub const ZERO: Self = Height(0);

    /// The minimum absolute block height (0), the genesis block.
    pub const MIN: Self = Self::ZERO;

    /// The maximum absolute block height.
    pub const MAX: Self = Height(LOCK_TIME_THRESHOLD - 1);

    /// Constructs a new [`Height`] from a hex string.
    ///
    /// The input string may or may not contain a typical hex prefix e.g., `0x`.
    ///
    /// # Errors
    ///
    /// If the input string is not a valid hex representation of a block height.
    pub fn from_hex(s: &str) -> Result<Self, ParseHeightError> { parse_hex(s, Self::from_u32) }

    #[deprecated(since = "TBD", note = "use `from_u32` instead")]
    #[doc(hidden)]
    pub const fn from_consensus(n: u32) -> Result<Self, ConversionError> { Self::from_u32(n) }

    #[deprecated(since = "TBD", note = "use `to_u32` instead")]
    #[doc(hidden)]
    pub const fn to_consensus_u32(self) -> u32 { self.to_u32() }

    /// Constructs a new block height directly from a `u32` value.
    ///
    /// # Errors
    ///
    /// If `n` does not represent a block height within the valid range for a locktime:
    /// `[0, 499_999_999]`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin_units::locktime::absolute::Height;
    ///
    /// let h: u32 = 741521;
    /// let height = Height::from_u32(h).expect("invalid height value");
    /// assert_eq!(height.to_consensus_u32(), h);
    /// ```
    #[inline]
    pub const fn from_u32(n: u32) -> Result<Height, ConversionError> {
        if is_block_height(n) {
            Ok(Self(n))
        } else {
            Err(ConversionError::invalid_height(n))
        }
    }

    /// Converts this [`Height`] to a raw `u32` value.
    #[inline]
    pub const fn to_u32(self) -> u32 { self.0 }

    /// Returns true if a transaction with this locktime can be included in the next block.
    ///
    /// `self` is value of the `LockTime` and if `height` is the current chain tip then
    /// a transaction with this lock can be broadcast for inclusion in the next block.
    #[inline]
    pub fn is_satisfied_by(self, height: Height) -> bool {
        // Use u64 so that there can be no overflow.
        let next_block_height = u64::from(height.to_u32()) + 1;
        u64::from(self.to_u32()) <= next_block_height
    }
}

impl fmt::Display for Height {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

crate::impl_parse_str!(Height, ParseHeightError, parser(Height::from_u32));

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
    // To be consistent with `write_err` we need to **not** return source in case of overflow
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { self.0.source() }
}

impl From<ParseError> for ParseHeightError {
    fn from(value: ParseError) -> Self { Self(value) }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Height {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let u = u32::deserialize(deserializer)?;
        Height::from_u32(u).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Height {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_u32().serialize(serializer)
    }
}

#[deprecated(since = "TBD", note = "use `MedianTimePast` instead")]
#[doc(hidden)]
pub type Time = MedianTimePast;

/// The median timestamp of 11 consecutive blocks, representing "the timestamp" of the
/// final block for locktime-checking purposes.
///
/// Time-based locktimes are not measured against the timestamps in individual block
/// headers, since these are not monotone and may be subject to miner manipulation.
/// Instead, locktimes use the "median-time-past" (MTP) of the most recent 11 blocks,
/// a quantity which is required by consensus to be monotone and which is difficult
/// for any individual miner to manipulate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MedianTimePast(u32);

impl MedianTimePast {
    /// The minimum MTP allowable in a locktime (Tue Nov 05 1985 00:53:20 GMT+0000).
    pub const MIN: Self = MedianTimePast(LOCK_TIME_THRESHOLD);

    /// The maximum MTP allowable in a locktime (Sun Feb 07 2106 06:28:15 GMT+0000).
    pub const MAX: Self = MedianTimePast(u32::MAX);

    /// Constructs an [`MedianTimePast`] by computing the median‐time‐past from the last 11 block timestamps
    ///
    /// Because block timestamps are not monotonic, this function internally sorts them;
    /// it is therefore not important what order they appear in the array; use whatever
    /// is most convenient.
    ///
    /// # Errors
    ///
    /// If the median block timestamp is not in the allowable range of MTPs in a
    /// locktime: `[500_000_000, 2^32 - 1]`. Because there is a consensus rule that MTP
    /// be monotonically increasing, and the MTP of the first 11 blocks exceeds `500_000_000`
    /// for every real-life chain, this error typically cannot be hit in practice.
    pub fn new(timestamps: [crate::BlockTime; 11]) -> Result<Self, ConversionError> {
        crate::BlockMtp::new(timestamps).try_into()
    }

    /// Constructs a new [`MedianTimePast`] from a big-endian hex-encoded `u32`.
    ///
    /// The input string may or may not contain a typical hex prefix e.g., `0x`.
    ///
    /// # Errors
    ///
    /// If the input string is not a valid hex representation of a block time.
    pub fn from_hex(s: &str) -> Result<Self, ParseTimeError> { parse_hex(s, Self::from_u32) }

    #[deprecated(since = "TBD", note = "use `from_u32` instead")]
    #[doc(hidden)]
    pub const fn from_consensus(n: u32) -> Result<Self, ConversionError> { Self::from_u32(n) }

    #[deprecated(since = "TBD", note = "use `to_u32` instead")]
    #[doc(hidden)]
    pub const fn to_consensus_u32(self) -> u32 { self.to_u32() }

    /// Constructs a new MTP directly from a `u32` value.
    ///
    /// This function, with [`MedianTimePast::to_u32`], is used to obtain a raw MTP value. It is
    /// **not** used to convert to or from a block timestamp, which is not a MTP.
    ///
    /// # Errors
    ///
    /// If `n` is not in the allowable range of MTPs in a locktime: `[500_000_000, 2^32 - 1]`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin_units::locktime::absolute::MedianTimePast;
    ///
    /// let t: u32 = 1653195600; // May 22nd, 5am UTC.
    /// let time = MedianTimePast::from_u32(t).expect("invalid time value");
    /// assert_eq!(time.to_consensus_u32(), t);
    /// ```
    #[inline]
    pub const fn from_u32(n: u32) -> Result<Self, ConversionError> {
        if is_block_time(n) {
            Ok(Self(n))
        } else {
            Err(ConversionError::invalid_time(n))
        }
    }

    /// Converts this [`MedianTimePast`] to a raw `u32` value.
    #[inline]
    pub const fn to_u32(self) -> u32 { self.0 }

    /// Returns true if a transaction with this locktime can be included in the next block.
    ///
    /// `self`is the value of the `LockTime` and if `time` is the median time past of the block at
    /// the chain tip then a transaction with this lock can be broadcast for inclusion in the next
    /// block.
    #[inline]
    pub fn is_satisfied_by(self, time: MedianTimePast) -> bool {
        // The locktime check in Core during block validation uses the MTP
        // of the previous block - which is the expected to be `time` here.
        self <= time
    }
}

impl fmt::Display for MedianTimePast {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

crate::impl_parse_str!(MedianTimePast, ParseTimeError, parser(MedianTimePast::from_u32));

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for MedianTimePast {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let u = u32::deserialize(deserializer)?;
        MedianTimePast::from_u32(u).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for MedianTimePast {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_u32().serialize(serializer)
    }
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
    // To be consistent with `write_err` we need to **not** return source in case of overflow
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { self.0.source() }
}

impl From<ParseError> for ParseTimeError {
    fn from(value: ParseError) -> Self { Self(value) }
}

fn parser<T, E, S, F>(f: F) -> impl FnOnce(S) -> Result<T, E>
where
    E: From<ParseError>,
    S: AsRef<str> + Into<InputString>,
    F: FnOnce(u32) -> Result<T, ConversionError>,
{
    move |s| {
        let n = s.as_ref().parse::<i64>().map_err(ParseError::invalid_int(s))?;
        let n = u32::try_from(n).map_err(|_| ParseError::Conversion(n))?;
        f(n).map_err(ParseError::from).map_err(Into::into)
    }
}

fn parse_hex<T, E, S, F>(s: S, f: F) -> Result<T, E>
where
    E: From<ParseError>,
    S: AsRef<str> + Into<InputString>,
    F: FnOnce(u32) -> Result<T, ConversionError>,
{
    let n = i64::from_str_radix(parse::hex_remove_optional_prefix(s.as_ref()), 16)
        .map_err(ParseError::invalid_int(s))?;
    let n = u32::try_from(n).map_err(|_| ParseError::Conversion(n))?;
    f(n).map_err(ParseError::from).map_err(Into::into)
}

/// Returns true if `n` is a block height i.e., less than 500,000,000.
pub const fn is_block_height(n: u32) -> bool { n < LOCK_TIME_THRESHOLD }

/// Returns true if `n` is a UNIX timestamp i.e., greater than or equal to 500,000,000.
pub const fn is_block_time(n: u32) -> bool { n >= LOCK_TIME_THRESHOLD }

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
    const fn invalid_height(n: u32) -> Self { Self { unit: LockTimeUnit::Blocks, input: n } }

    /// Constructs a new `ConversionError` from an invalid `n` when expecting a time value.
    const fn invalid_time(n: u32) -> Self { Self { unit: LockTimeUnit::Seconds, input: n } }
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
        use LockTimeUnit as L;

        match *self {
            L::Blocks => write!(f, "expected lock-by-height (must be < {})", LOCK_TIME_THRESHOLD),
            L::Seconds => write!(f, "expected lock-by-time (must be >= {})", LOCK_TIME_THRESHOLD),
        }
    }
}

/// Internal - common representation for height and time.
#[derive(Debug, Clone, Eq, PartialEq)]
enum ParseError {
    ParseInt(ParseIntError),
    // unit implied by outer type
    // we use i64 to have nicer messages for negative values
    Conversion(i64),
}

impl From<Infallible> for ParseError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl ParseError {
    fn invalid_int<S: Into<InputString>>(s: S) -> impl FnOnce(core::num::ParseIntError) -> Self {
        move |source| {
            Self::ParseInt(ParseIntError { input: s.into(), bits: 32, is_signed: true, source })
        }
    }

    fn display(
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

    // To be consistent with `write_err` we need to **not** return source in case of overflow
    #[cfg(feature = "std")]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
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

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Height {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;
        match choice {
            0 => Ok(Height::MIN),
            1 => Ok(Height::MAX),
            _ => {
                let min = Height::MIN.to_u32();
                let max = Height::MAX.to_u32();
                let h = u.int_in_range(min..=max)?;
                Ok(Height::from_u32(h).unwrap())
            }
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for MedianTimePast {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;
        match choice {
            0 => Ok(MedianTimePast::MIN),
            1 => Ok(MedianTimePast::MAX),
            _ => {
                let min = MedianTimePast::MIN.to_u32();
                let max = MedianTimePast::MAX.to_u32();
                let t = u.int_in_range(min..=max)?;
                Ok(MedianTimePast::from_u32(t).unwrap())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "serde")]
    use internals::serde_round_trip;

    use super::*;

    #[test]
    fn time_from_str_hex_happy_path() {
        let actual = MedianTimePast::from_hex("0x6289C350").unwrap();
        let expected = MedianTimePast::from_u32(0x6289_C350).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn time_from_str_hex_no_prefix_happy_path() {
        let time = MedianTimePast::from_hex("6289C350").unwrap();
        assert_eq!(time, MedianTimePast(0x6289_C350));
    }

    #[test]
    fn time_from_str_hex_invalid_hex_should_err() {
        let hex = "0xzb93";
        let result = MedianTimePast::from_hex(hex);
        assert!(result.is_err());
    }

    #[test]
    fn height_from_str_hex_happy_path() {
        let actual = Height::from_hex("0xBA70D").unwrap();
        let expected = Height(0xBA70D);
        assert_eq!(actual, expected);
    }

    #[test]
    fn height_from_str_hex_no_prefix_happy_path() {
        let height = Height::from_hex("BA70D").unwrap();
        assert_eq!(height, Height(0xBA70D));
    }

    #[test]
    fn height_from_str_hex_invalid_hex_should_err() {
        let hex = "0xzb93";
        let result = Height::from_hex(hex);
        assert!(result.is_err());
    }

    #[test]
    fn is_block_height_or_time() {
        assert!(is_block_height(499_999_999));
        assert!(!is_block_height(500_000_000));

        assert!(!is_block_time(499_999_999));
        assert!(is_block_time(500_000_000));
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
        serde_round_trip!(MedianTimePast::MIN);
        serde_round_trip!(MedianTimePast::MAX);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn locktime_unit_display() {
        use alloc::format;
        let blocks = LockTimeUnit::Blocks;
        let seconds = LockTimeUnit::Seconds;

        assert_eq!(format!("{}", blocks), "expected lock-by-height (must be < 500000000)");
        assert_eq!(format!("{}", seconds), "expected lock-by-time (must be >= 500000000)");
    }

    #[test]
    fn valid_chain_computes_mtp() {
        use crate::BlockTime;

        let mut timestamps = [
            BlockTime::from_u32(500_000_010),
            BlockTime::from_u32(500_000_003),
            BlockTime::from_u32(500_000_005),
            BlockTime::from_u32(500_000_008),
            BlockTime::from_u32(500_000_001),
            BlockTime::from_u32(500_000_004),
            BlockTime::from_u32(500_000_006),
            BlockTime::from_u32(500_000_009),
            BlockTime::from_u32(500_000_002),
            BlockTime::from_u32(500_000_007),
            BlockTime::from_u32(500_000_000),
        ];

        // Try various reorderings
        assert_eq!(MedianTimePast::new(timestamps).unwrap().to_u32(), 500_000_005);
        timestamps.reverse();
        assert_eq!(MedianTimePast::new(timestamps).unwrap().to_u32(), 500_000_005);
        timestamps.sort();
        assert_eq!(MedianTimePast::new(timestamps).unwrap().to_u32(), 500_000_005);
        timestamps.reverse();
        assert_eq!(MedianTimePast::new(timestamps).unwrap().to_u32(), 500_000_005);
    }
}
