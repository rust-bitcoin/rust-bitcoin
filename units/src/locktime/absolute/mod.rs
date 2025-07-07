// SPDX-License-Identifier: CC0-1.0

//! Provides [`Height`] and [`MedianTimePast`] types used by the `rust-bitcoin` `absolute::LockTime` type.

pub mod error;

use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use internals::error::InputString;

use self::error::ParseError;
use crate::parse;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(no_inline)]
pub use self::error::{ConversionError, ParseHeightError, ParseTimeError};

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
    /// use bitcoin_units::locktime::absolute;
    ///
    /// let h: u32 = 741521;
    /// let height = absolute::Height::from_u32(h)?;
    /// assert_eq!(height.to_u32(), h);
    /// # Ok::<_, absolute::ConversionError>(())
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
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin_units::locktime::absolute;
    ///
    /// assert_eq!(absolute::Height::MAX.to_u32(), 499_999_999);
    /// ```
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

    /// Constructs an [`MedianTimePast`] by computing the median-time-past from the last
    /// 11 block timestamps.
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
    /// use bitcoin_units::locktime::absolute;
    ///
    /// let t: u32 = 1653195600; // May 22nd, 5am UTC.
    /// let time = absolute::MedianTimePast::from_u32(t)?;
    /// assert_eq!(time.to_u32(), t);
    /// # Ok::<_, absolute::ConversionError>(())
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
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin_units::locktime::absolute;
    ///
    /// assert_eq!(absolute::MedianTimePast::MIN.to_u32(), 500_000_000);
    /// ```
    #[inline]
    pub const fn to_u32(self) -> u32 { self.0 }

    /// Returns true if a transaction with this locktime can be included in the next block.
    ///
    /// `self` is the value of the `LockTime` and if `time` is the median time past of the block at
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

    #[test]
    fn height_is_satisfied_by() {
        let chain_tip = Height::from_u32(100).unwrap();

        // lock is satisfied if transaction can go in the next block (height <= chain_tip + 1).
        let locktime = Height::from_u32(100).unwrap();
        assert!(locktime.is_satisfied_by(chain_tip));
        let locktime = Height::from_u32(101).unwrap();
        assert!(locktime.is_satisfied_by(chain_tip));

        // It is not satisfied if the lock height is after the next block.
        let locktime = Height::from_u32(102).unwrap();
        assert!(!locktime.is_satisfied_by(chain_tip));
    }

    #[test]
    fn median_time_past_is_satisfied_by() {
        let mtp = MedianTimePast::from_u32(500_000_001).unwrap();

        // lock is satisfied if transaction can go in the next block (locktime <= mtp).
        let locktime = MedianTimePast::from_u32(500_000_000).unwrap();
        assert!(locktime.is_satisfied_by(mtp));
        let locktime = MedianTimePast::from_u32(500_000_001).unwrap();
        assert!(locktime.is_satisfied_by(mtp));

        // It is not satisfied if the lock time is after the median time past.
        let locktime = MedianTimePast::from_u32(500_000_002).unwrap();
        assert!(!locktime.is_satisfied_by(mtp));
    }
}
