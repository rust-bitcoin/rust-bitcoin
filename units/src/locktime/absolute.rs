// SPDX-License-Identifier: CC0-1.0

//! Provides type `Height` and `Time` types used by the `rust-bitcoin` `absolute::LockTime` type.

#[cfg(feature = "encoding")]
use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use internals::write_err;

use crate::parse::{self, ParseIntError};
#[cfg(feature = "alloc")]
use crate::prelude::*;

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

    /// Creates a `Height` from a hex string.
    ///
    /// The input string is may or may not contain a typical hex prefix e.g., `0x`.
    pub fn from_hex(s: &str) -> Result<Self, ParseHeightError> {
        parse_hex(s, Self::from_consensus)
    }

    /// Constructs a new block height.
    ///
    /// # Errors
    ///
    /// If `n` does not represent a valid block height value.
    ///
    /// # Examples
    /// ```rust
    /// use bitcoin_units::locktime::absolute::Height;
    ///
    /// let h: u32 = 741521;
    /// let height = Height::from_consensus(h).expect("invalid height value");
    /// assert_eq!(height.to_consensus_u32(), h);
    /// ```
    #[inline]
    pub fn from_consensus(n: u32) -> Result<Height, ConversionError> {
        if is_block_height(n) {
            Ok(Self(n))
        } else {
            Err(ConversionError::invalid_height(n))
        }
    }

    /// Converts this `Height` to its inner `u32` value.
    #[inline]
    pub fn to_consensus_u32(self) -> u32 { self.0 }
}

impl fmt::Display for Height {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

/// An error encountered while decoding an absolute locktime [`Height`].
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeightDecoderError {
    /// The encoded bytes ended before a full `u32` was read.
    Eof(encoding::UnexpectedEofError),
    /// The encoded value does not represent a valid absolute height.
    Conversion(ConversionError),
}

#[cfg(feature = "encoding")]
impl From<Infallible> for HeightDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for HeightDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HeightDecoderError::Eof(error) =>
                write_err!(f, "error decoding absolute height"; error),
            HeightDecoderError::Conversion(error) => {
                write_err!(f, "invalid absolute height encoding"; error)
            }
        }
    }
}

#[cfg(all(feature = "std", feature = "encoding"))]
impl std::error::Error for HeightDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HeightDecoderError::Eof(error) => Some(error),
            HeightDecoderError::Conversion(error) => Some(error),
        }
    }
}

#[cfg(feature = "encoding")]
impl encoding::Encodable for Height {
    type Encoder<'e>
        = HeightEncoder
    where
        Self: 'e;

    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        HeightEncoder::new(encoding::ArrayEncoder::without_length_prefix(
            self.to_consensus_u32().to_le_bytes(),
        ))
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decodable for Height {
    type Decoder = HeightDecoder;

    fn decoder() -> Self::Decoder { HeightDecoder::new() }
}

/// The encoder for the absolute [`Height`] type.
#[cfg(feature = "encoding")]
pub struct HeightEncoder(encoding::ArrayEncoder<4>);

#[cfg(feature = "encoding")]
impl HeightEncoder {
    /// Constructs a new absolute [`Height`] encoder.
    pub const fn new(encoder: encoding::ArrayEncoder<4>) -> Self { Self(encoder) }
}

#[cfg(feature = "encoding")]
impl encoding::Encoder for HeightEncoder {
    fn current_chunk(&self) -> &[u8] { self.0.current_chunk() }

    fn advance(&mut self) -> bool { self.0.advance() }
}

/// The decoder for the absolute [`Height`] type.
#[cfg(feature = "encoding")]
pub struct HeightDecoder(encoding::ArrayDecoder<4>);

#[cfg(feature = "encoding")]
impl HeightDecoder {
    /// Constructs a new absolute [`Height`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
}

#[cfg(feature = "encoding")]
impl encoding::Decoder for HeightDecoder {
    type Output = Height;
    type Error = HeightDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(HeightDecoderError::Eof)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.0.end().map_err(HeightDecoderError::Eof)?;
        Height::from_consensus(u32::from_le_bytes(bytes)).map_err(HeightDecoderError::Conversion)
    }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "encoding")]
impl Default for HeightDecoder {
    fn default() -> Self { Self::new() }
}

crate::impl_parse_str!(Height, ParseHeightError, parser(Height::from_consensus));

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
        Ok(Height::from_consensus(u).map_err(serde::de::Error::custom)?)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Height {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_consensus_u32().serialize(serializer)
    }
}

/// A UNIX timestamp, seconds since epoch, guaranteed to always contain a valid time value.
///
/// Note that there is no manipulation of the inner value during construction or when using
/// `to_consensus_u32()`. Said another way, `Time(x)` means 'x seconds since epoch' _not_ '(x -
/// threshold) seconds since epoch'.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time(u32);

impl Time {
    /// The minimum absolute block time (Tue Nov 05 1985 00:53:20 GMT+0000).
    pub const MIN: Self = Time(LOCK_TIME_THRESHOLD);

    /// The maximum absolute block time (Sun Feb 07 2106 06:28:15 GMT+0000).
    pub const MAX: Self = Time(u32::MAX);

    /// Creates a `Time` from a hex string.
    ///
    /// The input string is may or may not contain a typical hex prefix e.g., `0x`.
    pub fn from_hex(s: &str) -> Result<Self, ParseTimeError> { parse_hex(s, Self::from_consensus) }

    /// Constructs a new block time.
    ///
    /// # Errors
    ///
    /// If `n` does not encode a valid UNIX time stamp.
    ///
    /// # Examples
    /// ```rust
    /// use bitcoin_units::locktime::absolute::Time;
    ///
    /// let t: u32 = 1653195600; // May 22nd, 5am UTC.
    /// let time = Time::from_consensus(t).expect("invalid time value");
    /// assert_eq!(time.to_consensus_u32(), t);
    /// ```
    #[inline]
    pub fn from_consensus(n: u32) -> Result<Time, ConversionError> {
        if is_block_time(n) {
            Ok(Self(n))
        } else {
            Err(ConversionError::invalid_time(n))
        }
    }

    /// Converts this `Time` to its inner `u32` value.
    #[inline]
    pub fn to_consensus_u32(self) -> u32 { self.0 }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

/// An error encountered while decoding an absolute locktime [`Time`].
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeDecoderError {
    /// The encoded bytes ended before a full `u32` was read.
    Eof(encoding::UnexpectedEofError),
    /// The encoded value does not represent a valid absolute time.
    Conversion(ConversionError),
}

#[cfg(feature = "encoding")]
impl From<Infallible> for TimeDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for TimeDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TimeDecoderError::Eof(error) => write_err!(f, "error decoding absolute time"; error),
            TimeDecoderError::Conversion(error) => {
                write_err!(f, "invalid absolute time encoding"; error)
            }
        }
    }
}

#[cfg(all(feature = "std", feature = "encoding"))]
impl std::error::Error for TimeDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TimeDecoderError::Eof(error) => Some(error),
            TimeDecoderError::Conversion(error) => Some(error),
        }
    }
}

#[cfg(feature = "encoding")]
impl encoding::Encodable for Time {
    type Encoder<'e>
        = TimeEncoder
    where
        Self: 'e;

    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        TimeEncoder::new(encoding::ArrayEncoder::without_length_prefix(
            self.to_consensus_u32().to_le_bytes(),
        ))
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decodable for Time {
    type Decoder = TimeDecoder;

    fn decoder() -> Self::Decoder { TimeDecoder::new() }
}

/// The encoder for the absolute [`Time`] type.
#[cfg(feature = "encoding")]
pub struct TimeEncoder(encoding::ArrayEncoder<4>);

#[cfg(feature = "encoding")]
impl TimeEncoder {
    /// Constructs a new absolute [`Time`] encoder.
    pub const fn new(encoder: encoding::ArrayEncoder<4>) -> Self { Self(encoder) }
}

#[cfg(feature = "encoding")]
impl encoding::Encoder for TimeEncoder {
    fn current_chunk(&self) -> &[u8] { self.0.current_chunk() }

    fn advance(&mut self) -> bool { self.0.advance() }
}

/// The decoder for the absolute [`Time`] type.
#[cfg(feature = "encoding")]
pub struct TimeDecoder(encoding::ArrayDecoder<4>);

#[cfg(feature = "encoding")]
impl TimeDecoder {
    /// Constructs a new absolute [`Time`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
}

#[cfg(feature = "encoding")]
impl encoding::Decoder for TimeDecoder {
    type Output = Time;
    type Error = TimeDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(TimeDecoderError::Eof)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.0.end().map_err(TimeDecoderError::Eof)?;
        Time::from_consensus(u32::from_le_bytes(bytes)).map_err(TimeDecoderError::Conversion)
    }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "encoding")]
impl Default for TimeDecoder {
    fn default() -> Self { Self::new() }
}

crate::impl_parse_str!(Time, ParseTimeError, parser(Time::from_consensus));

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Time {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let u = u32::deserialize(deserializer)?;
        Ok(Time::from_consensus(u).map_err(serde::de::Error::custom)?)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Time {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_consensus_u32().serialize(serializer)
    }
}

/// Error returned when parsing block time fails.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParseTimeError(ParseError);

impl fmt::Display for ParseTimeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.display(f, "block height", LOCK_TIME_THRESHOLD, u32::MAX)
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
    S: AsRef<str> + Into<String>,
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
    S: AsRef<str> + Into<String>,
    F: FnOnce(u32) -> Result<T, ConversionError>,
{
    let n = i64::from_str_radix(parse::strip_hex_prefix(s.as_ref()), 16)
        .map_err(ParseError::invalid_int(s))?;
    let n = u32::try_from(n).map_err(|_| ParseError::Conversion(n))?;
    f(n).map_err(ParseError::from).map_err(Into::into)
}

/// Returns true if `n` is a block height i.e., less than 500,000,000.
pub fn is_block_height(n: u32) -> bool { n < LOCK_TIME_THRESHOLD }

/// Returns true if `n` is a UNIX timestamp i.e., greater than or equal to 500,000,000.
pub fn is_block_time(n: u32) -> bool { n >= LOCK_TIME_THRESHOLD }

/// An error that occurs when converting a `u32` to a lock time variant.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConversionError {
    /// The expected timelock unit, height (blocks) or time (seconds).
    unit: LockTimeUnit,
    /// The invalid input value.
    input: u32,
}

impl ConversionError {
    /// Constructs a `ConversionError` from an invalid `n` when expecting a height value.
    fn invalid_height(n: u32) -> Self { Self { unit: LockTimeUnit::Blocks, input: n } }

    /// Constructs a `ConversionError` from an invalid `n` when expecting a time value.
    fn invalid_time(n: u32) -> Self { Self { unit: LockTimeUnit::Seconds, input: n } }
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

/// Describes the two types of locking, lock-by-blockheight and lock-by-blocktime.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
enum LockTimeUnit {
    /// Lock by blockheight.
    Blocks,
    /// Lock by blocktime.
    Seconds,
}

impl fmt::Display for LockTimeUnit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use LockTimeUnit::*;

        match *self {
            Blocks => write!(f, "expected lock-by-blockheight (must be < {})", LOCK_TIME_THRESHOLD),
            Seconds => write!(f, "expected lock-by-blocktime (must be >= {})", LOCK_TIME_THRESHOLD),
        }
    }
}

/// Internal - common representation for height and time.
#[derive(Debug, Clone, Eq, PartialEq)]
enum ParseError {
    InvalidInteger { source: core::num::ParseIntError, input: String },
    // unit implied by outer type
    // we use i64 to have nicer messages for negative values
    Conversion(i64),
}

internals::impl_from_infallible!(ParseError);

impl ParseError {
    fn invalid_int<S: Into<String>>(s: S) -> impl FnOnce(core::num::ParseIntError) -> Self {
        move |source| Self::InvalidInteger { source, input: s.into() }
    }

    fn display(
        &self,
        f: &mut fmt::Formatter<'_>,
        subject: &str,
        lower_bound: u32,
        upper_bound: u32,
    ) -> fmt::Result {
        use core::num::IntErrorKind;

        use ParseError::*;

        match self {
            InvalidInteger { source, input } if *source.kind() == IntErrorKind::PosOverflow => {
                write!(f, "{} {} is above limit {}", subject, input, upper_bound)
            }
            InvalidInteger { source, input } if *source.kind() == IntErrorKind::NegOverflow => {
                write!(f, "{} {} is below limit {}", subject, input, lower_bound)
            }
            InvalidInteger { source, input } => {
                write_err!(f, "failed to parse {} as {}", input, subject; source)
            }
            Conversion(value) if *value < i64::from(lower_bound) => {
                write!(f, "{} {} is below limit {}", subject, value, lower_bound)
            }
            Conversion(value) => {
                write!(f, "{} {} is above limit {}", subject, value, upper_bound)
            }
        }
    }

    // To be consistent with `write_err` we need to **not** return source in case of overflow
    #[cfg(feature = "std")]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use core::num::IntErrorKind;

        use ParseError::*;

        match self {
            InvalidInteger { source, .. } if *source.kind() == IntErrorKind::PosOverflow => None,
            InvalidInteger { source, .. } if *source.kind() == IntErrorKind::NegOverflow => None,
            InvalidInteger { source, .. } => Some(source),
            Conversion(_) => None,
        }
    }
}

impl From<ParseIntError> for ParseError {
    fn from(value: ParseIntError) -> Self {
        Self::InvalidInteger { source: value.source, input: value.input }
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
                let min = Height::MIN.to_consensus_u32();
                let max = Height::MAX.to_consensus_u32();
                let h = u.int_in_range(min..=max)?;
                Ok(Height::from_consensus(h).unwrap())
            }
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Time {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;
        match choice {
            0 => Ok(Time::MIN),
            1 => Ok(Time::MAX),
            _ => {
                let min = Time::MIN.to_consensus_u32();
                let max = Time::MAX.to_consensus_u32();
                let t = u.int_in_range(min..=max)?;
                Ok(Time::from_consensus(t).unwrap())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_from_str_hex_happy_path() {
        let actual = Time::from_hex("0x6289C350").unwrap();
        let expected = Time::from_consensus(0x6289C350).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn time_from_str_hex_no_prefix_happy_path() {
        let time = Time::from_hex("6289C350").unwrap();
        assert_eq!(time, Time(0x6289C350));
    }

    #[test]
    fn time_from_str_hex_invalid_hex_should_err() {
        let hex = "0xzb93";
        let result = Time::from_hex(hex);
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

    #[cfg(feature = "encoding")]
    #[test]
    fn encode_decode_height_with_consensus_validation() {
        let valid = Height::from_consensus(499_999_999).unwrap();
        let encoded = encoding::encode_to_vec(&valid);
        let decoded = encoding::decode_from_slice::<Height>(&encoded).unwrap();
        assert_eq!(decoded, valid);

        let err = encoding::decode_from_slice::<Height>(&500_000_000u32.to_le_bytes()).unwrap_err();
        assert!(matches!(err, HeightDecoderError::Conversion(_)));
    }

    #[cfg(feature = "encoding")]
    #[test]
    fn encode_decode_time_with_consensus_validation() {
        let valid = Time::from_consensus(500_000_000).unwrap();
        let encoded = encoding::encode_to_vec(&valid);
        let decoded = encoding::decode_from_slice::<Time>(&encoded).unwrap();
        assert_eq!(decoded, valid);

        let err = encoding::decode_from_slice::<Time>(&499_999_999u32.to_le_bytes()).unwrap_err();
        assert!(matches!(err, TimeDecoderError::Conversion(_)));
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
        serde_round_trip!(Time::MIN);
        serde_round_trip!(Time::MAX);
    }
}
