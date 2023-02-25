// Rust Bitcoin Library - Written by the rust-bitcoin developers.
// SPDX-License-Identifier: CC0-1.0

//! Provides type [`LockTime`] that implements the logic around nLockTime/OP_CHECKLOCKTIMEVERIFY.
//!
//! There are two types of lock time: lock-by-blockheight and lock-by-blocktime, distinguished by
//! whether `LockTime < LOCKTIME_THRESHOLD`.
//!

use core::{mem, fmt};
use core::cmp::{PartialOrd, Ordering};

use bitcoin_internals::write_err;

#[cfg(all(test, mutate))]
use mutagen::mutate;

use crate::consensus::encode::{self, Decodable, Encodable};
use crate::error::ParseIntError;
use crate::io::{self, Read, Write};
use crate::parse::{impl_parse_str_from_int_infallible, impl_parse_str_from_int_fallible};
use crate::prelude::*;
use crate::string::FromHexStr;

#[cfg(doc)]
use crate::absolute;

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

/// An absolute lock time value, representing either a block height or a UNIX timestamp (seconds
/// since epoch).
///
/// Used for transaction lock time (`nLockTime` in Bitcoin Core and [`crate::Transaction::lock_time`]
/// in this library) and also for the argument to opcode 'OP_CHECKLOCKTIMEVERIFY`.
///
/// ### Note on ordering
///
/// Because locktimes may be height- or time-based, and these metrics are incommensurate, there
/// is no total ordering on locktimes. We therefore have implemented [`PartialOrd`] but not [`Ord`].
/// For [`crate::Transaction`], which has a locktime field, we implement a total ordering to make
/// it easy to store transactions in sorted data structures, and use the locktime's 32-bit integer
/// consensus encoding to order it.
///
/// ### Relevant BIPs
///
/// * [BIP-65 OP_CHECKLOCKTIMEVERIFY](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki)
/// * [BIP-113 Median time-past as endpoint for lock-time calculations](https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki)
///
/// # Examples
/// ```
/// # use bitcoin::absolute::{LockTime, LockTime::*};
/// # let n = LockTime::from_consensus(741521);          // n OP_CHECKLOCKTIMEVERIFY
/// # let lock_time = LockTime::from_consensus(741521);  // nLockTime
/// // To compare absolute lock times there are various `is_satisfied_*` methods, you may also use:
/// let is_satisfied = match (n, lock_time) {
///     (Blocks(n), Blocks(lock_time)) => n <= lock_time,
///     (Seconds(n), Seconds(lock_time)) => n <= lock_time,
///     _ => panic!("handle invalid comparison error"),
/// };
/// ```
#[allow(clippy::derive_ord_xor_partial_ord)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockTime {
    /// A block height lock time value.
    ///
    /// # Examples
    /// ```rust
    /// use bitcoin::absolute::LockTime;
    ///
    /// let block: u32 = 741521;
    /// let n = LockTime::from_height(block).expect("valid height");
    /// assert!(n.is_block_height());
    /// assert_eq!(n.to_consensus_u32(), block);
    /// ```
    Blocks(Height),
    /// A UNIX timestamp lock time value.
    ///
    /// # Examples
    /// ```rust
    /// use bitcoin::absolute::LockTime;
    ///
    /// let seconds: u32 = 1653195600; // May 22nd, 5am UTC.
    /// let n = LockTime::from_time(seconds).expect("valid time");
    /// assert!(n.is_block_time());
    /// assert_eq!(n.to_consensus_u32(), seconds);
    /// ```
    Seconds(Time),
}

impl LockTime {
    /// If [`crate::Transaction::lock_time`] is set to zero it is ignored, in other words a
    /// transaction with nLocktime==0 is able to be included immediately in any block.
    pub const ZERO: LockTime = LockTime::Blocks(Height::ZERO);

    /// Constructs a `LockTime` from an nLockTime value or the argument to OP_CHEKCLOCKTIMEVERIFY.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin::absolute::LockTime;
    /// # let n = LockTime::from_consensus(741521); // n OP_CHECKLOCKTIMEVERIFY
    ///
    /// // `from_consensus` roundtrips as expected with `to_consensus_u32`.
    /// let n_lock_time: u32 = 741521;
    /// let lock_time = LockTime::from_consensus(n_lock_time);
    /// assert_eq!(lock_time.to_consensus_u32(), n_lock_time);
    #[inline]
    pub fn from_consensus(n: u32) -> Self {
        if is_block_height(n) {
            Self::Blocks(Height::from_consensus(n).expect("n is valid"))
        } else {
            Self::Seconds(Time::from_consensus(n).expect("n is valid"))
        }
    }

    /// Constructs a `LockTime` from `n`, expecting `n` to be a valid block height.
    ///
    /// See [`LOCK_TIME_THRESHOLD`] for definition of a valid height value.
    ///
    /// # Examples
    /// ```rust
    /// # use bitcoin::absolute::LockTime;
    /// assert!(LockTime::from_height(741521).is_ok());
    /// assert!(LockTime::from_height(1653195600).is_err());
    /// ```
    #[inline]
    pub fn from_height(n: u32) -> Result<Self, Error> {
        let height = Height::from_consensus(n)?;
        Ok(LockTime::Blocks(height))
    }

    /// Constructs a `LockTime` from `n`, expecting `n` to be a valid block time.
    ///
    /// See [`LOCK_TIME_THRESHOLD`] for definition of a valid time value.
    ///
    /// # Examples
    /// ```rust
    /// # use bitcoin::absolute::LockTime;
    /// assert!(LockTime::from_time(1653195600).is_ok());
    /// assert!(LockTime::from_time(741521).is_err());
    /// ```
    #[inline]
    pub fn from_time(n: u32) -> Result<Self, Error> {
        let time = Time::from_consensus(n)?;
        Ok(LockTime::Seconds(time))
    }

    /// Returns true if both lock times use the same unit i.e., both height based or both time based.
    #[inline]
    pub fn is_same_unit(&self, other: LockTime) -> bool {
        mem::discriminant(self) == mem::discriminant(&other)
    }

    /// Returns true if this lock time value is a block height.
    #[inline]
    pub fn is_block_height(&self) -> bool {
        match *self {
            LockTime::Blocks(_) => true,
            LockTime::Seconds(_) => false,
        }
    }

    /// Returns true if this lock time value is a block time (UNIX timestamp).
    #[inline]
    pub fn is_block_time(&self) -> bool {
        !self.is_block_height()
    }

    /// Returns true if this timelock constraint is satisfied by the respective `height`/`time`.
    ///
    /// If `self` is a blockheight based lock then it is checked against `height` and if `self` is a
    /// blocktime based lock it is checked against `time`.
    ///
    /// A 'timelock constraint' refers to the `n` from `n OP_CHEKCLOCKTIMEVERIFY`, this constraint
    /// is satisfied if a transaction with nLockTime ([`crate::Transaction::lock_time`]) set to
    /// `height`/`time` is valid.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoin::absolute::{LockTime, Height, Time};
    /// // Can be implemented if block chain data is available.
    /// fn get_height() -> Height { todo!("return the current block height") }
    /// fn get_time() -> Time { todo!("return the current block time") }
    ///
    /// let n = LockTime::from_consensus(741521); // `n OP_CHEKCLOCKTIMEVERIFY`.
    /// if n.is_satisfied_by(get_height(), get_time()) {
    ///     // Can create and mine a transaction that satisfies the OP_CLTV timelock constraint.
    /// }
    /// ````
    #[inline]
    #[cfg_attr(all(test, mutate), mutate)]
    pub fn is_satisfied_by(&self, height: Height, time: Time) -> bool {
        use LockTime::*;

        match *self {
            Blocks(n) => n <= height,
            Seconds(n) => n <= time,
        }
    }

    /// Returns true if satisfaction of `other` lock time implies satisfaction of this
    /// [`absolute::LockTime`].
    ///
    /// A lock time can only be satisfied by n blocks being mined or n seconds passing. If you have
    /// two lock times (same unit) then the larger lock time being satisfied implies (in a
    /// mathematical sense) the smaller one being satisfied.
    ///
    /// This function is useful if you wish to check a lock time against various other locks e.g.,
    /// filtering out locks which cannot be satisfied. Can also be used to remove the smaller value
    /// of two `OP_CHECKLOCKTIMEVERIFY` operations within one branch of the script.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin::absolute::{LockTime, LockTime::*};
    /// let lock_time = LockTime::from_consensus(741521);
    /// let check = LockTime::from_consensus(741521 + 1);
    /// assert!(lock_time.is_implied_by(check));
    /// ```
    #[inline]
    #[cfg_attr(all(test, mutate), mutate)]
    pub fn is_implied_by(&self, other: LockTime) -> bool {
        use LockTime::*;

        match (*self, other) {
            (Blocks(this), Blocks(other)) => this <= other,
            (Seconds(this), Seconds(other)) => this <= other,
            _ => false, // Not the same units.
        }
    }

    /// Returns the inner `u32` value. This is the value used when creating this `LockTime`
    /// i.e., `n OP_CHECKLOCKTIMEVERIFY` or nLockTime.
    ///
    /// # Warning
    ///
    /// Do not compare values return by this method. The whole point of the `LockTime` type is to
    /// assist in doing correct comparisons. Either use `is_satisfied_by`, `is_satisfied_by_lock`,
    /// or use the pattern below:
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin::absolute::{LockTime, LockTime::*};
    /// # let n = LockTime::from_consensus(741521);              // n OP_CHECKLOCKTIMEVERIFY
    /// # let lock_time = LockTime::from_consensus(741521 + 1);  // nLockTime
    ///
    /// let is_satisfied = match (n, lock_time) {
    ///     (Blocks(n), Blocks(lock_time)) => n <= lock_time,
    ///     (Seconds(n), Seconds(lock_time)) => n <= lock_time,
    ///     _ => panic!("invalid comparison"),
    /// };
    ///
    /// // Or, if you have Rust 1.53 or greater
    /// // let is_satisfied = n.partial_cmp(&lock_time).expect("invalid comparison").is_le();
    /// ```
    #[inline]
    pub fn to_consensus_u32(self) -> u32 {
        match self {
            LockTime::Blocks(ref h) => h.to_consensus_u32(),
            LockTime::Seconds(ref t) => t.to_consensus_u32(),
        }
    }
}

impl_parse_str_from_int_infallible!(LockTime, u32, from_consensus);

impl From<Height> for LockTime {
    #[inline]
    fn from(h: Height) -> Self {
        LockTime::Blocks(h)
    }
}

impl From<Time> for LockTime {
    #[inline]
    fn from(t: Time) -> Self {
        LockTime::Seconds(t)
    }
}

impl PartialOrd for LockTime {
    #[inline]
    fn partial_cmp(&self, other: &LockTime) -> Option<Ordering> {
        use LockTime::*;

        match (*self, *other) {
            (Blocks(ref a), Blocks(ref b)) => a.partial_cmp(b),
            (Seconds(ref a), Seconds(ref b)) => a.partial_cmp(b),
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
                Seconds(ref t) => write!(f, "block-time {} (seconds since epoch)", t),
            }
        } else {
            match *self {
                Blocks(ref h) => fmt::Display::fmt(h, f),
                Seconds(ref t) => fmt::Display::fmt(t, f),
            }
        }
    }
}

impl FromHexStr for LockTime {
    type Error = Error;

    #[inline]
    fn from_hex_str_no_prefix<S: AsRef<str> + Into<String>>(s: S) -> Result<Self, Self::Error> {
        let packed_lock_time = crate::parse::hex_u32(s)?;
        Ok(Self::from_consensus(packed_lock_time))
    }
}

impl Encodable for LockTime {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let v = self.to_consensus_u32();
        v.consensus_encode(w)
    }
}

impl Decodable for LockTime {
    #[inline]
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        u32::consensus_decode(r).map(LockTime::from_consensus)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for LockTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(self.to_consensus_u32())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for LockTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = u32;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("a u32") }
            // We cannot just implement visit_u32 because JSON (among other things) always
            // calls visit_u64, even when called from Deserializer::deserialize_u32. The
            // other visit_u*s have default implementations that forward to visit_u64.
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<u32, E> {
                use core::convert::TryInto;
                v.try_into().map_err(|_| E::invalid_value(serde::de::Unexpected::Unsigned(v), &"a 32-bit number"))
            }
            // Also do the signed version, just for good measure.
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<u32, E> {
                use core::convert::TryInto;
                v.try_into().map_err(|_| E::invalid_value(serde::de::Unexpected::Signed(v), &"a 32-bit number"))
            }
        }
        deserializer.deserialize_u32(Visitor).map(LockTime::from_consensus)
    }
}


/// An absolute block height, guaranteed to always contain a valid height value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Height(u32);

impl Height {
    /// Absolute block height 0, the genesis block.
    pub const ZERO: Self = Height(0);

    /// The minimum absolute block height (0), the genesis block.
    pub const MIN: Self = Self::ZERO;

    /// The maximum absolute block height.
    pub const MAX: Self = Height(LOCK_TIME_THRESHOLD - 1);

    /// The minimum absolute block height (0), the genesis block.
    ///
    /// This is provided for consistency with Rust 1.41.1, newer code should use [`Height::MIN`].
    pub const fn min_value() -> Self { Self::MIN }

    /// The maximum absolute block height.
    ///
    /// This is provided for consistency with Rust 1.41.1, newer code should use [`Height::MAX`].
    pub const fn max_value() -> Self { Self::MAX }

    /// Constructs a new block height.
    ///
    /// # Errors
    ///
    /// If `n` does not represent a block height value (see documentation on [`LockTime`]).
    ///
    /// # Examples
    /// ```rust
    /// use bitcoin::locktime::absolute::Height;
    ///
    /// let h: u32 = 741521;
    /// let height = Height::from_consensus(h).expect("invalid height value");
    /// assert_eq!(height.to_consensus_u32(), h);
    /// ```
    #[inline]
    pub fn from_consensus(n: u32) -> Result<Height, Error> {
        if is_block_height(n) {
            Ok(Self(n))
        } else {
            Err(ConversionError::invalid_height(n).into())
        }
    }

    /// Converts this `Height` to its inner `u32` value.
    ///
    /// # Examples
    /// ```rust
    /// use bitcoin::absolute::LockTime;
    ///
    /// let n_lock_time: u32 = 741521;
    /// let lock_time = LockTime::from_consensus(n_lock_time);
    /// assert!(lock_time.is_block_height());
    /// assert_eq!(lock_time.to_consensus_u32(), n_lock_time);
    #[inline]
    pub fn to_consensus_u32(self) -> u32 {
        self.0
    }
}

impl_parse_str_from_int_fallible!(Height, u32, from_consensus, Error);

impl fmt::Display for Height {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromHexStr for Height {
    type Error = Error;

    #[inline]
    fn from_hex_str_no_prefix<S: AsRef<str> + Into<String>>(s: S) -> Result<Self, Self::Error> {
        let height = crate::parse::hex_u32(s)?;
        Self::from_consensus(height)
    }
}

/// A UNIX timestamp, seconds since epoch, guaranteed to always contain a valid time value.
///
/// Note that there is no manipulation of the inner value during construction or when using
/// `to_consensus_u32()`. Said another way, `Time(x)` means 'x seconds since epoch' _not_ '(x -
/// threshold) seconds since epoch'.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Time(u32);

impl Time {
    /// The minimum absolute block time (Tue Nov 05 1985 00:53:20 GMT+0000).
    pub const MIN: Self = Time(LOCK_TIME_THRESHOLD);

    /// The maximum absolute block time (Sun Feb 07 2106 06:28:15 GMT+0000).
    pub const MAX: Self = Time(u32::max_value());

    /// The minimum absolute block time.
    ///
    /// This is provided for consistency with Rust 1.41.1, newer code should use [`Time::MIN`].
    pub const fn min_value() -> Self { Self::MIN }

    /// The maximum absolute block time.
    ///
    /// This is provided for consistency with Rust 1.41.1, newer code should use [`Time::MAX`].
    pub const fn max_value() -> Self { Self::MAX }

    /// Constructs a new block time.
    ///
    /// # Errors
    ///
    /// If `n` does not encode a UNIX time stamp (see documentation on [`LockTime`]).
    ///
    /// # Examples
    /// ```rust
    /// use bitcoin::locktime::absolute::Time;
    ///
    /// let t: u32 = 1653195600; // May 22nd, 5am UTC.
    /// let time = Time::from_consensus(t).expect("invalid time value");
    /// assert_eq!(time.to_consensus_u32(), t);
    /// ```
    #[inline]
    pub fn from_consensus(n: u32) -> Result<Time, Error> {
        if is_block_time(n) {
            Ok(Self(n))
        } else {
            Err(ConversionError::invalid_time(n).into())
        }
    }

    /// Converts this `Time` to its inner `u32` value.
    ///
    /// # Examples
    /// ```rust
    /// use bitcoin::absolute::LockTime;
    ///
    /// let n_lock_time: u32 = 1653195600; // May 22nd, 5am UTC.
    /// let lock_time = LockTime::from_consensus(n_lock_time);
    /// assert_eq!(lock_time.to_consensus_u32(), n_lock_time);
    /// ```
    #[inline]
    pub fn to_consensus_u32(self) -> u32 {
        self.0
    }
}

impl_parse_str_from_int_fallible!(Time, u32, from_consensus, Error);

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromHexStr for Time {
    type Error = Error;

    #[inline]
    fn from_hex_str_no_prefix<S: AsRef<str> + Into<String>>(s: S) -> Result<Self, Self::Error> {
        let time = crate::parse::hex_u32(s)?;
        Time::from_consensus(time)
    }
}

/// Returns true if `n` is a block height i.e., less than 500,000,000.
fn is_block_height(n: u32) -> bool {
    n < LOCK_TIME_THRESHOLD
}

/// Returns true if `n` is a UNIX timestamp i.e., greater than or equal to 500,000,000.
fn is_block_time(n: u32) -> bool {
    n >= LOCK_TIME_THRESHOLD
}

/// Catchall type for errors that relate to time locks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An error occurred while converting a `u32` to a lock time variant.
    Conversion(ConversionError),
    /// An error occurred while operating on lock times.
    Operation(OperationError),
    /// An error occurred while parsing a string into an `u32`.
    Parse(ParseIntError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            Conversion(ref e) => write_err!(f, "error converting lock time value"; e),
            Operation(ref e) => write_err!(f, "error during lock time operation"; e),
            Parse(ref e) => write_err!(f, "failed to parse lock time from string"; e),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match *self {
            Conversion(ref e) => Some(e),
            Operation(ref e) => Some(e),
            Parse(ref e) => Some(e),
        }
    }
}

impl From<ConversionError> for Error {
    #[inline]
    fn from(e: ConversionError) -> Self {
        Error::Conversion(e)
    }
}

impl From<OperationError> for Error {
    #[inline]
    fn from(e: OperationError) -> Self {
        Error::Operation(e)
    }
}

impl From<ParseIntError> for Error {
    #[inline]
    fn from(e: ParseIntError) -> Self {
        Error::Parse(e)
    }
}

/// An error that occurs when converting a `u32` to a lock time variant.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ConversionError {
    /// The expected timelock unit, height (blocks) or time (seconds).
    unit: LockTimeUnit,
    /// The invalid input value.
    input: u32,
}

impl ConversionError {
    /// Constructs a `ConversionError` from an invalid `n` when expecting a height value.
    fn invalid_height(n: u32) -> Self {
        Self {
            unit: LockTimeUnit::Blocks,
            input: n,
        }
    }

    /// Constructs a `ConversionError` from an invalid `n` when expecting a time value.
    fn invalid_time(n: u32) -> Self {
        Self {
            unit: LockTimeUnit::Seconds,
            input: n,
        }
    }
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid lock time value {}, {}", self.input, self.unit)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for ConversionError {}

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

/// Errors than occur when operating on lock times.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum OperationError {
    /// Cannot compare different lock time units (height vs time).
    InvalidComparison,
}

impl fmt::Display for OperationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::OperationError::*;

        match *self {
            InvalidComparison => f.write_str("cannot compare different lock units (height vs time)"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for OperationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_alternate() {
        let n = LockTime::from_consensus(741521);
        let s = format!("{}", n);
        assert_eq!(&s, "741521");

        let got = format!("{:#}", n);
        assert_eq!(got, "block-height 741521");
    }

    #[test]
    fn time_from_str_hex_happy_path() {
        let actual = Time::from_hex_str("0x6289C350").unwrap();
        let expected = Time::from_consensus(0x6289C350).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn time_from_str_hex_no_prefix_happy_path() {
        let time = Time::from_hex_str_no_prefix("6289C350").unwrap();
        assert_eq!(time, Time(0x6289C350));
    }

    #[test]
    fn time_from_str_hex_invalid_hex_should_err() {
        let hex = "0xzb93";
        let result = Time::from_hex_str(hex);
        assert!(result.is_err());
    }

    #[test]
    fn packed_lock_time_from_str_hex_happy_path() {
        let actual = LockTime::from_hex_str("0xBA70D").unwrap();
        let expected = LockTime::from_consensus(0xBA70D);
        assert_eq!(actual, expected);
    }

    #[test]
    fn packed_lock_time_from_str_hex_no_prefix_happy_path() {
        let lock_time = LockTime::from_hex_str_no_prefix("BA70D").unwrap();
        assert_eq!(lock_time, LockTime::from_consensus(0xBA70D));
    }

    #[test]
    fn packed_lock_time_from_str_hex_invalid_hex_should_ergr() {
        let hex = "0xzb93";
        let result = LockTime::from_hex_str(hex);
        assert!(result.is_err());
    }

    #[test]
    fn height_from_str_hex_happy_path() {
        let actual = Height::from_hex_str("0xBA70D").unwrap();
        let expected = Height(0xBA70D);
        assert_eq!(actual, expected);
    }

    #[test]
    fn height_from_str_hex_no_prefix_happy_path() {
        let height = Height::from_hex_str_no_prefix("BA70D").unwrap();
        assert_eq!(height, Height(0xBA70D));
    }

    #[test]
    fn height_from_str_hex_invalid_hex_should_err() {
        let hex = "0xzb93";
        let result = Height::from_hex_str(hex);
        assert!(result.is_err());
    }

    #[test]
    fn parses_correctly_to_height_or_time() {
        let lock = LockTime::from_consensus(750_000);

        assert!(lock.is_block_height());
        assert!(!lock.is_block_time());

        let t: u32 = 1653195600; // May 22nd, 5am UTC.
        let lock = LockTime::from_consensus(t);

        assert!(!lock.is_block_height());
        assert!(lock.is_block_time());
    }

    #[test]
    fn satisfied_by_height() {
        let lock = LockTime::from_consensus(750_000);

        let height = Height::from_consensus(800_000).expect("failed to parse height");

        let t: u32 = 1653195600; // May 22nd, 5am UTC.
        let time = Time::from_consensus(t).expect("invalid time value");

        assert!(lock.is_satisfied_by(height, time))
    }

    #[test]
    fn satisfied_by_time() {
        let lock = LockTime::from_consensus(1053195600);

        let t: u32 = 1653195600; // May 22nd, 5am UTC.
        let time = Time::from_consensus(t).expect("invalid time value");

        let height = Height::from_consensus(800_000).expect("failed to parse height");

        assert!(lock.is_satisfied_by(height, time))
    }

    #[test]
    fn satisfied_by_same_height() {
        let h = 750_000;
        let lock = LockTime::from_consensus(h);
        let height = Height::from_consensus(h).expect("failed to parse height");

        let t: u32 = 1653195600; // May 22nd, 5am UTC.
        let time = Time::from_consensus(t).expect("invalid time value");

        assert!(lock.is_satisfied_by(height, time))
    }

    #[test]
    fn satisfied_by_same_time() {
        let t: u32 = 1653195600; // May 22nd, 5am UTC.
        let lock = LockTime::from_consensus(t);
        let time = Time::from_consensus(t).expect("invalid time value");

        let height = Height::from_consensus(800_000).expect("failed to parse height");

        assert!(lock.is_satisfied_by(height, time))
    }

    #[test]
    fn height_correctly_implies() {
        let lock = LockTime::from_consensus(750_005);

        assert!(!lock.is_implied_by(LockTime::from_consensus(750_004)));
        assert!(lock.is_implied_by(LockTime::from_consensus(750_005)));
        assert!(lock.is_implied_by(LockTime::from_consensus(750_006)));
   }

    #[test]
    fn time_correctly_implies() {
        let t: u32 = 1700000005;
        let lock = LockTime::from_consensus(t);

        assert!(!lock.is_implied_by(LockTime::from_consensus(1700000004)));
        assert!(lock.is_implied_by(LockTime::from_consensus(1700000005)));
        assert!(lock.is_implied_by(LockTime::from_consensus(1700000006)));
   }

    #[test]
    fn incorrect_units_do_not_imply() {
        let lock = LockTime::from_consensus(750_005);
        assert!(!lock.is_implied_by(LockTime::from_consensus(1700000004)));
    }
}
