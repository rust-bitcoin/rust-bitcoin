// SPDX-License-Identifier: CC0-1.0

//! Provides type [`LockTime`] that implements the logic around `nLockTime`/`OP_CHECKLOCKTIMEVERIFY`.
//!
//! There are two types of lock time: lock-by-height and lock-by-time, distinguished by
//! whether `LockTime < LOCKTIME_THRESHOLD`. To support these we provide the [`Height`] and
//! [`MedianTimePast`] types.

pub mod error;

use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use internals::error::InputString;

use self::error::ParseError;
#[cfg(doc)]
use crate::absolute;
use crate::parse_int::{self, PrefixedHexError, UnprefixedHexError};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(no_inline)]
pub use self::error::{
    ConversionError, IncompatibleHeightError, IncompatibleTimeError, ParseHeightError, ParseTimeError,
};
#[cfg(feature = "encoding")]
pub use self::error::LockTimeDecoderError;

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
/// Used for transaction lock time (`nLockTime` in Bitcoin Core and `Transaction::lock_time`
/// in `rust-bitcoin`) and also for the argument to opcode `OP_CHECKLOCKTIMEVERIFY`.
///
/// # Note on ordering
///
/// Locktimes may be height- or time-based, and these metrics are incommensurate; there is no total
/// ordering on locktimes. In order to compare locktimes, instead of using `<` or `>` we provide the
/// [`LockTime::is_satisfied_by`] API.
///
/// For transaction, which has a locktime field, we implement a total ordering to make
/// it easy to store transactions in sorted data structures, and use the locktime's 32-bit integer
/// consensus encoding to order it.
///
/// # Relevant BIPs
///
/// * [BIP-0065 OP_CHECKLOCKTIMEVERIFY](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki)
/// * [BIP-0113 Median time-past as endpoint for lock-time calculations](https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki)
///
/// # Examples
///
/// ```
/// use bitcoin_units::absolute::{self, LockTime as L};
/// # let n = absolute::LockTime::from_consensus(741521);          // n OP_CHECKLOCKTIMEVERIFY
/// # let lock_time = absolute::LockTime::from_consensus(741521);  // nLockTime
/// // To compare absolute lock times there are various `is_satisfied_*` methods, you may also use:
/// let _is_satisfied = match (n, lock_time) {
///     (L::Blocks(n), L::Blocks(lock_time)) => n <= lock_time,
///     (L::Seconds(n), L::Seconds(lock_time)) => n <= lock_time,
///     _ => panic!("handle invalid comparison error"),
/// };
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockTime {
    /// A block height lock time value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin_units::absolute;
    ///
    /// let block: u32 = 741521;
    /// let n = absolute::LockTime::from_height(block).expect("valid height");
    /// assert!(n.is_block_height());
    /// assert_eq!(n.to_consensus_u32(), block);
    /// ```
    Blocks(Height),
    /// A UNIX timestamp lock time value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin_units::absolute;
    ///
    /// let seconds: u32 = 1653195600; // May 22nd, 5am UTC.
    /// let n = absolute::LockTime::from_mtp(seconds).expect("valid time");
    /// assert!(n.is_block_time());
    /// assert_eq!(n.to_consensus_u32(), seconds);
    /// ```
    Seconds(MedianTimePast),
}

impl LockTime {
    /// If transaction lock time is set to zero it is ignored, in other words a
    /// transaction with nLocktime==0 is able to be included immediately in any block.
    pub const ZERO: Self = Self::Blocks(Height::ZERO);

    /// The number of bytes that the locktime contributes to the size of a transaction.
    pub const SIZE: usize = 4; // Serialized length of a u32.

    /// Constructs a new `LockTime` from a prefixed hex string.
    ///
    /// # Errors
    ///
    /// If the input string is not a valid hex representation of a locktime or it does not include
    /// the `0x` prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::{absolute, parse_int};
    /// let hex_str = "0x61cf9980"; // Unix timestamp for January 1, 2022
    /// let lock_time = absolute::LockTime::from_hex(hex_str)?;
    /// assert_eq!(lock_time.to_consensus_u32(), 0x61cf9980);
    ///
    /// # Ok::<_, parse_int::PrefixedHexError>(())
    /// ```
    #[inline]
    pub fn from_hex(s: &str) -> Result<Self, PrefixedHexError> {
        let lock_time = parse_int::hex_u32_prefixed(s)?;
        Ok(Self::from_consensus(lock_time))
    }

    /// Constructs a new `LockTime` from an unprefixed hex string.
    ///
    /// # Errors
    ///
    /// If the input string is not a valid hex representation of a locktime or if it includes the
    /// `0x` prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::{absolute, parse_int};
    /// let hex_str = "61cf9980"; // Unix timestamp for January 1, 2022
    /// let lock_time = absolute::LockTime::from_unprefixed_hex(hex_str)?;
    /// assert_eq!(lock_time.to_consensus_u32(), 0x61cf9980);
    ///
    /// # Ok::<_, parse_int::UnprefixedHexError>(())
    /// ```
    #[inline]
    pub fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError> {
        let lock_time = parse_int::hex_u32_unprefixed(s)?;
        Ok(Self::from_consensus(lock_time))
    }

    /// Constructs a new `LockTime` from an `nLockTime` value or the argument to `OP_CHECKLOCKTIMEVERIFY`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin_units::absolute;
    ///
    /// // `from_consensus` roundtrips as expected with `to_consensus_u32`.
    /// let n_lock_time: u32 = 741521;
    /// let lock_time = absolute::LockTime::from_consensus(n_lock_time);
    /// assert_eq!(lock_time.to_consensus_u32(), n_lock_time);
    #[inline]
    #[allow(clippy::missing_panics_doc)]
    pub fn from_consensus(n: u32) -> Self {
        if crate::locktime::absolute::is_block_height(n) {
            Self::Blocks(Height::from_u32(n).expect("n is valid"))
        } else {
            Self::Seconds(MedianTimePast::from_u32(n).expect("n is valid"))
        }
    }

    /// Constructs a new `LockTime` from `n`, expecting `n` to be a valid block height.
    ///
    /// # Note
    ///
    /// If the current block height is `h` and the locktime is set to `h`,
    /// the transaction can be included in block `h+1` or later.
    /// It is possible to broadcast the transaction at block height `h`.
    ///
    /// See [`LOCK_TIME_THRESHOLD`] for definition of a valid height value.
    ///
    /// # Errors
    ///
    /// If `n` does not represent a block height within the valid range for a locktime:
    /// `[0, 499_999_999]`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin_units::absolute;
    /// assert!(absolute::LockTime::from_height(741521).is_ok());
    /// assert!(absolute::LockTime::from_height(1653195600).is_err());
    /// ```
    #[inline]
    pub fn from_height(n: u32) -> Result<Self, ConversionError> {
        let height = Height::from_u32(n)?;
        Ok(Self::Blocks(height))
    }

    #[inline]
    #[deprecated(since = "TBD", note = "use `from_mtp` instead")]
    #[doc(hidden)]
    pub fn from_time(n: u32) -> Result<Self, ConversionError> { Self::from_mtp(n) }

    /// Constructs a new `LockTime` from `n`, expecting `n` to be a median-time-past (MTP)
    /// which is in range for a locktime.
    ///
    /// # Note
    ///
    /// If the locktime is set to an MTP `T`, the transaction can be included in a block only if
    /// the MTP of last recent 11 blocks is greater than `T`.
    ///
    /// It is possible to broadcast the transaction once the MTP is greater than `T`. See BIP-0113.
    ///
    /// [BIP-0113 Median time-past as endpoint for lock-time calculations](https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki)
    ///
    /// See [`LOCK_TIME_THRESHOLD`] for definition of a valid time value.
    ///
    /// # Errors
    ///
    /// If `n` is not in the allowable range of MTPs in a locktime: `[500_000_000, 2^32 - 1]`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin_units::absolute;
    /// assert!(absolute::LockTime::from_mtp(1653195600).is_ok());
    /// assert!(absolute::LockTime::from_mtp(741521).is_err());
    /// ```
    #[inline]
    pub fn from_mtp(n: u32) -> Result<Self, ConversionError> {
        let time = MedianTimePast::from_u32(n)?;
        Ok(Self::Seconds(time))
    }

    /// Returns true if both lock times use the same unit i.e., both height based or both time based.
    #[inline]
    pub const fn is_same_unit(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::Blocks(_), Self::Blocks(_)) | (Self::Seconds(_), Self::Seconds(_))
        )
    }

    /// Returns true if this lock time value is a block height.
    #[inline]
    pub const fn is_block_height(self) -> bool { matches!(self, Self::Blocks(_)) }

    /// Returns true if this lock time value is a block time (UNIX timestamp).
    #[inline]
    pub const fn is_block_time(self) -> bool { !self.is_block_height() }

    /// Returns true if this timelock constraint is satisfied by the respective `height`/`time`.
    ///
    /// If `self` is a blockheight based lock then it is checked against `height` and if `self` is a
    /// blocktime based lock it is checked against `time`.
    ///
    /// A 'timelock constraint' refers to the `n` from `n OP_CHECKLOCKTIMEVERIFY`, this constraint
    /// is satisfied if a transaction with `nLockTime` set to `height`/`time` is valid.
    ///
    /// If `height` and `mtp` represent the current chain tip then a transaction with this
    /// locktime can be broadcast for inclusion in the next block.
    ///
    /// If you do not have, or do not wish to calculate, both parameters consider using:
    ///
    /// * [`is_satisfied_by_height()`](absolute::LockTime::is_satisfied_by_height)
    /// * [`is_satisfied_by_time()`](absolute::LockTime::is_satisfied_by_time)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use bitcoin_units::absolute;
    /// // Can be implemented if block chain data is available.
    /// fn get_height() -> absolute::Height { todo!("return the current block height") }
    /// fn get_time() -> absolute::MedianTimePast { todo!("return the current block MTP") }
    ///
    /// let n = absolute::LockTime::from_consensus(741521); // `n OP_CHECKLOCKTIMEVERIFY`.
    /// if n.is_satisfied_by(get_height(), get_time()) {
    ///     // Can create and mine a transaction that satisfies the OP_CLTV timelock constraint.
    /// }
    /// ````
    #[inline]
    pub fn is_satisfied_by(self, height: Height, mtp: MedianTimePast) -> bool {
        match self {
            Self::Blocks(blocks) => blocks.is_satisfied_by(height),
            Self::Seconds(time) => time.is_satisfied_by(mtp),
        }
    }

    /// Returns true if a transaction with this locktime can be spent in the next block.
    ///
    /// If `height` is the current block height of the chain then a transaction with this locktime
    /// can be broadcast for inclusion in the next block.
    ///
    /// # Errors
    ///
    /// Returns an error if this lock is not lock-by-height.
    #[inline]
    pub fn is_satisfied_by_height(self, height: Height) -> Result<bool, IncompatibleHeightError> {
        match self {
            Self::Blocks(blocks) => Ok(blocks.is_satisfied_by(height)),
            Self::Seconds(time) =>
                Err(IncompatibleHeightError { lock: time, incompatible: height }),
        }
    }

    /// Returns true if a transaction with this locktime can be included in the next block.
    ///
    /// # Errors
    ///
    /// Returns an error if this lock is not lock-by-time.
    #[inline]
    pub fn is_satisfied_by_time(self, mtp: MedianTimePast) -> Result<bool, IncompatibleTimeError> {
        match self {
            Self::Seconds(time) => Ok(time.is_satisfied_by(mtp)),
            Self::Blocks(blocks) => Err(IncompatibleTimeError { lock: blocks, incompatible: mtp }),
        }
    }

    /// Returns true if satisfaction of `other` lock time implies satisfaction of this
    /// [`absolute::LockTime`].
    ///
    /// A lock time can only be satisfied by n blocks being mined or n seconds passing. If you have
    /// two lock times (same unit) then the larger lock time being satisfied implies (in a
    /// mathematical sense) the smaller one being satisfied.
    ///
    /// This function serves multiple purposes:
    ///
    /// * When evaluating `OP_CHECKLOCKTIMEVERIFY` the argument must be less than or equal to the
    ///   transactions nLockTime. If using this function to validate a script `self` is the argument
    ///   to `CLTV` and `other` is the transaction nLockTime.
    ///
    /// * If you wish to check a lock time against various other locks e.g., filtering out locks
    ///   which cannot be satisfied. Can also be used to remove the smaller value of two
    ///   `OP_CHECKLOCKTIMEVERIFY` operations within one branch of the script.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin_units::absolute;
    /// let lock_time = absolute::LockTime::from_consensus(741521);
    /// let check = absolute::LockTime::from_consensus(741521 + 1);
    /// assert!(lock_time.is_implied_by(check));
    /// ```
    #[inline]
    pub fn is_implied_by(self, other: Self) -> bool {
        match (self, other) {
            (Self::Blocks(this), Self::Blocks(other)) => this <= other,
            (Self::Seconds(this), Self::Seconds(other)) => this <= other,
            _ => false, // Not the same units.
        }
    }

    /// Returns the inner `u32` value. This is the value used when creating this `LockTime`
    /// i.e., `n OP_CHECKLOCKTIMEVERIFY` or `nLockTime`.
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
    /// use bitcoin_units::absolute::{self, LockTime as L};
    /// # let n = absolute::LockTime::from_consensus(741521);  // n OP_CHECKLOCKTIMEVERIFY
    /// # let lock_time = absolute::LockTime::from_consensus(741521 + 1);  // nLockTime
    ///
    /// let _is_satisfied = match (n, lock_time) {
    ///     (L::Blocks(n), L::Blocks(lock_time)) => n <= lock_time,
    ///     (L::Seconds(n), L::Seconds(lock_time)) => n <= lock_time,
    ///     _ => panic!("invalid comparison"),
    /// };
    ///
    /// // Or, if you have Rust 1.53 or greater
    /// // let is_satisfied = n.partial_cmp(&lock_time).expect("invalid comparison").is_le();
    /// ```
    #[inline]
    pub fn to_consensus_u32(self) -> u32 {
        match self {
            Self::Blocks(ref h) => h.to_u32(),
            Self::Seconds(ref t) => t.to_u32(),
        }
    }
}

parse_int::impl_parse_str_from_int_infallible!(LockTime, u32, from_consensus);

#[cfg(feature = "encoding")]
encoding::encoder_newtype! {
    /// The encoder for the [`LockTime`] type.
    pub struct LockTimeEncoder(encoding::ArrayEncoder<4>);
}

#[cfg(feature = "encoding")]
impl encoding::Encodable for LockTime {
    type Encoder<'e> = LockTimeEncoder;
    fn encoder(&self) -> Self::Encoder<'_> {
        LockTimeEncoder(encoding::ArrayEncoder::without_length_prefix(
            self.to_consensus_u32().to_le_bytes(),
        ))
    }
}

/// The decoder for the [`LockTime`] type.
#[cfg(feature = "encoding")]
pub struct LockTimeDecoder(encoding::ArrayDecoder<4>);

#[cfg(feature = "encoding")]
impl LockTimeDecoder {
    /// Constructs a new [`LockTime`] decoder.
    pub fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
}

#[cfg(feature = "encoding")]
impl Default for LockTimeDecoder {
    fn default() -> Self { Self::new() }
}

#[cfg(feature = "encoding")]
impl encoding::Decoder for LockTimeDecoder {
    type Output = LockTime;
    type Error = LockTimeDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        Ok(self.0.push_bytes(bytes).map_err(LockTimeDecoderError)?)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let n = u32::from_le_bytes(self.0.end().map_err(LockTimeDecoderError)?);
        Ok(LockTime::from_consensus(n))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "encoding")]
impl encoding::Decodable for LockTime {
    type Decoder = LockTimeDecoder;
    fn decoder() -> Self::Decoder { LockTimeDecoder(encoding::ArrayDecoder::<4>::new()) }
}

impl From<Height> for LockTime {
    #[inline]
    fn from(h: Height) -> Self { Self::Blocks(h) }
}

impl From<MedianTimePast> for LockTime {
    #[inline]
    fn from(t: MedianTimePast) -> Self { Self::Seconds(t) }
}

impl fmt::Debug for LockTime {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Blocks(ref h) => write!(f, "{} blocks", h),
            Self::Seconds(ref t) => write!(f, "{} seconds", t),
        }
    }
}

impl fmt::Display for LockTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            match *self {
                Self::Blocks(ref h) => write!(f, "block-height {}", h),
                Self::Seconds(ref t) => write!(f, "block-time {} (seconds since epoch)", t),
            }
        } else {
            match *self {
                Self::Blocks(ref h) => fmt::Display::fmt(h, f),
                Self::Seconds(ref t) => fmt::Display::fmt(t, f),
            }
        }
    }
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
        u32::deserialize(deserializer).map(Self::from_consensus)
    }
}

/// An absolute block height, guaranteed to always contain a valid height value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Height(u32);

impl Height {
    /// Absolute block height 0, the genesis block.
    pub const ZERO: Self = Self(0);

    /// The minimum absolute block height (0), the genesis block.
    pub const MIN: Self = Self::ZERO;

    /// The maximum absolute block height.
    pub const MAX: Self = Self(LOCK_TIME_THRESHOLD - 1);

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
    /// # Ok::<_, absolute::error::ConversionError>(())
    /// ```
    #[inline]
    pub const fn from_u32(n: u32) -> Result<Self, ConversionError> {
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
    pub fn is_satisfied_by(self, height: Self) -> bool {
        // Use u64 so that there can be no overflow.
        let next_block_height = u64::from(height.to_u32()) + 1;
        u64::from(self.to_u32()) <= next_block_height
    }
}

impl fmt::Display for Height {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

parse_int::impl_parse_str!(Height, ParseHeightError, parser(Height::from_u32));

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
    pub const MIN: Self = Self(LOCK_TIME_THRESHOLD);

    /// The maximum MTP allowable in a locktime (Sun Feb 07 2106 06:28:15 GMT+0000).
    pub const MAX: Self = Self(u32::MAX);

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
    /// # Ok::<_, absolute::error::ConversionError>(())
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
    pub fn is_satisfied_by(self, time: Self) -> bool {
        // The locktime check in Core during block validation uses the MTP
        // of the previous block - which is the expected to be `time` here.
        self <= time
    }
}

impl fmt::Display for MedianTimePast {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

parse_int::impl_parse_str!(MedianTimePast, ParseTimeError, parser(MedianTimePast::from_u32));

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
    let n = i64::from_str_radix(parse_int::hex_remove_optional_prefix(s.as_ref()), 16)
        .map_err(ParseError::invalid_int(s))?;
    let n = u32::try_from(n).map_err(|_| ParseError::Conversion(n))?;
    f(n).map_err(ParseError::from).map_err(Into::into)
}

/// Returns true if `n` is a block height i.e., less than 500,000,000.
pub const fn is_block_height(n: u32) -> bool { n < LOCK_TIME_THRESHOLD }

/// Returns true if `n` is a UNIX timestamp i.e., greater than or equal to 500,000,000.
pub const fn is_block_time(n: u32) -> bool { n >= LOCK_TIME_THRESHOLD }

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for LockTime {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let l = u32::arbitrary(u)?;
        Ok(Self::from_consensus(l))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Height {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;
        match choice {
            0 => Ok(Self::MIN),
            1 => Ok(Self::MAX),
            _ => {
                let min = Self::MIN.to_u32();
                let max = Self::MAX.to_u32();
                let h = u.int_in_range(min..=max)?;
                Ok(Self::from_u32(h).unwrap())
            }
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for MedianTimePast {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;
        match choice {
            0 => Ok(Self::MIN),
            1 => Ok(Self::MAX),
            _ => {
                let min = Self::MIN.to_u32();
                let max = Self::MAX.to_u32();
                let t = u.int_in_range(min..=max)?;
                Ok(Self::from_u32(t).unwrap())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::format;

    use super::*;

    #[test]
    #[cfg(feature = "alloc")]
    fn display_and_alternate() {
        let lock_by_height = LockTime::from_height(741_521).unwrap();
        let lock_by_time = LockTime::from_mtp(1_653_195_600).unwrap(); // May 22nd 2022, 5am UTC.

        assert_eq!(format!("{}", lock_by_height), "741521");
        assert_eq!(format!("{:#}", lock_by_height), "block-height 741521");
        assert!(!format!("{:?}", lock_by_height).is_empty());

        assert_eq!(format!("{}", lock_by_time), "1653195600");
        assert_eq!(format!("{:#}", lock_by_time), "block-time 1653195600 (seconds since epoch)");
        assert!(!format!("{:?}", lock_by_time).is_empty());
    }

    #[test]
    fn roundtrips() {
        let lock_by_height = LockTime::from_consensus(741_521);
        let lock_by_time = LockTime::from_consensus(1_653_195_600);

        assert_eq!(lock_by_height.to_consensus_u32(), 741_521);
        assert_eq!(lock_by_time.to_consensus_u32(), 1_653_195_600);
    }

    #[test]
    fn lock_time_from_hex_lower() {
        let lock_by_time = LockTime::from_hex("0x6289c350").unwrap();
        assert_eq!(lock_by_time, LockTime::from_consensus(0x6289_C350));
    }

    #[test]
    fn lock_time_from_hex_upper() {
        let lock_by_time = LockTime::from_hex("0X6289C350").unwrap();
        assert_eq!(lock_by_time, LockTime::from_consensus(0x6289_C350));
    }

    #[test]
    fn lock_time_from_unprefixed_hex_lower() {
        let lock_by_time = LockTime::from_unprefixed_hex("6289c350").unwrap();
        assert_eq!(lock_by_time, LockTime::from_consensus(0x6289_C350));
    }

    #[test]
    fn lock_time_from_unprefixed_hex_upper() {
        let lock_by_time = LockTime::from_unprefixed_hex("6289C350").unwrap();
        assert_eq!(lock_by_time, LockTime::from_consensus(0x6289_C350));
    }

    #[test]
    fn invalid_hex() {
        assert!(LockTime::from_hex("0xzb93").is_err());
        assert!(LockTime::from_unprefixed_hex("zb93").is_err());
    }

    #[test]
    fn invalid_locktime_type() {
        assert!(LockTime::from_height(499_999_999).is_ok()); // Below the threshold.
        assert!(LockTime::from_height(500_000_000).is_err()); // The threshold.
        assert!(LockTime::from_height(500_000_001).is_err()); // Above the threshold.

        assert!(LockTime::from_mtp(499_999_999).is_err()); // Below the threshold.
        assert!(LockTime::from_mtp(500_000_000).is_ok()); // The threshold.
        assert!(LockTime::from_mtp(500_000_001).is_ok()); // Above the threshold.
    }

    #[test]
    fn parses_correctly_to_height_or_time() {
        let lock_by_height = LockTime::from_consensus(750_000);

        assert!(lock_by_height.is_block_height());
        assert!(!lock_by_height.is_block_time());

        let t: u32 = 1_653_195_600; // May 22nd, 5am UTC.
        let lock_by_time = LockTime::from_consensus(t);

        assert!(!lock_by_time.is_block_height());
        assert!(lock_by_time.is_block_time());

        // Test is_same_unit() logic
        assert!(lock_by_height.is_same_unit(LockTime::from_consensus(800_000)));
        assert!(!lock_by_height.is_same_unit(lock_by_time));
        assert!(lock_by_time.is_same_unit(LockTime::from_consensus(1_653_282_000)));
        assert!(!lock_by_time.is_same_unit(lock_by_height));
    }

    #[test]
    fn satisfied_by_height() {
        let height_below = Height::from_u32(700_000).unwrap();
        let height = Height::from_u32(750_000).unwrap();
        let height_above = Height::from_u32(800_000).unwrap();

        let lock_by_height = LockTime::from(height);

        let t: u32 = 1_653_195_600; // May 22nd, 5am UTC.
        let time = MedianTimePast::from_u32(t).unwrap();

        assert!(!lock_by_height.is_satisfied_by(height_below, time));
        assert!(lock_by_height.is_satisfied_by(height, time));
        assert!(lock_by_height.is_satisfied_by(height_above, time));
    }

    #[test]
    fn satisfied_by_time() {
        let time_before = MedianTimePast::from_u32(1_653_109_200).unwrap(); // "May 21th 2022, 5am UTC.
        let time = MedianTimePast::from_u32(1_653_195_600).unwrap(); // "May 22nd 2022, 5am UTC.
        let time_after = MedianTimePast::from_u32(1_653_282_000).unwrap(); // "May 23rd 2022, 5am UTC.

        let lock_by_time = LockTime::from(time);

        let height = Height::from_u32(800_000).unwrap();

        assert!(!lock_by_time.is_satisfied_by(height, time_before));
        assert!(lock_by_time.is_satisfied_by(height, time));
        assert!(lock_by_time.is_satisfied_by(height, time_after));
    }

    #[test]
    fn height_correctly_implies() {
        let lock_by_height = LockTime::from_consensus(750_005);

        assert!(!lock_by_height.is_implied_by(LockTime::from_consensus(750_004)));
        assert!(lock_by_height.is_implied_by(LockTime::from_consensus(750_005)));
        assert!(lock_by_height.is_implied_by(LockTime::from_consensus(750_006)));
    }

    #[test]
    fn time_correctly_implies() {
        let t: u32 = 1_700_000_005;
        let lock_by_time = LockTime::from_consensus(t);

        assert!(!lock_by_time.is_implied_by(LockTime::from_consensus(1_700_000_004)));
        assert!(lock_by_time.is_implied_by(LockTime::from_consensus(1_700_000_005)));
        assert!(lock_by_time.is_implied_by(LockTime::from_consensus(1_700_000_006)));
    }

    #[test]
    fn incorrect_units_do_not_imply() {
        let lock_by_height = LockTime::from_consensus(750_005);
        assert!(!lock_by_height.is_implied_by(LockTime::from_consensus(1_700_000_004)));
    }

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
