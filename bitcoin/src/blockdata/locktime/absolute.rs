// SPDX-License-Identifier: CC0-1.0

//! Provides type [`LockTime`] that implements the logic around nLockTime/OP_CHECKLOCKTIMEVERIFY.
//!
//! There are two types of lock time: lock-by-blockheight and lock-by-blocktime, distinguished by
//! whether `LockTime < LOCKTIME_THRESHOLD`.
//!

use core::cmp::Ordering;
use core::fmt;

use io::{BufRead, Write};
#[cfg(all(test, mutate))]
use mutagen::mutate;
use units::parse;

#[cfg(doc)]
use crate::absolute;
use crate::consensus::encode::{self, Decodable, Encodable};
use crate::error::{ContainsPrefixError, MissingPrefixError, PrefixedHexError, UnprefixedHexError};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use units::locktime::absolute::{
    Height, Time, LOCK_TIME_THRESHOLD, ConversionError, ParseHeightError, ParseTimeError,
};

/// An absolute lock time value, representing either a block height or a UNIX timestamp (seconds
/// since epoch).
///
/// Used for transaction lock time (`nLockTime` in Bitcoin Core and [`crate::Transaction::lock_time`]
/// in this library) and also for the argument to opcode 'OP_CHECKLOCKTIMEVERIFY`.
///
/// ### Note on ordering
///
/// Locktimes may be height- or time-based, and these metrics are incommensurate; there is no total
/// ordering on locktimes. We therefore have implemented [`PartialOrd`] but not [`Ord`].
/// For [`crate::Transaction`], which has a locktime field, we implement a total ordering to make
/// it easy to store transactions in sorted data structures, and use the locktime's 32-bit integer
/// consensus encoding to order it. We also implement [`ordered::ArbitraryOrd`] if the "ordered"
/// feature is enabled.
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
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
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

    /// The number of bytes that the locktime contributes to the size of a transaction.
    pub const SIZE: usize = 4; // Serialized length of a u32.

    /// Creates a `LockTime` from an prefixed hex string.
    pub fn from_hex(s: &str) -> Result<Self, PrefixedHexError> {
        let stripped = if let Some(stripped) = s.strip_prefix("0x") {
            stripped
        } else if let Some(stripped) = s.strip_prefix("0X") {
            stripped
        } else {
            return Err(MissingPrefixError::new(s).into());
        };

        let lock_time = parse::hex_u32(stripped)?;
        Ok(Self::from_consensus(lock_time))
    }

    /// Creates a `LockTime` from an unprefixed hex string.
    pub fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError> {
        if s.starts_with("0x") || s.starts_with("0X") {
            return Err(ContainsPrefixError::new(s).into());
        }
        let lock_time = parse::hex_u32(s)?;
        Ok(Self::from_consensus(lock_time))
    }

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
        if units::locktime::absolute::is_block_height(n) {
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
    pub fn from_height(n: u32) -> Result<Self, ConversionError> {
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
    pub fn from_time(n: u32) -> Result<Self, ConversionError> {
        let time = Time::from_consensus(n)?;
        Ok(LockTime::Seconds(time))
    }

    /// Returns true if both lock times use the same unit i.e., both height based or both time based.
    #[inline]
    pub const fn is_same_unit(&self, other: LockTime) -> bool {
        matches!(
            (self, other),
            (LockTime::Blocks(_), LockTime::Blocks(_))
                | (LockTime::Seconds(_), LockTime::Seconds(_))
        )
    }

    /// Returns true if this lock time value is a block height.
    #[inline]
    pub const fn is_block_height(&self) -> bool { matches!(*self, LockTime::Blocks(_)) }

    /// Returns true if this lock time value is a block time (UNIX timestamp).
    #[inline]
    pub const fn is_block_time(&self) -> bool { !self.is_block_height() }

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

units::impl_parse_str_from_int_infallible!(LockTime, u32, from_consensus);

impl From<Height> for LockTime {
    #[inline]
    fn from(h: Height) -> Self { LockTime::Blocks(h) }
}

impl From<Time> for LockTime {
    #[inline]
    fn from(t: Time) -> Self { LockTime::Seconds(t) }
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

impl fmt::Debug for LockTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use LockTime::*;

        match *self {
            Blocks(ref h) => write!(f, "{} blocks", h),
            Seconds(ref t) => write!(f, "{} seconds", t),
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

impl Encodable for LockTime {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let v = self.to_consensus_u32();
        v.consensus_encode(w)
    }
}

impl Decodable for LockTime {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
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
                v.try_into().map_err(|_| {
                    E::invalid_value(serde::de::Unexpected::Unsigned(v), &"a 32-bit number")
                })
            }
            // Also do the signed version, just for good measure.
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<u32, E> {
                v.try_into().map_err(|_| {
                    E::invalid_value(serde::de::Unexpected::Signed(v), &"a 32-bit number")
                })
            }
        }
        deserializer.deserialize_u32(Visitor).map(LockTime::from_consensus)
    }
}

#[cfg(feature = "ordered")]
impl ordered::ArbitraryOrd for LockTime {
    fn arbitrary_cmp(&self, other: &Self) -> Ordering {
        use LockTime::*;

        match (self, other) {
            (Blocks(_), Seconds(_)) => Ordering::Less,
            (Seconds(_), Blocks(_)) => Ordering::Greater,
            (Blocks(this), Blocks(that)) => this.cmp(that),
            (Seconds(this), Seconds(that)) => this.cmp(that),
        }
    }
}

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
    fn lock_time_from_hex_lower() {
        let lock = LockTime::from_hex("0x6289c350").unwrap();
        assert_eq!(lock, LockTime::from_consensus(0x6289C350));
    }

    #[test]
    fn lock_time_from_hex_upper() {
        let lock = LockTime::from_hex("0X6289C350").unwrap();
        assert_eq!(lock, LockTime::from_consensus(0x6289C350));
    }

    #[test]
    fn lock_time_from_unprefixed_hex_lower() {
        let lock = LockTime::from_unprefixed_hex("6289c350").unwrap();
        assert_eq!(lock, LockTime::from_consensus(0x6289C350));
    }

    #[test]
    fn lock_time_from_unprefixed_hex_upper() {
        let lock = LockTime::from_unprefixed_hex("6289C350").unwrap();
        assert_eq!(lock, LockTime::from_consensus(0x6289C350));
    }

    #[test]
    fn lock_time_from_invalid_hex_should_err() {
        let hex = "0xzb93";
        let result = LockTime::from_hex(hex);
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
