// SPDX-License-Identifier: CC0-1.0

//! Bitcoin transaction input sequence number.
//!
//! The sequence field is used for:
//! - Indicating whether absolute lock-time (specified in `lock_time` field of `Transaction`)
//!   is enabled.
//! - Indicating and encoding [BIP-68] relative lock-times.
//! - Indicating whether a transaction opts-in to [BIP-125] replace-by-fee.
//!
//! Note that transactions spending an output with `OP_CHECKLOCKTIMEVERIFY`MUST NOT use
//! `Sequence::MAX` for the corresponding input. [BIP-65]
//!
//! [BIP-65]: <https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki>
//! [BIP-68]: <https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki>
//! [BIP-125]: <https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki>

use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "alloc")]
use units::locktime::relative::TimeOverflowError;
#[cfg(feature = "alloc")]
use units::parse::{self, PrefixedHexError, UnprefixedHexError};

#[cfg(feature = "alloc")]
use crate::locktime::relative;

/// Bitcoin transaction input sequence number.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Sequence(pub u32);

impl Sequence {
    /// The maximum allowable sequence number.
    ///
    /// This sequence number disables absolute lock time and replace-by-fee.
    pub const MAX: Self = Sequence(0xFFFFFFFF);
    /// Zero value sequence.
    ///
    /// This sequence number enables replace-by-fee and absolute lock time.
    pub const ZERO: Self = Sequence(0);
    /// The sequence number that enables absolute lock time but disables replace-by-fee
    /// and relative lock time.
    pub const ENABLE_LOCKTIME_NO_RBF: Self = Sequence::MIN_NO_RBF;
    /// The sequence number that enables replace-by-fee and absolute lock time but
    /// disables relative lock time.
    pub const ENABLE_RBF_NO_LOCKTIME: Self = Sequence(0xFFFFFFFD);

    /// The number of bytes that a sequence number contributes to the size of a transaction.
    pub const SIZE: usize = 4; // Serialized length of a u32.

    /// The lowest sequence number that does not opt-in for replace-by-fee.
    ///
    /// A transaction is considered to have opted in to replacement of itself
    /// if any of it's inputs have a `Sequence` number less than this value
    /// (Explicit Signalling [BIP-125]).
    ///
    /// [BIP-125]: <https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki]>
    const MIN_NO_RBF: Self = Sequence(0xFFFFFFFE);
    /// BIP-68 relative lock time disable flag mask.
    const LOCK_TIME_DISABLE_FLAG_MASK: u32 = 0x80000000;
    /// BIP-68 relative lock time type flag mask.
    const LOCK_TYPE_MASK: u32 = 0x00400000;

    /// Returns `true` if the sequence number enables absolute lock-time (`Transaction::lock_time`).
    #[inline]
    pub fn enables_absolute_lock_time(&self) -> bool { *self != Sequence::MAX }

    /// Returns `true` if the sequence number indicates that the transaction is finalized.
    ///
    /// Instead of this method please consider using `!enables_absolute_lock_time` because it
    /// is equivalent and improves readability for those not steeped in Bitcoin folklore.
    ///
    /// ## Historical note
    ///
    /// The term 'final' is an archaic Bitcoin term, it may have come about because the sequence
    /// number in the original Bitcoin code was intended to be incremented in order to replace a
    /// transaction, so once the sequence number got to `u64::MAX` it could no longer be increased,
    /// hence it was 'final'.
    ///
    ///
    /// Some other references to the term:
    /// - `CTxIn::SEQUENCE_FINAL` in the Bitcoin Core code.
    /// - [BIP-112]: "BIP 68 prevents a non-final transaction from being selected for inclusion in a
    ///   block until the corresponding input has reached the specified age"
    ///
    /// [BIP-112]: <https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki>
    #[inline]
    pub fn is_final(&self) -> bool { !self.enables_absolute_lock_time() }

    /// Returns true if the transaction opted-in to BIP125 replace-by-fee.
    ///
    /// Replace by fee is signaled by the sequence being less than 0xfffffffe which is checked by
    /// this method. Note, this is the highest "non-final" value (see [`Sequence::is_final`]).
    #[inline]
    pub fn is_rbf(&self) -> bool { *self < Sequence::MIN_NO_RBF }

    /// Returns `true` if the sequence has a relative lock-time.
    #[inline]
    pub fn is_relative_lock_time(&self) -> bool {
        self.0 & Sequence::LOCK_TIME_DISABLE_FLAG_MASK == 0
    }

    /// Returns `true` if the sequence number encodes a block based relative lock-time.
    #[inline]
    pub fn is_height_locked(&self) -> bool {
        self.is_relative_lock_time() & (self.0 & Sequence::LOCK_TYPE_MASK == 0)
    }

    /// Returns `true` if the sequence number encodes a time interval based relative lock-time.
    #[inline]
    pub fn is_time_locked(&self) -> bool {
        self.is_relative_lock_time() & (self.0 & Sequence::LOCK_TYPE_MASK > 0)
    }

    /// Creates a `Sequence` from a prefixed hex string.
    #[cfg(feature = "alloc")]
    pub fn from_hex(s: &str) -> Result<Self, PrefixedHexError> {
        let lock_time = parse::hex_u32_prefixed(s)?;
        Ok(Self::from_consensus(lock_time))
    }

    /// Creates a `Sequence` from an unprefixed hex string.
    #[cfg(feature = "alloc")]
    pub fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError> {
        let lock_time = parse::hex_u32_unprefixed(s)?;
        Ok(Self::from_consensus(lock_time))
    }

    /// Creates a relative lock-time using block height.
    #[inline]
    pub fn from_height(height: u16) -> Self { Sequence(u32::from(height)) }

    /// Creates a relative lock-time using time intervals where each interval is equivalent
    /// to 512 seconds.
    ///
    /// Encoding finer granularity of time for relative lock-times is not supported in Bitcoin
    #[inline]
    pub fn from_512_second_intervals(intervals: u16) -> Self {
        Sequence(u32::from(intervals) | Sequence::LOCK_TYPE_MASK)
    }

    /// Creates a relative lock-time from seconds, converting the seconds into 512 second
    /// interval with floor division.
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    #[inline]
    #[cfg(feature = "alloc")]
    pub fn from_seconds_floor(seconds: u32) -> Result<Self, TimeOverflowError> {
        if let Ok(interval) = u16::try_from(seconds / 512) {
            Ok(Sequence::from_512_second_intervals(interval))
        } else {
            Err(TimeOverflowError::new(seconds))
        }
    }

    /// Creates a relative lock-time from seconds, converting the seconds into 512 second
    /// interval with ceiling division.
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    #[inline]
    #[cfg(feature = "alloc")]
    pub fn from_seconds_ceil(seconds: u32) -> Result<Self, TimeOverflowError> {
        if let Ok(interval) = u16::try_from((seconds + 511) / 512) {
            Ok(Sequence::from_512_second_intervals(interval))
        } else {
            Err(TimeOverflowError::new(seconds))
        }
    }

    /// Creates a sequence from a u32 value.
    #[inline]
    pub fn from_consensus(n: u32) -> Self { Sequence(n) }

    /// Returns the inner 32bit integer value of Sequence.
    #[inline]
    pub fn to_consensus_u32(self) -> u32 { self.0 }

    /// Creates a [`relative::LockTime`] from this [`Sequence`] number.
    #[inline]
    #[cfg(feature = "alloc")]
    pub fn to_relative_lock_time(&self) -> Option<relative::LockTime> {
        use crate::locktime::relative::{Height, LockTime, Time};

        if !self.is_relative_lock_time() {
            return None;
        }

        let lock_value = self.low_u16();

        if self.is_time_locked() {
            Some(LockTime::from(Time::from_512_second_intervals(lock_value)))
        } else {
            Some(LockTime::from(Height::from(lock_value)))
        }
    }

    /// Returns the low 16 bits from sequence number.
    ///
    /// BIP-68 only uses the low 16 bits for relative lock value.
    #[cfg(feature = "alloc")]
    fn low_u16(&self) -> u16 { self.0 as u16 }
}

impl Default for Sequence {
    /// The default value of sequence is 0xffffffff.
    fn default() -> Self { Sequence::MAX }
}

impl From<Sequence> for u32 {
    fn from(sequence: Sequence) -> u32 { sequence.0 }
}

impl fmt::Display for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl fmt::LowerHex for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
}

impl fmt::UpperHex for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::UpperHex::fmt(&self.0, f) }
}

impl fmt::Debug for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // 10 because its 8 digits + 2 for the '0x'
        write!(f, "Sequence({:#010x})", self.0)
    }
}

#[cfg(feature = "alloc")]
units::impl_parse_str_from_int_infallible!(Sequence, u32, from_consensus);
