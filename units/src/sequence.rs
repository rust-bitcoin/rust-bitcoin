// SPDX-License-Identifier: CC0-1.0

//! Bitcoin transaction input sequence number.
//!
//! The sequence field is used for:
//! - Indicating whether absolute lock-time (specified in `lock_time` field of `Transaction`) is enabled.
//! - Indicating and encoding [BIP-0068] relative lock-times.
//! - Indicating whether a transaction opts-in to [BIP-0125] replace-by-fee.
//!
//! Note that transactions spending an output with `OP_CHECKLOCKTIMEVERIFY` MUST NOT use
//! `Sequence::MAX` for the corresponding input. [BIP-0065]
//!
//! [BIP-0065]: <https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki>
//! [BIP-0068]: <https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki>
//! [BIP-0125]: <https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki>

use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::locktime::relative::error::TimeOverflowError;
use crate::locktime::relative::{self, NumberOf512Seconds};
use crate::parse_int::{self, PrefixedHexError, UnprefixedHexError};

#[rustfmt::skip]                // Keep public re-exports separate.
#[cfg(feature = "encoding")]
#[doc(no_inline)]
pub use self::error::SequenceDecoderError;

/// Bitcoin transaction input sequence number.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Sequence(pub u32);

impl Sequence {
    /// The maximum allowable sequence number.
    ///
    /// The sequence number that disables replace-by-fee, absolute lock time and relative lock time.
    pub const MAX: Self = Self(0xFFFF_FFFF);

    /// Zero value sequence.
    ///
    /// This sequence number enables replace-by-fee and absolute lock time.
    pub const ZERO: Self = Self(0);

    /// The sequence number that disables replace-by-fee, absolute lock time and relative lock time.
    pub const FINAL: Self = Self::MAX;

    /// The sequence number that enables absolute lock time but disables replace-by-fee
    /// and relative lock time.
    pub const ENABLE_LOCKTIME_NO_RBF: Self = Self::MIN_NO_RBF;

    /// The maximum sequence number that enables replace-by-fee and absolute lock time but
    /// disables relative lock time.
    ///
    /// This sequence number has no meaning other than to enable RBF and the absolute locktime.
    pub const ENABLE_LOCKTIME_AND_RBF: Self = Self(0xFFFF_FFFD);

    /// The number of bytes that a sequence number contributes to the size of a transaction.
    pub const SIZE: usize = 4; // Serialized length of a u32.

    /// The lowest sequence number that does not opt-in for replace-by-fee.
    ///
    /// A transaction is considered to have opted in to replacement of itself
    /// if any of its inputs have a `Sequence` number less than this value
    /// (Explicit Signalling [BIP-0125]).
    ///
    /// [BIP-0125]: <https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki>
    const MIN_NO_RBF: Self = Self(0xFFFF_FFFE);

    /// BIP-0068 relative lock time disable flag mask.
    const LOCK_TIME_DISABLE_FLAG_MASK: u32 = 0x8000_0000;

    /// BIP-0068 relative lock time type flag mask.
    pub(super) const LOCK_TYPE_MASK: u32 = 0x0040_0000;

    /// Returns `true` if the sequence number enables absolute lock-time (`Transaction::lock_time`).
    #[inline]
    pub fn enables_absolute_lock_time(self) -> bool { self != Self::MAX }

    /// Returns `true` if the sequence number indicates that the transaction is finalized.
    ///
    /// Instead of this method please consider using `!enables_absolute_lock_time` because it
    /// is equivalent and improves readability for those not steeped in Bitcoin folklore.
    ///
    /// # Historical note
    ///
    /// The term 'final' is an archaic Bitcoin term, it may have come about because the sequence
    /// number in the original Bitcoin code was intended to be incremented in order to replace a
    /// transaction, so once the sequence number got to `u32::MAX` it could no longer be increased,
    /// hence it was 'final'.
    ///
    ///
    /// Some other references to the term:
    /// - `CTxIn::SEQUENCE_FINAL` in the Bitcoin Core code.
    /// - [BIP-0112]: "BIP-0068 prevents a non-final transaction from being selected for inclusion in a
    ///   block until the corresponding input has reached the specified age"
    ///
    /// [BIP-0112]: <https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki>
    #[inline]
    pub fn is_final(self) -> bool { !self.enables_absolute_lock_time() }

    /// Returns true if the transaction opted-in to BIP-0125 replace-by-fee.
    ///
    /// Replace by fee is signaled by the sequence being less than 0xfffffffe which is checked by
    /// this method. Note, this is the highest "non-final" value (see [`Sequence::is_final`]).
    #[inline]
    pub fn is_rbf(self) -> bool { self < Self::MIN_NO_RBF }

    /// Returns `true` if the sequence has a relative lock-time.
    #[inline]
    pub fn is_relative_lock_time(self) -> bool { self.0 & Self::LOCK_TIME_DISABLE_FLAG_MASK == 0 }

    /// Returns `true` if the sequence number encodes a block based relative lock-time.
    #[inline]
    pub fn is_height_locked(self) -> bool {
        self.is_relative_lock_time() && (self.0 & Self::LOCK_TYPE_MASK == 0)
    }

    /// Returns `true` if the sequence number encodes a time interval based relative lock-time.
    #[inline]
    pub fn is_time_locked(self) -> bool {
        self.is_relative_lock_time() && (self.0 & Self::LOCK_TYPE_MASK > 0)
    }

    /// Constructs a new `Sequence` from a prefixed hex string.
    ///
    /// # Errors
    ///
    /// If the input string is not a valid hex representation of a locktime or it does not include
    /// the `0x` prefix.
    #[inline]
    pub fn from_hex(s: &str) -> Result<Self, PrefixedHexError> {
        let lock_time = parse_int::hex_u32_prefixed(s)?;
        Ok(Self::from_consensus(lock_time))
    }

    /// Constructs a new `Sequence` from an unprefixed hex string.
    ///
    /// # Errors
    ///
    /// If the input string is not a valid hex representation of a locktime or if it includes the
    /// `0x` prefix.
    #[inline]
    pub fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError> {
        let lock_time = parse_int::hex_u32_unprefixed(s)?;
        Ok(Self::from_consensus(lock_time))
    }

    /// Constructs a new relative lock-time using block height.
    #[inline]
    pub fn from_height(height: u16) -> Self { Self(u32::from(height)) }

    /// Constructs a new relative lock-time using time intervals where each interval is equivalent
    /// to 512 seconds.
    ///
    /// Encoding finer granularity of time for relative lock-times is not supported in Bitcoin.
    #[inline]
    pub fn from_512_second_intervals(intervals: u16) -> Self {
        Self(u32::from(intervals) | Self::LOCK_TYPE_MASK)
    }

    /// Constructs a new relative lock-time from seconds, converting the seconds into 512 second
    /// interval with floor division.
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    ///
    /// # Errors
    ///
    /// Will return an error if `seconds` cannot be encoded in 16 bits. See
    /// [`NumberOf512Seconds::from_seconds_floor`].
    #[inline]
    pub fn from_seconds_floor(seconds: u32) -> Result<Self, TimeOverflowError> {
        let intervals = NumberOf512Seconds::from_seconds_floor(seconds)?;
        Ok(Self::from_512_second_intervals(intervals.to_512_second_intervals()))
    }

    /// Constructs a new relative lock-time from seconds, converting the seconds into 512 second
    /// interval with ceiling division.
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    ///
    /// # Errors
    ///
    /// Will return an error if `seconds` cannot be encoded in 16 bits. See
    /// [`NumberOf512Seconds::from_seconds_ceil`].
    #[inline]
    pub fn from_seconds_ceil(seconds: u32) -> Result<Self, TimeOverflowError> {
        let intervals = NumberOf512Seconds::from_seconds_ceil(seconds)?;
        Ok(Self::from_512_second_intervals(intervals.to_512_second_intervals()))
    }

    /// Constructs a new sequence from a u32 value.
    #[inline]
    pub fn from_consensus(n: u32) -> Self { Self(n) }

    /// Returns the inner 32-bit integer value of Sequence.
    #[inline]
    pub const fn to_consensus_u32(self) -> u32 { self.0 }

    /// Constructs a new [`relative::LockTime`] from this [`Sequence`] number.
    #[inline]
    pub fn to_relative_lock_time(self) -> Option<relative::LockTime> {
        use crate::locktime::relative::{LockTime, NumberOfBlocks};

        if !self.is_relative_lock_time() {
            return None;
        }

        let lock_value = self.low_u16();

        if self.is_time_locked() {
            Some(LockTime::from(NumberOf512Seconds::from_512_second_intervals(lock_value)))
        } else {
            Some(LockTime::from(NumberOfBlocks::from(lock_value)))
        }
    }

    /// Returns the low 16 bits from sequence number.
    ///
    /// BIP-0068 only uses the low 16 bits for relative lock value.
    #[inline]
    const fn low_u16(self) -> u16 { self.0 as u16 }
}

crate::internal_macros::impl_fmt_traits_for_u32_wrapper!(Sequence);

impl Default for Sequence {
    /// The default value of sequence is 0xffffffff.
    #[inline]
    fn default() -> Self { Self::MAX }
}

impl From<Sequence> for u32 {
    #[inline]
    fn from(sequence: Sequence) -> Self { sequence.0 }
}

impl fmt::Display for Sequence {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl fmt::Debug for Sequence {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // 10 because its 8 digits + 2 for the '0x'
        write!(f, "Sequence({:#010x})", self.0)
    }
}

parse_int::impl_parse_str_from_int_infallible!(Sequence, u32, from_consensus);

#[cfg(feature = "encoding")]
impl encoding::Encode for Sequence {
    type Encoder<'e> = SequenceEncoder<'e>;
    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        SequenceEncoder::new(encoding::ArrayEncoder::without_length_prefix(
            self.to_consensus_u32().to_le_bytes(),
        ))
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for Sequence {
    type Decoder = SequenceDecoder;
}

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// The encoder for the [`Sequence`] type.
    #[derive(Debug, Clone)]
    pub struct SequenceEncoder<'e>(encoding::ArrayEncoder<4>);
}

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// The decoder for the [`Sequence`] type.
    #[derive(Debug, Clone)]
    pub struct SequenceDecoder(encoding::ArrayDecoder<4>);

    /// Constructs a new [`Sequence`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }

    fn end(result: Result<[u8; 4], encoding::UnexpectedEofError>) -> Result<Sequence, SequenceDecoderError> {
        let value = result.map_err(SequenceDecoderError)?;
        let n = u32::from_le_bytes(value);
        Ok(Sequence::from_consensus(n))
    }
}

/// Error types for input sequence numbers.
pub mod error {
    #[cfg(feature = "encoding")]
    use core::convert::Infallible;
    #[cfg(feature = "encoding")]
    use core::fmt;

    #[cfg(feature = "encoding")]
    use internals::write_err;

    /// An error consensus decoding a `Sequence`.
    #[cfg(feature = "encoding")]
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SequenceDecoderError(pub(super) encoding::UnexpectedEofError);

    #[cfg(feature = "encoding")]
    impl From<Infallible> for SequenceDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    #[cfg(feature = "encoding")]
    impl fmt::Display for SequenceDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write_err!(f, "sequence decoder error"; self.0)
        }
    }

    #[cfg(feature = "encoding")]
    #[cfg(feature = "std")]
    impl std::error::Error for SequenceDecoderError {
        #[inline]
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }
}

#[cfg(feature = "arbitrary")]
#[cfg(feature = "alloc")]
impl<'a> Arbitrary<'a> for Sequence {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Equally weight the cases of meaningful sequence numbers
        let choice = u.int_in_range(0..=8)?;
        match choice {
            0 => Ok(Self::MAX),
            1 => Ok(Self::ZERO),
            2 => Ok(Self::MIN_NO_RBF),
            3 => Ok(Self::ENABLE_LOCKTIME_AND_RBF),
            4 => Ok(Self::from_consensus(u32::from(relative::NumberOfBlocks::MIN.to_height()))),
            5 => Ok(Self::from_consensus(u32::from(relative::NumberOfBlocks::MAX.to_height()))),
            6 => Ok(Self::from_consensus(
                Self::LOCK_TYPE_MASK
                    | u32::from(relative::NumberOf512Seconds::MIN.to_512_second_intervals()),
            )),
            7 => Ok(Self::from_consensus(
                Self::LOCK_TYPE_MASK
                    | u32::from(relative::NumberOf512Seconds::MAX.to_512_second_intervals()),
            )),
            _ => Ok(Self(u.arbitrary()?)),
        }
    }
}

#[cfg(feature = "arbitrary")]
#[cfg(not(feature = "alloc"))]
impl<'a> Arbitrary<'a> for Sequence {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Equally weight the cases of meaningful sequence numbers
        let choice = u.int_in_range(0..=4)?;
        match choice {
            0 => Ok(Sequence::MAX),
            1 => Ok(Sequence::ZERO),
            2 => Ok(Sequence::MIN_NO_RBF),
            3 => Ok(Sequence::ENABLE_LOCKTIME_AND_RBF),
            _ => Ok(Sequence(u.arbitrary()?)),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::format;
    #[cfg(feature = "alloc")]
    #[cfg(feature = "encoding")]
    use alloc::string::ToString;
    #[cfg(feature = "encoding")]
    #[cfg(feature = "std")]
    use std::error::Error;

    #[cfg(feature = "alloc")]
    #[cfg(feature = "encoding")]
    use encoding::UnexpectedEofError;
    #[cfg(feature = "encoding")]
    use encoding::{Decode as _, Decoder as _};

    use super::*;

    const MAXIMUM_ENCODABLE_SECONDS: u32 = u16::MAX as u32 * 512;

    #[test]
    fn from_seconds_floor_success() {
        let expected = Sequence::from_hex("0x0040ffff").unwrap();
        let actual = Sequence::from_seconds_floor(MAXIMUM_ENCODABLE_SECONDS + 511).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_seconds_floor_causes_overflow_error() {
        assert!(Sequence::from_seconds_floor(MAXIMUM_ENCODABLE_SECONDS + 512).is_err());
    }

    #[test]
    fn from_seconds_ceil_success() {
        let expected = Sequence::from_hex("0x0040ffff").unwrap();
        let actual = Sequence::from_seconds_ceil(MAXIMUM_ENCODABLE_SECONDS - 511).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_seconds_ceil_causes_overflow_error() {
        assert!(Sequence::from_seconds_ceil(MAXIMUM_ENCODABLE_SECONDS + 1).is_err());
    }

    #[test]
    fn sequence_number() {
        let seq_final = Sequence::from_consensus(0xFFFF_FFFF);
        let seq_non_rbf = Sequence::from_consensus(0xFFFF_FFFE);
        let block_time_lock = Sequence::from_consensus(0xFFFF);
        let unit_time_lock = Sequence::from_consensus(0x40_FFFF);
        let lock_time_disabled = Sequence::from_consensus(0x8000_0000);

        assert!(seq_final.is_final());
        assert!(!seq_final.is_rbf());
        assert!(!seq_final.is_relative_lock_time());
        assert!(!seq_non_rbf.is_rbf());
        assert!(block_time_lock.is_relative_lock_time());
        assert!(block_time_lock.is_height_locked());
        assert!(block_time_lock.is_rbf());
        assert!(unit_time_lock.is_relative_lock_time());
        assert!(unit_time_lock.is_time_locked());
        assert!(unit_time_lock.is_rbf());
        assert!(!lock_time_disabled.is_relative_lock_time());
    }

    #[test]
    fn sequence_from_hex_lower() {
        let sequence = Sequence::from_hex("0xffffffff").unwrap();
        assert_eq!(sequence, Sequence::MAX);
    }

    #[test]
    fn sequence_from_hex_upper() {
        let sequence = Sequence::from_hex("0XFFFFFFFF").unwrap();
        assert_eq!(sequence, Sequence::MAX);
    }

    #[test]
    fn sequence_from_unprefixed_hex_lower() {
        let sequence = Sequence::from_unprefixed_hex("ffffffff").unwrap();
        assert_eq!(sequence, Sequence::MAX);
    }

    #[test]
    fn sequence_from_unprefixed_hex_upper() {
        let sequence = Sequence::from_unprefixed_hex("FFFFFFFF").unwrap();
        assert_eq!(sequence, Sequence::MAX);
    }

    #[test]
    fn sequence_from_str_hex_invalid_hex_should_err() {
        let hex = "0xzb93";
        let result = Sequence::from_hex(hex);
        assert!(result.is_err());
    }

    #[test]
    fn sequence_properties() {
        let seq_max = Sequence(0xFFFF_FFFF);
        let seq_no_rbf = Sequence(0xFFFF_FFFE);
        let seq_rbf = Sequence(0xFFFF_FFFD);

        assert!(seq_max.is_final());
        assert!(!seq_no_rbf.is_final());

        assert!(seq_no_rbf.enables_absolute_lock_time());
        assert!(!seq_max.enables_absolute_lock_time());

        assert!(seq_rbf.is_rbf());
        assert!(!seq_no_rbf.is_rbf());

        let seq_relative = Sequence(0x7FFF_FFFF);
        assert!(seq_relative.is_relative_lock_time());
        assert!(!seq_max.is_relative_lock_time());

        let seq_height_locked = Sequence(0x0039_9999);
        let seq_time_locked = Sequence(0x0040_0000);
        assert!(seq_height_locked.is_height_locked());
        assert!(seq_time_locked.is_time_locked());
        assert!(!seq_time_locked.is_height_locked());
        assert!(!seq_height_locked.is_time_locked());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn sequence_formatting() {
        let sequence = Sequence(0x7FFF_FFFF);
        assert_eq!(format!("{:x}", sequence), "7fffffff");
        assert_eq!(format!("{:X}", sequence), "7FFFFFFF");

        // Test From<Sequence> for u32
        let sequence_u32: u32 = sequence.into();
        assert_eq!(sequence_u32, 0x7FFF_FFFF);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn sequence_display() {
        use alloc::string::ToString;

        let sequence = Sequence(0x7FFF_FFFF);
        let want: u32 = 0x7FFF_FFFF;
        assert_eq!(format!("{}", sequence), want.to_string());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn sequence_unprefixed_hex_roundtrip() {
        let sequence = Sequence(0x7FFF_FFFF);

        let hex_str = format!("{:x}", sequence);
        assert_eq!(hex_str, "7fffffff");

        let roundtrip = Sequence::from_unprefixed_hex(&hex_str).unwrap();
        assert_eq!(sequence, roundtrip);
    }

    #[test]
    fn sequence_from_height() {
        // Check near the boundaries
        assert_eq!(Sequence::from_height(0), Sequence(0));
        assert_eq!(Sequence::from_height(1), Sequence(1));
        assert_eq!(Sequence::from_height(0x7FFF), Sequence(0x7FFF));
        assert_eq!(Sequence::from_height(0xFFFF), Sequence(0xFFFF));

        // Check steps throughout the whole range
        let step = 512;
        for v in (0..=u16::MAX).step_by(step) {
            assert_eq!(Sequence::from_height(v), Sequence(v.into()));
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "encoding")]
    fn sequence_decoding_error() {
        let bytes = [0xff, 0xff, 0xff]; // 3 bytes is an EOF error

        let mut decoder = SequenceDecoder::default();
        assert!(decoder.push_bytes(&mut bytes.as_slice()).unwrap().needs_more());

        let error = decoder.end().unwrap_err();
        assert!(matches!(error, SequenceDecoderError(UnexpectedEofError { .. })));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn decoder_error_display_is_non_empty() {
        #[cfg(feature = "encoding")]
        {
            // SequenceDecoderError
            let mut decoder = Sequence::decoder();
            let _ = decoder.push_bytes(&mut [0u8; 3].as_slice());
            let e = decoder.end().unwrap_err();
            assert!(!e.to_string().is_empty());
            #[cfg(feature = "std")]
            assert!(e.source().is_some());
        }
    }
}
