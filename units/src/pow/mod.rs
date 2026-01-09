// SPDX-License-Identifier: CC0-1.0

//! Proof-of-work related integer types.

#[cfg(feature = "encoding")]
use core::convert::Infallible;
use core::fmt;
use core::ops::{Add, Sub};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(feature = "encoding")]
use internals::write_err;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::parse_int::{self, PrefixedHexError, UnprefixedHexError};

mod u256;
use u256::U256;

/// Encoding of 256-bit target as 32-bit float.
///
/// This is used to encode a target into the block header. Satoshi made this part of consensus code
/// in the original version of Bitcoin, likely copying an idea from OpenSSL.
///
/// OpenSSL's bignum (BN) type has an encoding, which is even called "compact" as in bitcoin, which
/// is exactly this format.
///
/// # Note on order/equality
///
/// Usage of the ordering and equality traits for this type may be surprising. Converting between
/// `CompactTarget` and `Target` is lossy *in both directions* (there are multiple `CompactTarget`
/// values that map to the same `Target` value). Ordering and equality for this type are defined in
/// terms of the underlying `u32`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CompactTarget(u32);

impl CompactTarget {
    /// Constructs a new [`CompactTarget`] from a consensus encoded `u32`.
    #[inline]
    pub fn from_consensus(bits: u32) -> Self { Self(bits) }

    /// Returns the consensus encoded `u32` representation of this [`CompactTarget`].
    #[inline]
    pub const fn to_consensus(self) -> u32 { self.0 }

    /// Gets the hex representation of this [`CompactTarget`].
    #[cfg(feature = "alloc")]
    #[inline]
    #[deprecated(since = "1.0.0-rc.0", note = "use `format!(\"{var:x}\")` instead")]
    pub fn to_hex(self) -> alloc::string::String { alloc::format!("{:x}", self) }

    /// Constructs a new `CompactTarget` from a prefixed hex string.
    ///
    /// # Errors
    ///
    /// - If the input string does not contain a `0x` (or `0X`) prefix.
    /// - If the input string is not a valid hex encoding of a `u32`.
    pub fn from_hex(s: &str) -> Result<Self, PrefixedHexError>
    where
        Self: Sized
    {
        let target = parse_int::hex_u32_prefixed(s)?;
        Ok(Self::from_consensus(target))
    }

    /// Constructs a new `CompactTarget` from an unprefixed hex string.
    ///
    /// # Errors
    ///
    /// - If the input string contains a `0x` (or `0X`) prefix.
    /// - If the input string is not a valid hex encoding of a `u32`.
    pub fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError>
    where
        Self: Sized
    {
        let target = parse_int::hex_u32_unprefixed(s)?;
        Ok(Self::from_consensus(target))
    }
}

impl fmt::LowerHex for CompactTarget {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
}

impl fmt::UpperHex for CompactTarget {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::UpperHex::fmt(&self.0, f) }
}

impl From<CompactTarget> for Target {
    fn from(c: CompactTarget) -> Self { Self::from_compact(c) }
}

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// The encoder for the [`CompactTarget`] type.
    pub struct CompactTargetEncoder(encoding::ArrayEncoder<4>);
}

#[cfg(feature = "encoding")]
impl encoding::Encodable for CompactTarget {
    type Encoder<'e> = CompactTargetEncoder;
    fn encoder(&self) -> Self::Encoder<'_> {
        CompactTargetEncoder(encoding::ArrayEncoder::without_length_prefix(
            self.to_consensus().to_le_bytes(),
        ))
    }
}

/// The decoder for the [`CompactTarget`] type.
#[cfg(feature = "encoding")]
pub struct CompactTargetDecoder(encoding::ArrayDecoder<4>);

#[cfg(feature = "encoding")]
impl CompactTargetDecoder {
    /// Constructs a new [`CompactTarget`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
}

#[cfg(feature = "encoding")]
impl Default for CompactTargetDecoder {
    fn default() -> Self { Self::new() }
}

#[cfg(feature = "encoding")]
impl encoding::Decoder for CompactTargetDecoder {
    type Output = CompactTarget;
    type Error = CompactTargetDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        Ok(self.0.push_bytes(bytes)?)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let n = u32::from_le_bytes(self.0.end()?);
        Ok(CompactTarget::from_consensus(n))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "encoding")]
impl encoding::Decodable for CompactTarget {
    type Decoder = CompactTargetDecoder;
    fn decoder() -> Self::Decoder { CompactTargetDecoder(encoding::ArrayDecoder::<4>::new()) }
}

/// An error consensus decoding an `CompactTarget`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "encoding")]
pub struct CompactTargetDecoderError(encoding::UnexpectedEofError);

#[cfg(feature = "encoding")]
impl From<Infallible> for CompactTargetDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl From<encoding::UnexpectedEofError> for CompactTargetDecoderError {
    fn from(e: encoding::UnexpectedEofError) -> Self { Self(e) }
}

#[cfg(feature = "encoding")]
impl fmt::Display for CompactTargetDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "sequence decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
#[cfg(feature = "encoding")]
impl std::error::Error for CompactTargetDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// Implement traits and methods shared by `Target` and `Work`.
macro_rules! do_impl {
    ($ty:ident) => {
        impl $ty {
            #[doc = "Constructs a new `"]
            #[doc = stringify!($ty)]
            #[doc = "` from a prefixed hex string.\n"]
            #[doc = "\n# Errors\n"]
            #[doc = "\n - If the input string does not contain a `0x` (or `0X`) prefix."]
            #[doc = "\n - If the input string is not a valid hex encoding of a `"]
            #[doc = stringify!($ty)]
            #[doc = "`."]
            pub fn from_hex(s: &str) -> Result<Self, PrefixedHexError> {
                Ok($ty(U256::from_hex(s)?))
            }

            #[doc = "Constructs a new `"]
            #[doc = stringify!($ty)]
            #[doc = "` from an unprefixed hex string.\n"]
            #[doc = "\n# Errors\n"]
            #[doc = "\n - If the input string contains a `0x` (or `0X`) prefix."]
            #[doc = "\n - If the input string is not a valid hex encoding of a `"]
            #[doc = stringify!($ty)]
            #[doc = "`."]
            pub fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError> {
                Ok($ty(U256::from_unprefixed_hex(s)?))
            }

            #[doc = "Constructs `"]
            #[doc = stringify!($ty)]
            #[doc = "` from a big-endian byte array."]
            #[inline]
            pub fn from_be_bytes(bytes: [u8; 32]) -> $ty { $ty(U256::from_be_bytes(bytes)) }

            #[doc = "Constructs `"]
            #[doc = stringify!($ty)]
            #[doc = "` from a little-endian byte array."]
            #[inline]
            pub fn from_le_bytes(bytes: [u8; 32]) -> $ty { $ty(U256::from_le_bytes(bytes)) }

            #[doc = "Converts `"]
            #[doc = stringify!($ty)]
            #[doc = "` to a big-endian byte array."]
            #[inline]
            pub fn to_be_bytes(self) -> [u8; 32] { self.0.to_be_bytes() }

            #[doc = "Converts `"]
            #[doc = stringify!($ty)]
            #[doc = "` to a little-endian byte array."]
            #[inline]
            pub fn to_le_bytes(self) -> [u8; 32] { self.0.to_le_bytes() }
        }

        impl fmt::Display for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::LowerHex for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl fmt::UpperHex for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
                fmt::UpperHex::fmt(&self.0, f)
            }
        }
    };
}

/// A 256 bit integer representing work.
///
/// Work is a measure of how difficult it is to find a hash below a given [`Target`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Work(U256);

impl Work {
    /// Converts this [`Work`] to [`Target`].
    pub fn to_target(self) -> Target { Target(self.0.inverse()) }

    /// Returns log2 of this work.
    ///
    /// The result inherently suffers from a loss of precision and is, therefore, meant to be
    /// used mainly for informative and displaying purposes, similarly to Bitcoin Core's
    /// `log2_work` output in its logs.
    #[cfg(feature = "std")]
    pub fn log2(self) -> f64 { self.0.to_f64().log2() }
}
do_impl!(Work);

impl Add for Work {
    type Output = Self;
    fn add(self, rhs: Self) -> Self { Self(self.0 + rhs.0) }
}

impl Sub for Work {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self { Self(self.0 - rhs.0) }
}

/// A 256 bit integer representing target.
///
/// The SHA-256 hash of a block's header must be lower than or equal to the current target for the
/// block to be accepted by the network. The lower the target, the more difficult it is to generate
/// a block. (See also [`Work`].)
///
/// ref: <https://en.bitcoin.it/wiki/Target>
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Target(U256);

impl Target {
    /// When parsing nBits, Bitcoin Core converts a negative target threshold into a target of zero.
    pub const ZERO: Self = Self(U256::ZERO);
    /// The maximum possible target.
    ///
    /// This value is used to calculate difficulty, which is defined as how difficult the current
    /// target makes it to find a block relative to how difficult it would be at the highest
    /// possible target. Remember highest target == lowest difficulty.
    ///
    /// ref: <https://en.bitcoin.it/wiki/Target>
    // In Bitcoind this is ~(u256)0 >> 32 stored as a floating-point type so it gets truncated, hence
    // the low 208 bits are all zero.
    pub const MAX: Self = Self(U256(0xFFFF_u128 << (208 - 128), 0));

    /// The maximum **attainable** target value on mainnet.
    ///
    /// Not all target values are attainable because consensus code uses the compact format to
    /// represent targets (see [`CompactTarget`]).
    // Taken from Bitcoin Core but had lossy conversion to/from compact form.
    // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L88
    pub const MAX_ATTAINABLE_MAINNET: Self = Self(U256(0xFFFF_u128 << (208 - 128), 0));

    /// The maximum **attainable** target value on testnet.
    // Taken from Bitcoin Core but had lossy conversion to/from compact form.
    // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L208
    pub const MAX_ATTAINABLE_TESTNET: Self = Self(U256(0xFFFF_u128 << (208 - 128), 0));

    /// The maximum **attainable** target value on regtest.
    // Taken from Bitcoin Core but had lossy conversion to/from compact form.
    // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L411
    pub const MAX_ATTAINABLE_REGTEST: Self = Self(U256(0x7FFF_FF00u128 << 96, 0));

    /// The maximum **attainable** target value on signet.
    // Taken from Bitcoin Core but had lossy conversion to/from compact form.
    // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L348
    pub const MAX_ATTAINABLE_SIGNET: Self = Self(U256(0x0377_ae00 << 80, 0));

    /// Computes the [`Target`] value from a compact representation.
    ///
    /// ref: <https://developer.bitcoin.org/reference/block_chain.html#target-nbits>
    pub fn from_compact(c: CompactTarget) -> Self {
        let bits = c.to_consensus();
        // This is a floating-point "compact" encoding originally used by
        // OpenSSL, which satoshi put into consensus code, so we're stuck
        // with it. The exponent needs to have 3 subtracted from it, hence
        // this goofy decoding code. 3 is due to 3 bytes in the mantissa.
        let (mant, expt) = {
            let unshifted_expt = bits >> 24;
            if unshifted_expt <= 3 {
                ((bits & 0xFF_FFFF) >> (8 * (3 - unshifted_expt as usize)), 0)
            } else {
                (bits & 0xFF_FFFF, 8 * ((bits >> 24) - 3))
            }
        };

        // The mantissa is signed but may not be negative.
        if mant > 0x7F_FFFF {
            Self::ZERO
        } else {
            Self(U256::from(mant) << expt)
        }
    }

    /// Computes the compact value from a [`Target`] representation.
    ///
    /// The compact form is by definition lossy, this means that
    /// `t == Target::from_compact(t.to_compact_lossy())` does not always hold.
    pub fn to_compact_lossy(self) -> CompactTarget {
        let mut size = self.0.bits().div_ceil(8);
        let mut compact = if size <= 3 {
            (self.0.low_u64() << (8 * (3 - size))) as u32
        } else {
            let bn = self.0 >> (8 * (size - 3));
            bn.low_u32()
        };

        if (compact & 0x0080_0000) != 0 {
            compact >>= 8;
            size += 1;
        }

        CompactTarget::from_consensus(compact | (size << 24))
    }

    /// Converts this [`Target`] to [`Work`].
    ///
    /// "Work" is defined as the work done to mine a block with this target value (recorded in the
    /// block header in compact form as nBits). This is not the same as the difficulty to mine a
    /// block with this target (see `Self::difficulty`).
    pub fn to_work(self) -> Work { Work(self.0.inverse()) }

    /// Computes the popular "difficulty" measure for mining.
    ///
    /// Difficulty represents how difficult the current target makes it to find a block, relative to
    /// how difficult it would be at the highest possible target (highest target == lowest difficulty).
    ///
    /// For example, a difficulty of 6,695,826 means that at a given hash rate, it will, on average,
    /// take ~6.6 million times as long to find a valid block as it would at a difficulty of 1, or
    /// alternatively, it will take, again on average, ~6.6 million times as many hashes to find a
    /// valid block.
    ///
    /// Values for the `max_target` paramter can be taken from const values on [`Target`]
    /// (e.g. [`Target::MAX_ATTAINABLE_MAINNET`]).
    ///
    /// # Note
    ///
    /// Difficulty is calculated using the following algorithm `max / current` where [max] is
    /// defined for the Bitcoin network and `current` is the current target for this block (i.e. `self`).
    /// As such, a low target implies a high difficulty. Since [`Target`] is represented as a 256 bit
    /// integer but `difficulty_with_max()` returns only 128 bits this means for targets below
    /// approximately `0xffff_ffff_ffff_ffff_ffff_ffff` `difficulty_with_max()` will saturate at `u128::MAX`.
    ///
    /// # Panics
    ///
    /// Panics if `self` is zero (divide by zero).
    ///
    /// [max]: Target::max
    pub fn difficulty_with_max(&self, max_target: &Self) -> u128 {
        // Panic here may be easier to debug than during the actual division.
        assert_ne!(self.0, U256::ZERO, "divide by zero");

        let d = max_target.0 / self.0;
        d.saturating_to_u128()
    }

    /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
    ///
    /// See [`difficulty_with_max`] for details.
    ///
    /// # Panics
    ///
    /// Panics if `self` is zero (divide by zero).
    ///
    /// [`difficulty_with_max`]: Target::difficulty_with_max
    pub fn difficulty_float_with_max(&self, max_target: &Self) -> f64 {
        // We want to explicitly panic to be uniform with `difficulty()`
        // (float division by zero does not panic).
        // Note, target 0 is basically impossible to obtain by any "normal" means.
        assert_ne!(self.0, U256::ZERO, "divide by zero");
        max_target.0.to_f64() / self.0.to_f64()
    }

    /// Computes the minimum valid [`Target`] threshold allowed for a block in which a difficulty
    /// adjustment occurs.
    ///
    /// The difficulty can only decrease or increase by a factor of 4 max on each difficulty
    /// adjustment period.
    ///
    /// # Returns
    ///
    /// In line with Bitcoin Core this function may return a target value of zero.
    #[must_use]
    pub fn min_transition_threshold(&self) -> Self { Self(self.0 >> 2) }

    /// Computes the maximum valid [`Target`] threshold allowed for a block in which a difficulty
    /// adjustment occurs.
    ///
    /// The difficulty can only decrease or increase by a factor of 4 max on each difficulty
    /// adjustment period.
    ///
    /// # Returns
    ///
    /// This function may return a value greater than the maximum allowed target for this network.
    ///
    /// The return value should be checked against the `max_attainable_target` field of a `Params`
    /// object, or use one of the `Target::MAX_ATTAINABLE_FOO` constants.
    #[must_use]
    pub fn max_transition_threshold_unchecked(&self) -> Self { Self(self.0 << 2) }
}
do_impl!(Target);

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for CompactTarget {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_consensus(u.arbitrary()?))
    }
}

/// In test code, U256s are a pain to work with, so we just convert Rust primitives in many places
#[cfg(test)]
pub mod test_utils {
    use crate::pow::{Target, Work, U256};

    /// Converts a `u64` to a [`Work`]
    pub fn u64_to_work(u: u64) -> Work { Work(U256::from(u)) }

    /// Converts a `u128` to a [`Work`]
    pub fn u128_to_work(u: u128) -> Work { Work(U256::from(u)) }

    /// Converts a `u32` to a [`Target`]
    pub fn u32_to_target(u: u32) -> Target { Target(U256::from(u)) }

    /// Converts a `u64` to a [`Target`]
    pub fn u64_to_target(u: u64) -> Target { Target(U256::from(u)) }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::format;
    #[cfg(feature = "std")]
    use crate::pow::test_utils::u128_to_work;
    use crate::pow::test_utils::{u32_to_target, u64_to_target};

    use super::*;

    #[test]
    fn compact_target_ordering() {
        let lower = CompactTarget::from_consensus(0x1d00_fffe);
        let lower_copy = CompactTarget::from_consensus(0x1d00_fffe);
        let higher = CompactTarget::from_consensus(0x1d00_ffff);

        assert!(lower < higher);
        assert!(lower == lower_copy);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn compact_target_formatting() {
        let compact_target = CompactTarget::from_consensus(0x1d00_ffff);
        assert_eq!(format!("{:x}", compact_target), "1d00ffff");
        assert_eq!(format!("{:X}", compact_target), "1D00FFFF");
        assert_eq!(compact_target.to_consensus(), 0x1d00_ffff);
    }

    #[test]
    fn compact_target_from_hex_lower() {
        let target = CompactTarget::from_hex("0x010034ab").unwrap();
        assert_eq!(target, CompactTarget::from_consensus(0x0100_34ab));
    }

    #[test]
    fn compact_target_from_hex_upper() {
        let target = CompactTarget::from_hex("0X010034AB").unwrap();
        assert_eq!(target, CompactTarget::from_consensus(0x0100_34ab));
    }

    #[test]
    fn compact_target_from_unprefixed_hex_lower() {
        let target = CompactTarget::from_unprefixed_hex("010034ab").unwrap();
        assert_eq!(target, CompactTarget::from_consensus(0x0100_34ab));
    }

    #[test]
    fn compact_target_from_unprefixed_hex_upper() {
        let target = CompactTarget::from_unprefixed_hex("010034AB").unwrap();
        assert_eq!(target, CompactTarget::from_consensus(0x0100_34ab));
    }

    #[test]
    fn compact_target_from_hex_invalid_hex_should_err() {
        let hex = "0xzbf9";
        let result = CompactTarget::from_hex(hex);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn compact_target_lower_hex_and_upper_hex() {
        assert_eq!(format!("{:08x}", CompactTarget::from_consensus(0x01D0_F456)), "01d0f456");
        assert_eq!(format!("{:08X}", CompactTarget::from_consensus(0x01d0_f456)), "01D0F456");
    }

    #[test]
    fn target_from_compact() {
        // (nBits, target)
        let tests = [
            (0x0100_3456_u32, 0x00_u64), // High bit set.
            (0x0112_3456_u32, 0x12_u64),
            (0x0200_8000_u32, 0x80_u64),
            (0x0500_9234_u32, 0x9234_0000_u64),
            (0x0492_3456_u32, 0x00_u64), // High bit set (0x80 in 0x92).
            (0x0412_3456_u32, 0x1234_5600_u64), // Inverse of above; no high bit.
            (0x047f_ffff_u32, 0x7fff_ff00_u64), // Edge case of mantissa = 0x7f_ffff
        ];

        for (n_bits, target) in tests {
            let want = u64_to_target(target);
            let got = Target::from_compact(CompactTarget::from_consensus(n_bits));
            assert_eq!(got, want);
        }
    }

    #[test]
    fn target_to_compact_lossy() {
        // (nBits, target)
        let tests = [
            (0x0_u32, 0x00_u64),
            (0x0112_0000_u32, 0x12_u64),
            (0x0200_8000_u32, 0x80_u64),
            (0x0500_9234_u32, 0x9234_0000_u64),
            (0x0412_3456_u32, 0x1234_5600_u64),
        ];

        for (n_bits, target) in tests {
            let want = CompactTarget::from_consensus(n_bits);
            let got = u64_to_target(target).to_compact_lossy();
            assert_eq!(got, want);
        }
    }

    #[test]
    fn target_difficulty_with_max() {
        let targets = [
            (u64_to_target(0x80), u128::MAX),
            // Values required to not saturate are intractibly large
            // Instead, we'll cheat by dividing max net values by small values
            (Target(Target::MAX_ATTAINABLE_MAINNET.0 / 10u128.into()), 10),
            (Target(Target::MAX_ATTAINABLE_TESTNET.0 / 0x9234_0000u64.into()), 2_452_881_408),
            (Target(Target::MAX_ATTAINABLE_SIGNET.0 / 0x1234_5600u64.into()), 344_060),
            (Target(Target::MAX_ATTAINABLE_REGTEST.0 / 0xffff_ffff_ffffu64.into()), 131_070),
            (Target::MAX_ATTAINABLE_MAINNET, 1_u128),
        ];
        for (target, want) in targets {
            let got = target.difficulty_with_max(&Target::MAX_ATTAINABLE_MAINNET);
            assert_eq!(got, want);
        }
    }

    #[test]
    #[should_panic(expected = "divide by zero")]
    fn target_difficulty_with_max_panics_on_zero() {
        let max_target = Target::MAX_ATTAINABLE_MAINNET;
        u64_to_target(0).difficulty_with_max(&max_target);
    }


    #[test]
    fn target_difficulty_float_with_max() {
        let targets = [
            (Target(Target::MAX_ATTAINABLE_MAINNET.0 / 10u128.into()), 10.0),
            (Target(Target::MAX_ATTAINABLE_TESTNET.0 / 0x9234_0000u64.into()), 2_452_881_408.0),
            (Target(Target::MAX_ATTAINABLE_SIGNET.0 / 0x1234_5600u64.into()), 344_060.0),
            (Target(Target::MAX_ATTAINABLE_REGTEST.0 / 0xffff_ffff_ffffu64.into()), 131_070.0),
            (Target::MAX_ATTAINABLE_MAINNET, 1.0),
        ];
        for (target, want) in targets {
            let got = target.difficulty_float_with_max(&Target::MAX_ATTAINABLE_MAINNET);
            // Since floating point will be imprecise at this scale,
            // We check very approximately.
            assert!((got - want).abs() < 0.05);
        }
    }

    #[test]
    #[should_panic(expected = "divide by zero")]
    fn target_difficulty_float_with_max_panics_on_zero() {
        let max_target = Target::MAX_ATTAINABLE_MAINNET;
        u64_to_target(0).difficulty_float_with_max(&max_target);
    }

    #[test]
    fn target_min_transition_threshold() {
        let targets = [
            4u128,
            0xff,
            u128::from(u64::MAX),
            u128::MAX,
        ];
        for target in targets {
            let got = Target(U256::from(target)).min_transition_threshold();
            let want = Target(U256::from(target / 4));
            assert_eq!(got, want);
        }
    }

    #[test]
    fn target_max_transition_threshold() {
        let targets = [
            1u128,
            0xff,
            u128::from(u64::MAX),
            u128::MAX >> 2,
        ];
        for target in targets {
            let got = Target(U256::from(target)).max_transition_threshold_unchecked();
            let want = Target(U256::from(target * 4));
            assert_eq!(got, want);
        }
    }

    #[test]
    fn max_target_from_compact() {
        // The highest possible target is defined as 0x1d00ffff
        let bits = 0x1d00_ffff_u32;
        let want = Target::MAX;
        let got = Target::from_compact(CompactTarget::from_consensus(bits));
        assert_eq!(got, want);
    }

    #[test]
    fn target_attainable_constants_from_original() {
        // The plain target values for the various nets from Bitcoin Core with no conversions.
        // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L88
        const MAX_MAINNET: Target = Target(U256(u128::MAX >> 32, u128::MAX));
        // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L208
        const MAX_TESTNET: Target = Target(U256(u128::MAX >> 32, u128::MAX));
        // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L411
        const MAX_REGTEST: Target = Target(U256(u128::MAX >> 1, u128::MAX));
        // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L348
        const MAX_SIGNET: Target = Target(U256(0x3_77aeu128 << 88, 0));

        assert_eq!(
            Target::MAX_ATTAINABLE_MAINNET,
            Target::from_compact(MAX_MAINNET.to_compact_lossy())
        );
        assert_eq!(
            Target::MAX_ATTAINABLE_TESTNET,
            Target::from_compact(MAX_TESTNET.to_compact_lossy())
        );
        assert_eq!(
            Target::MAX_ATTAINABLE_REGTEST,
            Target::from_compact(MAX_REGTEST.to_compact_lossy())
        );
        assert_eq!(
            Target::MAX_ATTAINABLE_SIGNET,
            Target::from_compact(MAX_SIGNET.to_compact_lossy())
        );
    }

    #[test]
    fn roundtrip_compact_target() {
        let consensus = 0x1d00_ffff;
        let compact = CompactTarget::from_consensus(consensus);
        let t = Target::from_compact(CompactTarget::from_consensus(consensus));
        assert_eq!(t, Target::from(compact)); // From/Into sanity check.

        let back = t.to_compact_lossy();
        assert_eq!(back, compact); // From/Into sanity check.

        assert_eq!(back.to_consensus(), consensus);
    }

    #[test]
    fn roundtrip_target_work() {
        let target = u32_to_target(0xdead_beef_u32);
        let work = target.to_work();
        let back = work.to_target();
        assert_eq!(back, target);
    }

    #[test]
    #[cfg(feature = "std")]
    fn work_log2() {
        // Compare work log2 to historical Bitcoin Core values found in Core logs.
        let tests: &[(u128, f64)] = &[
            // (chainwork, core log2)                // height
            (0x2_0002_0002, 33.000_022),                // 1
            (0xa97d_6704_1c5e_5159_6ee7, 79.405_055),     // 308004
            (0x1d_c45d_7939_4baa_8ab1_8b20, 84.895_644),   // 418141
            (0x8c8_5acb_7328_7e33_5d52_5b98, 91.134_654),  // 596624
            (0x2ef4_47e0_1d16_42c4_0a18_4ada, 93.553_183), // 738965
        ];

        for &(chainwork, core_log2) in tests {
            // Core log2 in the logs is rounded to 6 decimal places.
            let log2 = (u128_to_work(chainwork).log2() * 1e6).round() / 1e6;
            assert_eq!(log2, core_log2);
        }

        assert_eq!(Work(U256::ONE).log2(), 0.0);
        assert_eq!(Work(U256::MAX).log2(), 256.0);
    }

    #[test]
    fn u256_max_min_inverse_roundtrip() {
        let max = U256::MAX;

        for min in &[U256::ZERO, U256::ONE] {
            // lower target means more work required.
            assert_eq!(Target(max).to_work(), Work(U256::ONE));
            assert_eq!(Target(*min).to_work(), Work(max));

            assert_eq!(Work(max).to_target(), Target(U256::ONE));
            assert_eq!(Work(*min).to_target(), Target(max));
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "overflowed")]
    fn work_overflowing_addition_panics() { let _ = Work(U256::MAX) + Work(U256::ONE); }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "overflowed")]
    fn work_overflowing_subtraction_panics() { let _ = Work(U256::ZERO) - Work(U256::ONE); }
}
