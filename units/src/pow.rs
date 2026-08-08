// SPDX-License-Identifier: CC0-1.0

//! Proof-of-work related integer types.

use core::fmt;
use core::ops::{Add, Sub};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use internals::u256::U256;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::internal_macros::impl_fmt_traits_for_u32_wrapper;
use crate::parse_int::{self, PrefixedHexError, UnprefixedHexError};

#[rustfmt::skip]                // Keep public re-exports separate.
#[cfg(feature = "encoding")]
#[doc(no_inline)]
pub use self::error::CompactTargetDecoderError;
#[doc(no_inline)]
pub use self::error::{ParseTargetError, ParseWorkError};

/// Implement traits and methods shared by `Target` and `Work`.
macro_rules! do_impl {
    ($ty:ident, $err_ty:ident) => {
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

        impl core::str::FromStr for $ty {
            type Err = $err_ty;

            #[inline]
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                U256::from_str(s).map($ty).map_err($err_ty)
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
}

do_impl!(Work, ParseWorkError);
impl_fmt_traits_for_u32_wrapper!(Work);

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
/// [`Target`] does not limit its value to the maximum attainable value for any network when it
/// is constructed. If you need to enforce that invariant, you should compare the constructed value
/// against the required network's `MAX_ATTAINABLE_*` target constant.
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
    pub const MAX: Self = Self(U256::new(0xFFFF_u128 << (208 - 128), 0));

    /// The maximum **attainable** target value on mainnet.
    ///
    /// Not all target values are attainable because consensus code uses the compact format to
    /// represent targets (see [`CompactTarget`]).
    // Taken from Bitcoin Core but had lossy conversion to/from compact form.
    // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L88
    pub const MAX_ATTAINABLE_MAINNET: Self = Self(U256::new(0xFFFF_u128 << (208 - 128), 0));

    /// The maximum **attainable** target value on testnet.
    // Taken from Bitcoin Core but had lossy conversion to/from compact form.
    // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L208
    pub const MAX_ATTAINABLE_TESTNET: Self = Self(U256::new(0xFFFF_u128 << (208 - 128), 0));

    /// The maximum **attainable** target value on regtest.
    // Taken from Bitcoin Core but had lossy conversion to/from compact form.
    // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L411
    pub const MAX_ATTAINABLE_REGTEST: Self = Self(U256::new(0x7FFF_FF00u128 << 96, 0));

    /// The maximum **attainable** target value on signet.
    // Taken from Bitcoin Core but had lossy conversion to/from compact form.
    // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L348
    pub const MAX_ATTAINABLE_SIGNET: Self = Self(U256::new(0x0377_ae00 << 80, 0));

    /// Computes the [`Target`] value from a compact representation.
    ///
    /// ref: <https://developer.bitcoin.org/reference/block_chain.html#target-nbits>
    pub fn from_compact(c: CompactTarget) -> Self {
        let bits = c.to_consensus_u32();
        // This is a floating-point "compact" encoding originally used by
        // OpenSSL, which satoshi put into consensus code, so we're stuck
        // with it. The exponent needs to have 3 subtracted from it, hence
        // this goofy decoding code. 3 is due to 3 bytes in the mantissa.
        let unshifted_expt = bits >> 24;
        let (mant, expt) = {
            if unshifted_expt <= 3 {
                ((bits & 0xFF_FFFF) >> (8 * (3 - unshifted_expt as usize)), 0)
            } else {
                (bits & 0xFF_FFFF, 8 * ((bits >> 24) - 3))
            }
        };
        let overflow = mant != 0
            && (unshifted_expt > 34
                || (mant > 0xFF && unshifted_expt > 33)
                || (mant > 0xFFFF && unshifted_expt > 32));

        // The mantissa is signed but may not be negative or overflow.
        if mant > 0x7F_FFFF || overflow {
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
}
do_impl!(Target, ParseTargetError);
impl_fmt_traits_for_u32_wrapper!(Target);

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
    #[deprecated(since = "TBD", note = "use 'to_consensus_u32()' instead")]
    #[inline]
    pub const fn to_consensus(self) -> u32 { self.0 }

    /// Returns the consensus encoded `u32` representation of this [`CompactTarget`].
    #[inline]
    pub const fn to_consensus_u32(self) -> u32 { self.0 }

    /// Computes the [`Target`] value from this compact representation.
    ///
    /// ref: <https://developer.bitcoin.org/reference/block_chain.html#target-nbits>
    pub fn to_target(self) -> Target { Target::from_compact(self) }

    /// Constructs a new `CompactTarget` from a prefixed hex string.
    ///
    /// # Errors
    ///
    /// - If the input string does not contain a `0x` (or `0X`) prefix.
    /// - If the input string is not a valid hex encoding of a `u32`.
    #[inline]
    pub fn from_hex(s: &str) -> Result<Self, PrefixedHexError>
    where
        Self: Sized,
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
    #[inline]
    pub fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError>
    where
        Self: Sized,
    {
        let target = parse_int::hex_u32_unprefixed(s)?;
        Ok(Self::from_consensus(target))
    }
}

crate::internal_macros::impl_fmt_traits_for_u32_wrapper!(CompactTarget);

impl fmt::Display for CompactTarget {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

parse_int::impl_parse_str_from_int_infallible!(CompactTarget, u32, from_consensus);

impl From<CompactTarget> for Target {
    fn from(c: CompactTarget) -> Self { Self::from_compact(c) }
}

#[cfg(feature = "encoding")]
impl encoding::Encode for CompactTarget {
    type Encoder<'e> = CompactTargetEncoder<'e>;
    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        CompactTargetEncoder::new(encoding::ArrayEncoder::without_length_prefix(
            self.to_consensus_u32().to_le_bytes(),
        ))
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for CompactTarget {
    type Decoder = CompactTargetDecoder;
}

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// The encoder for the [`CompactTarget`] type.
    #[derive(Debug, Clone)]
    pub struct CompactTargetEncoder<'e>(encoding::ArrayEncoder<4>);
}

#[cfg(feature = "encoding")]
internals::decoder_newtype! {
    /// The decoder for the [`CompactTarget`] type.
    #[derive(Debug, Clone)]
    pub struct CompactTargetDecoder(encoding::ArrayDecoder<4>);

    /// Constructs a new [`CompactTarget`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }

    fn end(result: Result<[u8; 4], encoding::UnexpectedEofError>) -> Result<CompactTarget, CompactTargetDecoderError> {
        let value = result.map_err(CompactTargetDecoderError)?;
        let n = u32::from_le_bytes(value);
        Ok(CompactTarget::from_consensus(n))
    }
}

/// Error types for proof-of-work related integer types.
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    use internals::u256::ParseU256Error;
    use internals::write_err;

    /// An error consensus decoding a `CompactTarget`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[cfg(feature = "encoding")]
    pub struct CompactTargetDecoderError(pub(super) encoding::UnexpectedEofError);

    #[cfg(feature = "encoding")]
    impl From<Infallible> for CompactTargetDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    #[cfg(feature = "encoding")]
    impl fmt::Display for CompactTargetDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write_err!(f, "compact target decoder error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    #[cfg(feature = "encoding")]
    impl std::error::Error for CompactTargetDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }

    /// Error returned when parsing a [`Work`] from a string.
    ///
    /// [`Work`]: super::Work
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ParseWorkError(pub(super) ParseU256Error);

    impl From<Infallible> for ParseWorkError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for ParseWorkError {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write_err!(f, "work parse error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for ParseWorkError {
        #[inline]
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }

    /// Error returned when parsing a [`Target`] from a string.
    ///
    /// [`Target`]: super::Target
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ParseTargetError(pub(super) ParseU256Error);

    impl From<Infallible> for ParseTargetError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for ParseTargetError {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write_err!(f, "target parse error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for ParseTargetError {
        #[inline]
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for CompactTarget {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_consensus(u.arbitrary()?))
    }
}

/// Extension functionality for [`U256`] that is specific to `units` (hex parsing that goes
/// through `units::parse_int`).
trait U256Ext: Sized {
    /// Constructs a new `U256` from a prefixed hex string.
    fn from_hex(s: &str) -> Result<Self, PrefixedHexError>;

    /// Constructs a new `U256` from an unprefixed hex string.
    fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError>;
}

impl U256Ext for U256 {
    fn from_hex(s: &str) -> Result<Self, PrefixedHexError> { parse_int::hex_u256_prefixed(s) }

    fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError> {
        parse_int::hex_u256_unprefixed(s)
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
    use encoding::Decoder as _;

    use super::*;

    #[test]
    fn u256_to_from_hex_roundtrips() {
        let val = U256::new(
            0xDEAD_BEEA_A69B_455C_D41B_B662_A69B_4550,
            0xA69B_455C_D41B_B662_A69B_4555_DEAD_BEEF,
        );
        let hex = format!("0x{:x}", val);
        let got = U256::from_hex(&hex).expect("failed to parse hex");
        assert_eq!(got, val);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn u256_to_from_unprefixed_hex_roundtrips() {
        let val = U256::new(
            0xDEAD_BEEA_A69B_455C_D41B_B662_A69B_4550,
            0xA69B_455C_D41B_B662_A69B_4555_DEAD_BEEF,
        );
        let hex = format!("{:x}", val);
        let got = U256::from_unprefixed_hex(&hex).expect("failed to parse hex");
        assert_eq!(got, val);
    }

    #[test]
    fn u256_from_hex_32_characters_long() {
        let hex = "a69b455cd41bb662a69b4555deadbeef";
        let want = U256::new(0x00, 0xA69B_455C_D41B_B662_A69B_4555_DEAD_BEEF);
        let got = U256::from_unprefixed_hex(hex).expect("failed to parse hex");
        assert_eq!(got, want);
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

    #[test]
    fn compact_to_target() {
        // (nBits, target)
        let tests = [
            (0x0100_3456_u32, 0x00_u64), // High bit set.
            (0x0112_3456_u32, 0x12_u64),
            (0x0200_8000_u32, 0x80_u64),
            (0x0500_9234_u32, 0x9234_0000_u64),
            (0x0492_3456_u32, 0x00_u64), // High bit set (0x80 in 0x92).
            (0x0412_3456_u32, 0x1234_5600_u64), // Inverse of above; no high bit.
            (0x2101_0000_u32, 0x00_u64), // Overflows 256 bits.
            (0x2200_0100_u32, 0x00_u64), // Overflows 256 bits.
            (0x2200_0101_u32, 0x00_u64), // Overflows 256 bits.
            (0x2300_0001_u32, 0x00_u64), // Overflows 256 bits.
        ];

        for (n_bits, target) in tests {
            let want = Target(U256::from(target));
            let got = CompactTarget::from_consensus(n_bits).to_target();
            assert_eq!(got, want);
        }
    }

    #[test]
    fn compact_to_target_overflow_boundaries() {
        let tests = [
            (0x2100_FFFF_u32, Target(U256::from(0xFFFF_u32) << 240)),
            (0x2200_00FF_u32, Target(U256::from(0xFF_u32) << 248)),
        ];

        for (n_bits, want) in tests {
            let got = CompactTarget::from_consensus(n_bits).to_target();
            assert_eq!(got, want);
        }
    }

    macro_rules! check_from_str {
        ($ty:ident, $err_ty:ident, $mod_name:ident) => {
            #[cfg(feature = "alloc")]
            mod $mod_name {
                use alloc::string::ToString;
                use core::str::FromStr;

                use internals::u256::ParseU256Error;

                use super::{$err_ty, $ty, U256};

                #[test]
                fn target_from_str_decimal() {
                    assert_eq!($ty::from_str("0").unwrap(), $ty(U256::ZERO));
                    assert_eq!("1".parse::<$ty>().unwrap(), $ty(U256::new(0, 1)));
                    assert_eq!("123456789".parse::<$ty>().unwrap(), $ty(U256::new(0, 123_456_789)));

                    let str_tgt = "340282366920938463463374607431768211455";
                    let got = str_tgt.parse::<$ty>().unwrap();
                    assert_eq!(got, $ty(u128::MAX.into()));

                    // 2^128
                    let str_tgt = "340282366920938463463374607431768211456";
                    let got = str_tgt.parse::<$ty>().unwrap();
                    assert_eq!(got, $ty(U256::new(1, 0)));

                    // 2^256 - 1
                    let str_tgt = concat!(
                        "115792089237316195423570985008687907853",
                        "269984665640564039457584007913129639935"
                    );
                    let got = str_tgt.parse::<$ty>().unwrap();
                    assert_eq!(got, $ty(U256::MAX));

                    // Padding
                    let got = "00000000000042".parse::<$ty>().unwrap();
                    assert_eq!(got, $ty(U256::new(0, 42)));

                    // roundtrip
                    let want = $ty(u128::MAX.into());
                    let got = want.to_string().parse::<$ty>().unwrap();
                    assert_eq!(got, want);
                }

                #[test]
                fn target_from_str_error() {
                    assert!(matches!(
                        "".parse::<$ty>().unwrap_err(),
                        $err_ty(ParseU256Error::Empty),
                    ));
                    assert!(matches!(
                        "12a34".parse::<$ty>().unwrap_err(),
                        $err_ty(ParseU256Error::InvalidDigit(_)),
                    ));
                    assert!(matches!(
                        " 42".parse::<$ty>().unwrap_err(),
                        $err_ty(ParseU256Error::InvalidDigit(_)),
                    ));
                    assert!(matches!(
                        "-1".parse::<$ty>().unwrap_err(),
                        $err_ty(ParseU256Error::InvalidDigit(_)),
                    ));

                    assert!(matches!(
                        "1157ééééé92089237316195423570985008687907853".parse::<$ty>().unwrap_err(),
                        $err_ty(ParseU256Error::InvalidEncoding(_)),
                    ));

                    // 2^256
                    let tgt_str = concat!(
                        "115792089237316195423570985008687907853",
                        "269984665640564039457584007913129639936"
                    );
                    assert!(matches!(
                        tgt_str.parse::<$ty>().unwrap_err(),
                        $err_ty(ParseU256Error::Overflow),
                    ));
                }
            }
        };
    }

    check_from_str!(Target, ParseTargetError, target_from_str);
    check_from_str!(Work, ParseWorkError, work_from_str);

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
            let got = Target(U256::from(target)).to_compact_lossy();
            assert_eq!(got, want);
        }
    }

    #[test]
    fn roundtrip_compact_target() {
        let consensus = 0x1d00_ffff;
        let compact = CompactTarget::from_consensus(consensus);
        let t = Target::from_compact(CompactTarget::from_consensus(consensus));
        assert_eq!(t, Target::from(compact)); // From/Into sanity check.

        let back = t.to_compact_lossy();
        assert_eq!(back, compact); // From/Into sanity check.

        assert_eq!(back.to_consensus_u32(), consensus);
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
        let max_mainnet: Target = Target(U256::new(u128::MAX >> 32, u128::MAX));
        // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L208
        let max_testnet: Target = Target(U256::new(u128::MAX >> 32, u128::MAX));
        // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L411
        let max_regtest: Target = Target(U256::new(u128::MAX >> 1, u128::MAX));
        // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L348
        let max_signet: Target = Target(U256::new(0x3_77aeu128 << 88, 0));

        assert_eq!(
            Target::MAX_ATTAINABLE_MAINNET,
            Target::from_compact(max_mainnet.to_compact_lossy())
        );
        assert_eq!(
            Target::MAX_ATTAINABLE_TESTNET,
            Target::from_compact(max_testnet.to_compact_lossy())
        );
        assert_eq!(
            Target::MAX_ATTAINABLE_REGTEST,
            Target::from_compact(max_regtest.to_compact_lossy())
        );
        assert_eq!(
            Target::MAX_ATTAINABLE_SIGNET,
            Target::from_compact(max_signet.to_compact_lossy())
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn target_max_attainable_hex() {
        // Also check explicit hex representations for regression testing.
        assert_eq!(
            format!("{:x}", Target::MAX_ATTAINABLE_MAINNET),
            "00000000ffff0000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            format!("{:x}", Target::MAX_ATTAINABLE_TESTNET),
            "00000000ffff0000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            format!("{:x}", Target::MAX_ATTAINABLE_REGTEST),
            "7fffff0000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            format!("{:x}", Target::MAX_ATTAINABLE_SIGNET),
            "00000377ae000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    #[cfg(feature = "encoding")]
    fn compact_target_decoder_read_limit() {
        // read_limit is one u32 = 4 bytes for empty decoder
        assert_eq!(CompactTargetDecoder::default().read_limit(), 4);
        assert_eq!(<CompactTarget as encoding::Decode>::decoder().read_limit(), 4);
    }

    #[test]
    #[cfg(feature = "encoding")]
    fn compact_target_decoder_round_trip() {
        let bits: u32 = 0x1d00_ffff;
        let compact_target =
            encoding::decode_from_slice::<CompactTarget>(&bits.to_le_bytes()).unwrap();
        assert_eq!(compact_target.to_consensus_u32(), bits);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn compact_target_to_hex() {
        let compact_target = CompactTarget::from_consensus(0x1d00_ffff);
        let got = alloc::format!("{:x}", compact_target);
        assert_eq!(got, "1d00ffff");
    }

    #[test]
    #[cfg(feature = "encoding")]
    #[cfg(feature = "alloc")]
    fn compact_target_decoder_error_display_and_source() {
        #[cfg(feature = "std")]
        use std::error::Error as _;

        let mut slice = [0u8; 3].as_slice();
        let mut decoder = CompactTargetDecoder::new();

        assert!(decoder.push_bytes(&mut slice).unwrap().needs_more());

        let err = decoder.end().unwrap_err();
        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_some());
    }

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
        assert_eq!(format!("{}", compact_target), "486604799");
        assert_eq!(format!("{:x}", compact_target), "1d00ffff");
        assert_eq!(format!("{:#x}", compact_target), "0x1d00ffff");
        assert_eq!(format!("{:X}", compact_target), "1D00FFFF");
        assert_eq!(format!("{:#X}", compact_target), "0x1D00FFFF");
        assert_eq!(format!("{:o}", compact_target), "3500177777");
        assert_eq!(format!("{:#o}", compact_target), "0o3500177777");
        assert_eq!(format!("{:b}", compact_target), "11101000000001111111111111111");
        assert_eq!(format!("{:#b}", compact_target), "0b11101000000001111111111111111");
        assert_eq!(compact_target.to_consensus_u32(), 0x1d00_ffff);
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
}
