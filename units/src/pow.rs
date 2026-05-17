// SPDX-License-Identifier: CC0-1.0

//! Proof-of-work related integer types.

use core::fmt::{self, Write as _};
use core::ops::{Add, Div, Mul, Not, Rem, Shl, Shr, Sub};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
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
            self.to_consensus().to_le_bytes(),
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
crate::decoder_newtype! {
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

    use internals::write_err;

    use super::ParseU256Error;

    /// An error consensus decoding an `CompactTarget`.
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

include!("../include/u256.rs");

impl U256 {
    /// Constructs a new `U256` from a prefixed hex string.
    fn from_hex(s: &str) -> Result<Self, PrefixedHexError> { parse_int::hex_u256_prefixed(s) }

    /// Constructs a new `U256` from an unprefixed hex string.
    fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError> {
        parse_int::hex_u256_unprefixed(s)
    }
}

macro_rules! impl_hex {
    ($hex:path, $lookup:expr) => {
        impl $hex for U256 {
            fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
                if f.alternate() {
                    f.write_str("0x")?;
                }

                #[allow(clippy::indexing_slicing)]
                for byte in self.to_be_bytes() {
                    let upper_idx = ((byte & 0xf0) >> 4) as usize;
                    let lower_idx = (byte & 0xf) as usize;
                    f.write_char($lookup[upper_idx])?;
                    f.write_char($lookup[lower_idx])?;
                }
                Ok(())
            }
        }
    };
}
impl_hex!(
    fmt::LowerHex,
    ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
);
impl_hex!(
    fmt::UpperHex,
    ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']
);

#[cfg(feature = "serde")]
impl serde::Serialize for U256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        struct DisplayHex(U256);

        impl fmt::Display for DisplayHex {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{:x}", self.0) }
        }

        if serializer.is_human_readable() {
            serializer.collect_str(&DisplayHex(*self))
        } else {
            let bytes = self.to_be_bytes();
            serializer.serialize_bytes(&bytes)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for U256 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de;

        if d.is_human_readable() {
            struct HexVisitor;

            impl de::Visitor<'_> for HexVisitor {
                type Value = U256;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("a 32 byte ASCII hex string")
                }

                fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    if s.len() != 64 {
                        return Err(de::Error::invalid_length(s.len(), &self));
                    }

                    U256::from_unprefixed_hex(s)
                        .map_err(|_| de::Error::invalid_value(de::Unexpected::Str(s), &self))
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl serde::de::Visitor<'_> for BytesVisitor {
                type Value = U256;

                fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                    f.write_str("a sequence of bytes")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    let b = v.try_into().map_err(|_| de::Error::invalid_length(v.len(), &self))?;
                    Ok(U256::from_be_bytes(b))
                }
            }

            d.deserialize_bytes(BytesVisitor)
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
    #[cfg(feature = "std")]
    use std::error::Error as _;

    #[cfg(feature = "encoding")]
    use encoding::Decoder as _;

    use super::*;

    impl U256 {
        fn bit_at(&self, index: usize) -> bool {
            assert!(index <= 255, "index out of bounds");

            let word = if index < 128 { self.1 } else { self.0 };
            (word & (1 << (index % 128))) != 0
        }

        /// Constructs a new U256 from a big-endian array of u64's
        fn from_array(a: [u64; 4]) -> Self {
            let mut ret = Self::ZERO;
            ret.0 = (u128::from(a[0]) << 64) ^ u128::from(a[1]);
            ret.1 = (u128::from(a[2]) << 64) ^ u128::from(a[3]);
            ret
        }
    }

    #[test]
    fn u256_num_bits() {
        assert_eq!(U256::from(255_u64).bits(), 8);
        assert_eq!(U256::from(256_u64).bits(), 9);
        assert_eq!(U256::from(300_u64).bits(), 9);
        assert_eq!(U256::from(60000_u64).bits(), 16);
        assert_eq!(U256::from(70000_u64).bits(), 17);

        let u = U256::from(u128::MAX) << 1;
        assert_eq!(u.bits(), 129);

        // Try to read the following lines out loud quickly
        let mut shl = U256::from(70000_u64);
        shl = shl << 100;
        assert_eq!(shl.bits(), 117);
        shl = shl << 100;
        assert_eq!(shl.bits(), 217);
        shl = shl << 100;
        assert_eq!(shl.bits(), 0);
    }

    #[test]
    fn u256_bit_at() {
        assert!(!U256::from(10_u64).bit_at(0));
        assert!(U256::from(10_u64).bit_at(1));
        assert!(!U256::from(10_u64).bit_at(2));
        assert!(U256::from(10_u64).bit_at(3));
        assert!(!U256::from(10_u64).bit_at(4));

        let u = U256(0xa000_0000_0000_0000_0000_0000_0000_0000, 0);
        assert!(u.bit_at(255));
        assert!(!u.bit_at(254));
        assert!(u.bit_at(253));
        assert!(!u.bit_at(252));
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "serde")]
    fn u256_serde() {
        let check = |uint, hex| {
            let json = format!("\"{}\"", hex);
            assert_eq!(::serde_json::to_string(&uint).unwrap(), json);
            assert_eq!(::serde_json::from_str::<U256>(&json).unwrap(), uint);

            let bin_encoded = bincode::serialize(&uint).unwrap();
            let bin_decoded: U256 = bincode::deserialize(&bin_encoded).unwrap();
            assert_eq!(bin_decoded, uint);
        };

        check(U256::ZERO, "0000000000000000000000000000000000000000000000000000000000000000");
        check(
            U256::from(0xDEAD_BEEF_u32),
            "00000000000000000000000000000000000000000000000000000000deadbeef",
        );
        check(
            U256::from_array([0xdd44, 0xcc33, 0xbb22, 0xaa11]),
            "000000000000dd44000000000000cc33000000000000bb22000000000000aa11",
        );
        check(U256::MAX, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        check(
            U256(
                0xDEAD_BEEA_A69B_455C_D41B_B662_A69B_4550,
                0xA69B_455C_D41B_B662_A69B_4555_DEAD_BEEF,
            ),
            "deadbeeaa69b455cd41bb662a69b4550a69b455cd41bb662a69b4555deadbeef",
        );

        assert!(::serde_json::from_str::<U256>(
            "\"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffg\""
        )
        .is_err()); // invalid char
        assert!(::serde_json::from_str::<U256>(
            "\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\""
        )
        .is_err()); // invalid length
        assert!(::serde_json::from_str::<U256>(
            "\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\""
        )
        .is_err()); // invalid length
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn u256_lower_hex() {
        assert_eq!(
            format!("{:x}", U256::from(0xDEAD_BEEF_u64)),
            "00000000000000000000000000000000000000000000000000000000deadbeef",
        );
        assert_eq!(
            format!("{:#x}", U256::from(0xDEAD_BEEF_u64)),
            "0x00000000000000000000000000000000000000000000000000000000deadbeef",
        );
        assert_eq!(
            format!("{:x}", U256::MAX),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        assert_eq!(
            format!("{:#x}", U256::MAX),
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn u256_upper_hex() {
        assert_eq!(
            format!("{:X}", U256::from(0xDEAD_BEEF_u64)),
            "00000000000000000000000000000000000000000000000000000000DEADBEEF",
        );
        assert_eq!(
            format!("{:#X}", U256::from(0xDEAD_BEEF_u64)),
            "0x00000000000000000000000000000000000000000000000000000000DEADBEEF",
        );
        assert_eq!(
            format!("{:X}", U256::MAX),
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        );
        assert_eq!(
            format!("{:#X}", U256::MAX),
            "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn u256_display() {
        assert_eq!(format!("{}", U256::from(100_u32)), "100",);
        assert_eq!(format!("{}", U256::ZERO), "0",);
        assert_eq!(format!("{}", U256::from(u64::MAX)), format!("{}", u64::MAX),);
        assert_eq!(
            format!("{}", U256::MAX),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935",
        );
    }

    macro_rules! check_format {
        ($($test_name:ident, $val:literal, $format_string:literal, $expected:literal);* $(;)?) => {
            $(
                #[test]
                #[cfg(feature = "alloc")]
                fn $test_name() {
                    assert_eq!(format!($format_string, U256::from($val)), $expected);
                }
            )*
        }
    }
    check_format! {
        check_fmt_0, 0_u32, "{}", "0";
        check_fmt_1, 0_u32, "{:2}", " 0";
        check_fmt_2, 0_u32, "{:02}", "00";

        check_fmt_3, 1_u32, "{}", "1";
        check_fmt_4, 1_u32, "{:2}", " 1";
        check_fmt_5, 1_u32, "{:02}", "01";

        check_fmt_10, 10_u32, "{}", "10";
        check_fmt_11, 10_u32, "{:2}", "10";
        check_fmt_12, 10_u32, "{:02}", "10";
        check_fmt_13, 10_u32, "{:3}", " 10";
        check_fmt_14, 10_u32, "{:03}", "010";

        check_fmt_20, 1_u32, "{:<2}", "1 ";
        check_fmt_21, 1_u32, "{:<02}", "01";
        check_fmt_22, 1_u32, "{:>2}", " 1"; // This is default but check it anyways.
        check_fmt_23, 1_u32, "{:>02}", "01";
        check_fmt_24, 1_u32, "{:^3}", " 1 ";
        check_fmt_25, 1_u32, "{:^03}", "001";
        // Sanity check, for integral types precision is ignored.
        check_fmt_30, 0_u32, "{:.1}", "0";
        check_fmt_31, 0_u32, "{:4.1}", "   0";
        check_fmt_32, 0_u32, "{:04.1}", "0000";

        check_fmt_33, 0_u32, "{:b}", "0";
        check_fmt_34, 0_u32, "{:#b}", "0b0";
        check_fmt_35, 42_u32, "{:b}", "101010";
        check_fmt_36, 42_u32, "{:#b}", "0b101010";
        check_fmt_37, 42_u32, "{:8b}", "  101010";
        check_fmt_38, 42_u32, "{:08b}", "00101010";
        check_fmt_39, 42_u32, "{:<8b}", "101010  ";
        check_fmt_40, 42_u32, "{:>8b}", "  101010";
        check_fmt_41, 42_u32, "{:^8b}", " 101010 ";
        check_fmt_42, 42_u32, "{:#10b}", "  0b101010";
        check_fmt_43, 42_u32, "{:#010b}", "0b00101010";
        check_fmt_44, 42_u32, "{:.4b}", "101010";
        check_fmt_45, 42_u32, "{:10.4b}", "    101010";

        check_fmt_46, 0_u32, "{:o}", "0";
        check_fmt_47, 0_u32, "{:#o}", "0o0";
        check_fmt_48, 42_u32, "{:o}", "52";
        check_fmt_49, 42_u32, "{:#o}", "0o52";
        check_fmt_50, 42_u32, "{:4o}", "  52";
        check_fmt_51, 42_u32, "{:04o}", "0052";
        check_fmt_52, 42_u32, "{:<4o}", "52  ";
        check_fmt_53, 42_u32, "{:>4o}", "  52";
        check_fmt_54, 42_u32, "{:^4o}", " 52 ";
        check_fmt_55, 42_u32, "{:#6o}", "  0o52";
        check_fmt_56, 42_u32, "{:#06o}", "0o0052";
        check_fmt_57, 42_u32, "{:.4o}", "52";
        check_fmt_58, 42_u32, "{:6.4o}", "    52";
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn u256_comp() {
        let small = U256::from_array([0, 0, 0, 10]);
        let big = U256::from_array([0, 0, 0x0209_E737_8231_E632, 0x8C8C_3EE7_0C64_4118]);
        let bigger = U256::from_array([0, 0, 0x0209_E737_8231_E632, 0x9C8C_3EE7_0C64_4118]);
        let biggest = U256::from_array([1, 0, 0x0209_E737_8231_E632, 0x5C8C_3EE7_0C64_4118]);

        assert!(small < big);
        assert!(big < bigger);
        assert!(bigger < biggest);
        assert!(bigger <= biggest);
        assert!(biggest <= biggest);
        assert!(bigger >= big);
        assert!(bigger >= small);
        assert!(small <= small);
    }

    const WANT: U256 =
        U256(0x1bad_cafe_dead_beef_deaf_babe_2bed_feed, 0xbaad_f00d_defa_ceda_11fe_d2ba_d1c0_ffe0);

    #[rustfmt::skip]
    const BE_BYTES: [u8; 32] = [
        0x1b, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe, 0x2b, 0xed, 0xfe, 0xed,
        0xba, 0xad, 0xf0, 0x0d, 0xde, 0xfa, 0xce, 0xda, 0x11, 0xfe, 0xd2, 0xba, 0xd1, 0xc0, 0xff, 0xe0,
    ];

    #[rustfmt::skip]
    const LE_BYTES: [u8; 32] = [
        0xe0, 0xff, 0xc0, 0xd1, 0xba, 0xd2, 0xfe, 0x11, 0xda, 0xce, 0xfa, 0xde, 0x0d, 0xf0, 0xad, 0xba,
        0xed, 0xfe, 0xed, 0x2b, 0xbe, 0xba, 0xaf, 0xde, 0xef, 0xbe, 0xad, 0xde, 0xfe, 0xca, 0xad, 0x1b,
    ];

    // Sanity check that we have the bytes in the correct big-endian order.
    #[test]
    fn sanity_be_bytes() {
        let mut out = [0_u8; 32];
        out[..16].copy_from_slice(&WANT.0.to_be_bytes());
        out[16..].copy_from_slice(&WANT.1.to_be_bytes());
        assert_eq!(out, BE_BYTES);
    }

    // Sanity check that we have the bytes in the correct little-endian order.
    #[test]
    fn sanity_le_bytes() {
        let mut out = [0_u8; 32];
        out[..16].copy_from_slice(&WANT.1.to_le_bytes());
        out[16..].copy_from_slice(&WANT.0.to_le_bytes());
        assert_eq!(out, LE_BYTES);
    }

    #[test]
    fn u256_to_be_bytes() {
        assert_eq!(WANT.to_be_bytes(), BE_BYTES);
    }

    #[test]
    fn u256_from_be_bytes() {
        assert_eq!(U256::from_be_bytes(BE_BYTES), WANT);
    }

    #[test]
    fn u256_to_le_bytes() {
        assert_eq!(WANT.to_le_bytes(), LE_BYTES);
    }

    #[test]
    fn u256_from_le_bytes() {
        assert_eq!(U256::from_le_bytes(LE_BYTES), WANT);
    }

    #[test]
    fn u256_from_u8() {
        let u = U256::from(0xbe_u8);
        assert_eq!(u, U256(0, 0xbe));
    }

    #[test]
    fn u256_from_u16() {
        let u = U256::from(0xbeef_u16);
        assert_eq!(u, U256(0, 0xbeef));
    }

    #[test]
    fn u256_from_u32() {
        let u = U256::from(0xdead_beef_u32);
        assert_eq!(u, U256(0, 0xdead_beef));
    }

    #[test]
    fn u256_from_u64() {
        let u = U256::from(0xdead_beef_cafe_babe_u64);
        assert_eq!(u, U256(0, 0xdead_beef_cafe_babe));
    }

    #[test]
    fn u256_from_u128() {
        let u = U256::from(0xdead_beef_cafe_babe_0123_4567_89ab_cdefu128);
        assert_eq!(u, U256(0, 0xdead_beef_cafe_babe_0123_4567_89ab_cdef));
    }

    macro_rules! test_from_unsigned_integer_type {
        ($($test_name:ident, $ty:ident);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    // Internal representation is big-endian.
                    let want = U256(0, 0xAB);

                    let x = 0xAB as $ty;
                    let got = U256::from(x);

                    assert_eq!(got, want);
                }
            )*
        }
    }
    test_from_unsigned_integer_type! {
        from_unsigned_integer_type_u8, u8;
        from_unsigned_integer_type_u16, u16;
        from_unsigned_integer_type_u32, u32;
        from_unsigned_integer_type_u64, u64;
        from_unsigned_integer_type_u128, u128;
    }

    #[test]
    fn u256_from_be_array_u64() {
        let array = [
            0x1bad_cafe_dead_beef,
            0xdeaf_babe_2bed_feed,
            0xbaad_f00d_defa_ceda,
            0x11fe_d2ba_d1c0_ffe0,
        ];

        let uint = U256::from_array(array);
        assert_eq!(uint, WANT);
    }

    #[test]
    fn u256_shift_left() {
        let u = U256::from(1_u32);
        assert_eq!(u << 0, u);
        assert_eq!(u << 1, U256::from(2_u64));
        assert_eq!(u << 63, U256::from(0x8000_0000_0000_0000_u64));
        assert_eq!(u << 64, U256::from_array([0, 0, 0x0000_0000_0000_0001, 0]));
        assert_eq!(u << 127, U256(0, 0x8000_0000_0000_0000_0000_0000_0000_0000));
        assert_eq!(u << 128, U256(1, 0));

        let x = U256(0, 0x8000_0000_0000_0000_0000_0000_0000_0000);
        assert_eq!(x << 1, U256(1, 0));
    }

    #[test]
    fn u256_shift_right() {
        let u = U256(1, 0);
        assert_eq!(u >> 0, u);
        assert_eq!(u >> 1, U256(0, 0x8000_0000_0000_0000_0000_0000_0000_0000));
        assert_eq!(u >> 127, U256(0, 2));
        assert_eq!(u >> 128, U256(0, 1));
    }

    #[test]
    fn u256_arithmetic() {
        let init = U256::from(0xDEAD_BEEF_DEAD_BEEF_u64);
        let copy = init;

        let add = init.wrapping_add(copy);
        assert_eq!(add, U256::from_array([0, 0, 1, 0xBD5B_7DDF_BD5B_7DDE]));
        // Bitshifts
        let shl = add << 88;
        assert_eq!(shl, U256::from_array([0, 0x01BD_5B7D, 0xDFBD_5B7D_DE00_0000, 0]));
        let shr = shl >> 40;
        assert_eq!(shr, U256::from_array([0, 0, 0x0001_BD5B_7DDF_BD5B, 0x7DDE_0000_0000_0000]));
        // Increment
        let mut incr = shr;
        incr = incr.wrapping_inc();
        assert_eq!(incr, U256::from_array([0, 0, 0x0001_BD5B_7DDF_BD5B, 0x7DDE_0000_0000_0001]));
        // Subtraction
        let sub = incr.wrapping_sub(init);
        assert_eq!(sub, U256::from_array([0, 0, 0x0001_BD5B_7DDF_BD5A, 0x9F30_4110_2152_4112]));
        // Multiplication
        let (mult, _) = sub.mul_u64(300);
        assert_eq!(mult, U256::from_array([0, 0, 0x0209_E737_8231_E632, 0x8C8C_3EE7_0C64_4118]));
        // Division
        assert_eq!(U256::from(105_u32) / U256::from(5_u32), U256::from(21_u32));
        let div = mult / U256::from(300_u32);
        assert_eq!(div, U256::from_array([0, 0, 0x0001_BD5B_7DDF_BD5A, 0x9F30_4110_2152_4112]));

        assert_eq!(U256::from(105_u32) % U256::from(5_u32), U256::ZERO);
        assert_eq!(U256::from(35_498_456_u32) % U256::from(3_435_u32), U256::from(1_166_u32));
        let rem_src = mult.wrapping_mul(U256::from(39842_u32)).wrapping_add(U256::from(9054_u32));
        assert_eq!(rem_src % U256::from(39_842_u32), U256::from(9_054_u32));
    }

    #[test]
    fn u256_bit_inversion() {
        let v = U256(1, 0);
        let want = U256(
            0xffff_ffff_ffff_ffff_ffff_ffff_ffff_fffe,
            0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
        );
        assert_eq!(!v, want);

        let v = U256(0x0c0c_0c0c_0c0c_0c0c_0c0c_0c0c_0c0c_0c0c, 0xeeee_eeee_eeee_eeee);
        let want = U256(
            0xf3f3_f3f3_f3f3_f3f3_f3f3_f3f3_f3f3_f3f3,
            0xffff_ffff_ffff_ffff_1111_1111_1111_1111,
        );
        assert_eq!(!v, want);
    }

    #[test]
    fn u256_mul_u64_by_one() {
        let v = U256::from(0xDEAD_BEEF_DEAD_BEEF_u64);
        assert_eq!(v, v.mul_u64(1_u64).0);
    }

    #[test]
    fn u256_mul_u64_by_zero() {
        let v = U256::from(0xDEAD_BEEF_DEAD_BEEF_u64);
        assert_eq!(U256::ZERO, v.mul_u64(0_u64).0);
    }

    #[test]
    fn u256_mul_u64() {
        let u64_val = U256::from(0xDEAD_BEEF_DEAD_BEEF_u64);

        let u96_res = u64_val.mul_u64(0xFFFF_FFFF).0;
        let u128_res = u96_res.mul_u64(0xFFFF_FFFF).0;
        let u160_res = u128_res.mul_u64(0xFFFF_FFFF).0;
        let u192_res = u160_res.mul_u64(0xFFFF_FFFF).0;
        let u224_res = u192_res.mul_u64(0xFFFF_FFFF).0;
        let u256_res = u224_res.mul_u64(0xFFFF_FFFF).0;

        assert_eq!(u96_res, U256::from_array([0, 0, 0xDEAD_BEEE, 0xFFFF_FFFF_2152_4111]));
        assert_eq!(
            u128_res,
            U256::from_array([0, 0, 0xDEAD_BEEE_2152_4110, 0x2152_4111_DEAD_BEEF])
        );
        assert_eq!(
            u160_res,
            U256::from_array([0, 0xDEAD_BEED, 0x42A4_8222_0000_0001, 0xBD5B_7DDD_2152_4111])
        );
        assert_eq!(
            u192_res,
            U256::from_array([
                0,
                0xDEAD_BEEC_63F6_C334,
                0xBD5B_7DDF_BD5B_7DDB,
                0x63F6_C333_DEAD_BEEF
            ])
        );
        assert_eq!(
            u224_res,
            U256::from_array([
                0xDEAD_BEEB,
                0x8549_0448_5964_BAAA,
                0xFFFF_FFFB_A69B_4558,
                0x7AB6_FBBB_2152_4111
            ])
        );
        assert_eq!(
            u256_res,
            U256(
                0xDEAD_BEEA_A69B_455C_D41B_B662_A69B_4550,
                0xA69B_455C_D41B_B662_A69B_4555_DEAD_BEEF,
            )
        );
    }

    #[test]
    fn u256_addition() {
        let x = U256::from(u128::MAX);
        let (add, overflow) = x.overflowing_add(U256::ONE);
        assert!(!overflow);
        assert_eq!(add, U256(1, 0));

        let (add, _) = add.overflowing_add(U256::ONE);
        assert_eq!(add, U256(1, 1));
    }

    #[test]
    fn u256_subtraction() {
        let (sub, overflow) = U256::ONE.overflowing_sub(U256::ONE);
        assert!(!overflow);
        assert_eq!(sub, U256::ZERO);

        let x = U256(1, 0);
        let (sub, overflow) = x.overflowing_sub(U256::ONE);
        assert!(!overflow);
        assert_eq!(sub, U256::from(u128::MAX));
    }

    #[test]
    fn u256_multiplication() {
        let u64_val = U256::from(0xDEAD_BEEF_DEAD_BEEF_u64);

        let u128_res = u64_val.wrapping_mul(u64_val);

        assert_eq!(u128_res, U256(0, 0xC1B1_CD13_A4D1_3D46_048D_1354_216D_A321));

        let u256_res = u128_res.wrapping_mul(u128_res);

        assert_eq!(
            u256_res,
            U256(
                0x928D_92B4_D7F5_DF33_4AFC_FF6F_0375_C608,
                0xF5CF_7F36_18C2_C886_F4E1_66AA_D40D_0A41,
            )
        );
    }

    #[test]
    fn u256_multiplication_bits_in_each_word() {
        // Put a digit in the least significant bit of each 64 bit word.
        let u = (1_u128 << 64) | 1_u128;
        let x = U256(u, u);

        // Put a digit in the second least significant bit of each 64 bit word.
        let u = (2_u128 << 64) | 2_u128;
        let y = U256(u, u);

        let (got, overflow) = x.overflowing_mul(y);

        let want = U256(
            0x0000_0000_0000_0008_0000_0000_0000_0006,
            0x0000_0000_0000_0004_0000_0000_0000_0002,
        );
        assert!(overflow);
        assert_eq!(got, want);
    }

    #[test]
    fn u256_overflowing_mul() {
        let a = U256(u128::MAX, 0);
        let b = U256(1 << 65 | 1, 0);
        let (res, overflow) = a.overflowing_mul(b);
        assert_eq!(res, U256::ZERO);
        assert!(overflow);

        let a = U256(1 << 64, 0);
        let b = U256(1, 0);
        let (res, overflow) = a.overflowing_mul(b);
        assert_eq!(res, U256::ZERO);
        assert!(overflow);

        let a = U256(0, 1 << 63);
        let b = U256(1, 0);
        let (res, overflow) = a.overflowing_mul(b);
        assert_eq!(res, b << 63);
        assert!(!overflow);

        let (res, overflow) = U256::ONE.overflowing_mul(U256::ONE);
        assert_eq!(res, U256::ONE);
        assert!(!overflow);

        // Simple case near upper edge
        let a = U256(1 << 125, 0);
        let b = U256(0, 4);
        let (res, overflow) = a.overflowing_mul(b);
        assert_eq!(res, U256(1 << 127, 0));
        assert!(!overflow);

        // Check case where bits overflow during shift. Kills * -> + and - -> + mutants.
        let a = U256::ONE << 2;
        let b = U256::ONE << 254;
        let (res, overflow) = a.overflowing_mul(b);
        assert_eq!(res, U256::ZERO);
        assert!(overflow);

        // mul_u64 overflows twice but no other overflows. Kills |= -> ^= mutant.
        let a = U256::ONE << 255;
        let b = U256(1 << 1 | 1 << 65, 0);
        let (res, overflow) = a.overflowing_mul(b);
        assert_eq!(res, U256::ZERO);
        assert!(overflow);
    }

    #[test]
    fn u256_increment() {
        let mut val = U256(
            0xEFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFE,
        );
        val = val.wrapping_inc();
        assert_eq!(
            val,
            U256(
                0xEFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
                0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
            )
        );
        val = val.wrapping_inc();
        assert_eq!(
            val,
            U256(
                0xF000_0000_0000_0000_0000_0000_0000_0000,
                0x0000_0000_0000_0000_0000_0000_0000_0000,
            )
        );

        assert_eq!(U256::MAX.wrapping_inc(), U256::ZERO);
    }

    #[test]
    fn u256_extreme_bitshift() {
        // Shifting a u64 by 64 bits gives an undefined value, so make sure that
        // we're doing the Right Thing here
        let init = U256::from(0xDEAD_BEEF_DEAD_BEEF_u64);

        assert_eq!(init << 64, U256(0, 0xDEAD_BEEF_DEAD_BEEF_0000_0000_0000_0000));
        let add = (init << 64).wrapping_add(init);
        assert_eq!(add, U256(0, 0xDEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF));
        assert_eq!(add >> 0, U256(0, 0xDEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF));
        assert_eq!(add << 0, U256(0, 0xDEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF));
        assert_eq!(add >> 64, U256(0, 0x0000_0000_0000_0000_DEAD_BEEF_DEAD_BEEF));
        assert_eq!(
            add << 64,
            U256(0xDEAD_BEEF_DEAD_BEEF, 0xDEAD_BEEF_DEAD_BEEF_0000_0000_0000_0000)
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn u256_to_from_hex_roundtrips() {
        let val = U256(
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
        let val = U256(
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
        let want = U256(0x00, 0xA69B_455C_D41B_B662_A69B_4555_DEAD_BEEF);
        let got = U256::from_unprefixed_hex(hex).expect("failed to parse hex");
        assert_eq!(got, want);
    }

    #[test]
    fn u256_is_max_correct_negative() {
        let tc = [U256::ZERO, U256::ONE, U256::from(u128::MAX)];
        for t in tc {
            assert!(!t.is_max());
        }
    }

    #[test]
    fn u256_is_max_correct_positive() {
        assert!(U256::MAX.is_max());

        let u = u128::MAX;
        assert!(((U256::from(u) << 128) + U256::from(u)).is_max());
    }

    #[test]
    fn u256_zero_min_max_inverse() {
        assert_eq!(U256::MAX.inverse(), U256::ONE);
        assert_eq!(U256::ONE.inverse(), U256::MAX);
        assert_eq!(U256::ZERO.inverse(), U256::MAX);
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
    fn u256_wrapping_add_wraps_at_boundary() {
        assert_eq!(U256::MAX.wrapping_add(U256::ONE), U256::ZERO);
        assert_eq!(U256::MAX.wrapping_add(U256::from(2_u8)), U256::ONE);
    }

    #[test]
    fn u256_wrapping_sub_wraps_at_boundary() {
        assert_eq!(U256::ZERO.wrapping_sub(U256::ONE), U256::MAX);
        assert_eq!(U256::ONE.wrapping_sub(U256::from(2_u8)), U256::MAX);
    }

    #[test]
    fn mul_u64_overflows() {
        let (_, overflow) = U256::MAX.mul_u64(2);
        assert!(overflow, "max * 2 should overflow");
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "overflowed")]
    fn u256_overflowing_addition_panics() { let _ = U256::MAX + U256::ONE; }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "overflowed")]
    fn u256_overflowing_subtraction_panics() { let _ = U256::ZERO - U256::ONE; }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "overflowed")]
    fn u256_multiplication_by_max_panics() { let _ = U256::MAX * U256::MAX; }

    #[test]
    fn u256_to_f64() {
        assert_eq!(U256::ZERO.to_f64(), 0.0_f64);
        assert_eq!(U256::ONE.to_f64(), 1.0_f64);
        assert_eq!(U256::MAX.to_f64(), 1.157_920_892_373_162e77_f64);
        assert_eq!((U256::MAX >> 1).to_f64(), 5.789_604_461_865_81e76_f64);
        assert_eq!((U256::MAX >> 128).to_f64(), 3.402_823_669_209_385e38_f64);
        assert_eq!((U256::MAX >> (256 - 54)).to_f64(), 1.801_439_850_948_198_4e16_f64);
        // 53 bits and below should not use exponents
        assert_eq!((U256::MAX >> (256 - 53)).to_f64(), 9_007_199_254_740_991.0_f64);
        assert_eq!((U256::MAX >> (256 - 32)).to_f64(), 4_294_967_295.0_f64);
        assert_eq!((U256::MAX >> (256 - 16)).to_f64(), 65535.0_f64);
        assert_eq!((U256::MAX >> (256 - 8)).to_f64(), 255.0_f64);
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
    fn target_from_compact() {
        // (nBits, target)
        let tests = [
            (0x0100_3456_u32, 0x00_u64), // High bit set.
            (0x0112_3456_u32, 0x12_u64),
            (0x0200_8000_u32, 0x80_u64),
            (0x0500_9234_u32, 0x9234_0000_u64),
            (0x0492_3456_u32, 0x00_u64), // High bit set (0x80 in 0x92).
            (0x0412_3456_u32, 0x1234_5600_u64), // Inverse of above; no high bit.
        ];

        for (n_bits, target) in tests {
            let want = Target(U256::from(target));
            let got = Target::from_compact(CompactTarget::from_consensus(n_bits));
            assert_eq!(got, want);
        }
    }

    macro_rules! check_from_str {
        ($ty:ident, $err_ty:ident, $mod_name:ident) => {
            #[cfg(feature = "alloc")]
            mod $mod_name {
                use alloc::string::ToString;
                use core::str::FromStr;

                use super::{$err_ty, $ty, ParseU256Error, U256};

                #[test]
                fn target_from_str_decimal() {
                    assert_eq!($ty::from_str("0").unwrap(), $ty(U256::ZERO));
                    assert_eq!("1".parse::<$ty>().unwrap(), $ty(U256(0, 1)));
                    assert_eq!("123456789".parse::<$ty>().unwrap(), $ty(U256(0, 123_456_789)));

                    let str_tgt = "340282366920938463463374607431768211455";
                    let got = str_tgt.parse::<$ty>().unwrap();
                    assert_eq!(got, $ty(u128::MAX.into()));

                    // 2^128
                    let str_tgt = "340282366920938463463374607431768211456";
                    let got = str_tgt.parse::<$ty>().unwrap();
                    assert_eq!(got, $ty(U256(1, 0)));

                    // 2^256 - 1
                    let str_tgt = concat!(
                        "115792089237316195423570985008687907853",
                        "269984665640564039457584007913129639935"
                    );
                    let got = str_tgt.parse::<$ty>().unwrap();
                    assert_eq!(got, $ty(U256::MAX));

                    // Padding
                    let got = "00000000000042".parse::<$ty>().unwrap();
                    assert_eq!(got, $ty(U256(0, 42)));

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

        assert_eq!(back.to_consensus(), consensus);
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
        let max_mainnet: Target = Target(U256(u128::MAX >> 32, u128::MAX));
        // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L208
        let max_testnet: Target = Target(U256(u128::MAX >> 32, u128::MAX));
        // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L411
        let max_regtest: Target = Target(U256(u128::MAX >> 1, u128::MAX));
        // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L348
        let max_signet: Target = Target(U256(0x3_77aeu128 << 88, 0));

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
        assert_eq!(compact_target.to_consensus(), bits);
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[allow(deprecated)]
    fn compact_target_to_hex() {
        let compact_target = CompactTarget::from_consensus(0x1d00_ffff);
        assert_eq!(compact_target.to_hex(), "1d00ffff");
    }

    #[test]
    #[cfg(feature = "encoding")]
    #[cfg(feature = "alloc")]
    fn compact_target_decoder_error_display_and_source() {
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
}
