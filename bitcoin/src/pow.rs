// Rust Bitcoin Library - Written by the rust-bitcoin developers.
// SPDX-License-Identifier: CC0-1.0

//! Proof-of-work related integer types.
//!
//! Provides the [`Work`] and [`Target`] types that are use in proof-of-work calculations. The
//! functions here are designed to be fast, by that we mean it is safe to use them to check headers.
//!

use core::fmt::{self, LowerHex, UpperHex};
use core::ops::{Add, Div, Mul, Not, Rem, Shl, Shr, Sub};

#[cfg(all(test, mutate))]
use mutagen::mutate;

use crate::consensus::encode::{self, Decodable, Encodable};
#[cfg(doc)]
use crate::consensus::Params;
use crate::hash_types::BlockHash;
use crate::io::{self, Read, Write};
use crate::prelude::String;
use crate::string::FromHexStr;

/// Implement traits and methods shared by `Target` and `Work`.
macro_rules! do_impl {
    ($ty:ident) => {
        impl $ty {
            /// Creates `Self` from a big-endian byte array.
            #[inline]
            pub fn from_be_bytes(bytes: [u8; 32]) -> $ty { $ty(U256::from_be_bytes(bytes)) }

            /// Creates `Self` from a little-endian byte array.
            #[inline]
            pub fn from_le_bytes(bytes: [u8; 32]) -> $ty { $ty(U256::from_le_bytes(bytes)) }

            /// Converts `self` to a big-endian byte array.
            #[inline]
            pub fn to_be_bytes(self) -> [u8; 32] { self.0.to_be_bytes() }

            /// Converts `self` to a little-endian byte array.
            #[inline]
            pub fn to_le_bytes(self) -> [u8; 32] { self.0.to_le_bytes() }
        }

        impl fmt::Display for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
        }

        impl fmt::LowerHex for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
        }

        impl fmt::UpperHex for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::UpperHex::fmt(&self.0, f) }
        }
    };
}

/// A 256 bit integer representing work.
///
/// Work is a measure of how difficult it is to find a hash below a given [`Target`].
///
/// ref: <https://en.bitcoin.it/wiki/Work>
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Work(U256);

impl Work {
    /// Lowest possible work value for Mainnet. See comment on [`Params::pow_limit`] for more info.
    pub const MAINNET_MIN: Work = Work(U256(0x0000_0000_ffff_0000_0000_0000_0000_0000_u128, 0));

    /// Lowest possible work value for Testnet. See comment on [`Params::pow_limit`] for more info.
    pub const TESTNET_MIN: Work = Work(U256(0x0000_0000_ffff_0000_0000_0000_0000_0000_u128, 0));

    /// Lowest possible work value for Signet. See comment on [`Params::pow_limit`] for more info.
    pub const SIGNET_MIN: Work = Work(U256(0x0000_0377_ae00_0000_0000_0000_0000_0000_u128, 0));

    /// Lowest possible work value for Regtest. See comment on [`Params::pow_limit`] for more info.
    pub const REGTEST_MIN: Work = Work(U256(0x7fff_ff00_0000_0000_0000_0000_0000_0000_u128, 0));

    /// Converts this [`Work`] to [`Target`].
    pub fn to_target(self) -> Target { Target(self.0.inverse()) }

    /// Returns log2 of this work.
    ///
    /// The result inherently suffers from a loss of precision and is, therefore, meant to be
    /// used mainly for informative and displaying purposes, similarly to Bitcoin Core's
    /// `log2_work` output in its logs.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn log2(self) -> f64 { self.0.to_f64().log2() }
}
do_impl!(Work);

impl Add for Work {
    type Output = Work;
    fn add(self, rhs: Self) -> Self { Work(self.0 + rhs.0) }
}

impl Sub for Work {
    type Output = Work;
    fn sub(self, rhs: Self) -> Self { Work(self.0 - rhs.0) }
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
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Target(U256);

impl Target {
    /// When parsing nBits, Bitcoin Core converts a negative target threshold into a target of zero.
    pub const ZERO: Target = Target(U256::ZERO);
    /// The maximum possible target.
    ///
    /// This value is used to calculate difficulty, which is defined as how difficult the current
    /// target makes it to find a block relative to how difficult it would be at the highest
    /// possible target. Remember highest target == lowest difficulty.
    ///
    /// ref: <https://en.bitcoin.it/wiki/Target>
    // In Bitcoind this is ~(u256)0 >> 32 stored as a floating-point type so it gets truncated, hence
    // the low 208 bits are all zero.
    pub const MAX: Self = Target(U256(0xFFFF_u128 << (208 - 128), 0));

    /// The maximum possible target (see [`Target::MAX`]).
    ///
    /// This is provided for consistency with Rust 1.41.1, newer code should use [`Target::MAX`].
    pub const fn max_value() -> Self { Target::MAX }

    /// Computes the [`Target`] value from a compact representation.
    ///
    /// ref: <https://developer.bitcoin.org/reference/block_chain.html#target-nbits>
    pub fn from_compact(c: CompactTarget) -> Target {
        let bits = c.0;
        // This is a floating-point "compact" encoding originally used by
        // OpenSSL, which satoshi put into consensus code, so we're stuck
        // with it. The exponent needs to have 3 subtracted from it, hence
        // this goofy decoding code. 3 is due to 3 bytes in the mantissa.
        let (mant, expt) = {
            let unshifted_expt = bits >> 24;
            if unshifted_expt <= 3 {
                ((bits & 0xFFFFFF) >> (8 * (3 - unshifted_expt as usize)), 0)
            } else {
                (bits & 0xFFFFFF, 8 * ((bits >> 24) - 3))
            }
        };

        // The mantissa is signed but may not be negative.
        if mant > 0x7F_FFFF {
            Target::ZERO
        } else {
            Target(U256::from(mant) << expt)
        }
    }

    /// Computes the compact value from a [`Target`] representation.
    ///
    /// The compact form is by definition lossy, this means that
    /// `t == Target::from_compact(t.to_compact_lossy())` does not always hold.
    pub fn to_compact_lossy(self) -> CompactTarget {
        let mut size = (self.0.bits() + 7) / 8;
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

        CompactTarget(compact | (size << 24))
    }

    /// Returns true if block hash is less than or equal to this [`Target`].
    ///
    /// Proof-of-work validity for a block requires the hash of the block to be less than or equal
    /// to the target.
    #[cfg_attr(all(test, mutate), mutate)]
    pub fn is_met_by(&self, hash: BlockHash) -> bool {
        use crate::hashes::Hash;
        let hash = U256::from_le_bytes(hash.to_byte_array());
        hash <= self.0
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
    /// valid block
    ///
    /// # Note
    ///
    /// Difficulty is calculated using the following algorithm `max / current` where [max] is
    /// defined for the Bitcoin network and `current` is the current [target] for this block. As
    /// such, a low target implies a high difficulty. Since [`Target`] is represented as a 256 bit
    /// integer but `difficulty()` returns only 128 bits this means for targets below approximately
    /// `0xffff_ffff_ffff_ffff_ffff_ffff` `difficulty()` will saturate at `u128::MAX`.
    ///
    /// [max]: Target::max
    /// [target]: crate::blockdata::block::Header::target
    #[cfg_attr(all(test, mutate), mutate)]
    pub fn difficulty(&self) -> u128 {
        let d = Target::MAX.0 / self.0;
        d.saturating_to_u128()
    }

    /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
    ///
    /// See [`difficulty`] for details.
    ///
    /// [`difficulty`]: Target::difficulty
    #[cfg_attr(all(test, mutate), mutate)]
    pub fn difficulty_float(&self) -> f64 { TARGET_MAX_F64 / self.0.to_f64() }
}
do_impl!(Target);

/// Encoding of 256-bit target as 32-bit float.
///
/// This is used to encode a target into the block header. Satoshi made this part of consensus code
/// in the original version of Bitcoin, likely copying an idea from OpenSSL.
///
/// OpenSSL's bignum (BN) type has an encoding, which is even called "compact" as in bitcoin, which
/// is exactly this format.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct CompactTarget(u32);

impl CompactTarget {
    /// Creates a [`CompactTarget`] from a consensus encoded `u32`.
    pub fn from_consensus(bits: u32) -> Self { Self(bits) }

    /// Returns the consensus encoded `u32` representation of this [`CompactTarget`].
    pub fn to_consensus(self) -> u32 { self.0 }
}

impl From<CompactTarget> for Target {
    fn from(c: CompactTarget) -> Self { Target::from_compact(c) }
}

impl FromHexStr for CompactTarget {
    type Error = crate::parse::ParseIntError;

    fn from_hex_str_no_prefix<S: AsRef<str> + Into<String>>(s: S) -> Result<Self, Self::Error> {
        let compact_target = crate::parse::hex_u32(s)?;
        Ok(Self::from_consensus(compact_target))
    }
}

impl Encodable for CompactTarget {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for CompactTarget {
    #[inline]
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        u32::consensus_decode(r).map(CompactTarget)
    }
}

/// Big-endian 256 bit integer type.
// (high, low): u.0 contains the high bits, u.1 contains the low bits.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
struct U256(u128, u128);

impl U256 {
    const MAX: U256 =
        U256(0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff);

    const ZERO: U256 = U256(0, 0);

    const ONE: U256 = U256(0, 1);

    /// Creates [`U256`] from a big-endian array of `u8`s.
    #[cfg_attr(all(test, mutate), mutate)]
    fn from_be_bytes(a: [u8; 32]) -> U256 {
        let (high, low) = split_in_half(a);
        let big = u128::from_be_bytes(high);
        let little = u128::from_be_bytes(low);
        U256(big, little)
    }

    /// Creates a [`U256`] from a little-endian array of `u8`s.
    #[cfg_attr(all(test, mutate), mutate)]
    fn from_le_bytes(a: [u8; 32]) -> U256 {
        let (high, low) = split_in_half(a);
        let little = u128::from_le_bytes(high);
        let big = u128::from_le_bytes(low);
        U256(big, little)
    }

    /// Converts `Self` to a big-endian array of `u8`s.
    #[cfg_attr(all(test, mutate), mutate)]
    fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0; 32];
        out[..16].copy_from_slice(&self.0.to_be_bytes());
        out[16..].copy_from_slice(&self.1.to_be_bytes());
        out
    }

    /// Converts `Self` to a little-endian array of `u8`s.
    #[cfg_attr(all(test, mutate), mutate)]
    fn to_le_bytes(self) -> [u8; 32] {
        let mut out = [0; 32];
        out[..16].copy_from_slice(&self.1.to_le_bytes());
        out[16..].copy_from_slice(&self.0.to_le_bytes());
        out
    }

    /// Calculates 2^256 / (x + 1) where x is a 256 bit unsigned integer.
    ///
    /// 2**256 / (x + 1) == ~x / (x + 1) + 1
    ///
    /// (Equation shamelessly stolen from bitcoind)
    fn inverse(&self) -> U256 {
        // We should never have a target/work of zero so this doesn't matter
        // that much but we define the inverse of 0 as max.
        if self.is_zero() {
            return U256::MAX;
        }
        // We define the inverse of 1 as max.
        if self.is_one() {
            return U256::MAX;
        }
        // We define the inverse of max as 1.
        if self.is_max() {
            return U256::ONE;
        }

        let ret = !*self / self.wrapping_inc();
        ret.wrapping_inc()
    }

    #[cfg_attr(all(test, mutate), mutate)]
    fn is_zero(&self) -> bool { self.0 == 0 && self.1 == 0 }

    #[cfg_attr(all(test, mutate), mutate)]
    fn is_one(&self) -> bool { self.0 == 0 && self.1 == 1 }

    #[cfg_attr(all(test, mutate), mutate)]
    fn is_max(&self) -> bool { self.0 == u128::max_value() && self.1 == u128::max_value() }

    /// Returns the low 32 bits.
    fn low_u32(&self) -> u32 { self.low_u128() as u32 }

    /// Returns the low 64 bits.
    fn low_u64(&self) -> u64 { self.low_u128() as u64 }

    /// Returns the low 128 bits.
    fn low_u128(&self) -> u128 { self.1 }

    /// Returns `self` as a `u128` saturating to `u128::MAX` if `self` is too big.
    // Matagen gives false positive because >= and > both return u128::MAX
    fn saturating_to_u128(&self) -> u128 {
        if *self > U256::from(u128::max_value()) {
            u128::max_value()
        } else {
            self.low_u128()
        }
    }

    /// Returns the least number of bits needed to represent the number.
    #[cfg_attr(all(test, mutate), mutate)]
    fn bits(&self) -> u32 {
        if self.0 > 0 {
            256 - self.0.leading_zeros()
        } else {
            128 - self.1.leading_zeros()
        }
    }

    /// Wrapping multiplication by `u64`.
    ///
    /// # Returns
    ///
    /// The multiplication result along with a boolean indicating whether an arithmetic overflow
    /// occurred. If an overflow occurred then the wrapped value is returned.
    // mutagen false positive: binop_bit, replace `|` with `^`
    fn mul_u64(self, rhs: u64) -> (U256, bool) {
        let mut carry: u128 = 0;
        let mut split_le =
            [self.1 as u64, (self.1 >> 64) as u64, self.0 as u64, (self.0 >> 64) as u64];

        for word in &mut split_le {
            // TODO: Use `carrying_mul` when stabilized: https://github.com/rust-lang/rust/issues/85532
            // This will not overflow, for proof see https://github.com/rust-bitcoin/rust-bitcoin/pull/1496#issuecomment-1365938572
            let n = carry + u128::from(rhs) * u128::from(*word);

            *word = n as u64; // Intentional truncation, save the low bits
            carry = n >> 64; // and carry the high bits.
        }

        let low = u128::from(split_le[0]) | u128::from(split_le[1]) << 64;
        let high = u128::from(split_le[2]) | u128::from(split_le[3]) << 64;
        (Self(high, low), carry != 0)
    }

    /// Calculates quotient and remainder.
    ///
    /// # Returns
    ///
    /// (quotient, remainder)
    ///
    /// # Panics
    ///
    /// If `rhs` is zero.
    #[cfg_attr(all(test, mutate), mutate)]
    fn div_rem(self, rhs: Self) -> (Self, Self) {
        let mut sub_copy = self;
        let mut shift_copy = rhs;
        let mut ret = [0u128; 2];

        let my_bits = self.bits();
        let your_bits = rhs.bits();

        // Check for division by 0
        assert!(your_bits != 0, "attempted to divide {} by zero", self);

        // Early return in case we are dividing by a larger number than us
        if my_bits < your_bits {
            return (U256::ZERO, sub_copy);
        }

        // Bitwise long division
        let mut shift = my_bits - your_bits;
        shift_copy = shift_copy << shift;
        loop {
            if sub_copy >= shift_copy {
                ret[1 - (shift / 128) as usize] |= 1 << (shift % 128);
                sub_copy = sub_copy.wrapping_sub(shift_copy);
            }
            shift_copy = shift_copy >> 1;
            if shift == 0 {
                break;
            }
            shift -= 1;
        }

        (U256(ret[0], ret[1]), sub_copy)
    }

    /// Calculates `self` + `rhs`
    ///
    /// Returns a tuple of the addition along with a boolean indicating whether an arithmetic
    /// overflow would occur. If an overflow would have occurred then the wrapped value is returned.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    fn overflowing_add(self, rhs: Self) -> (Self, bool) {
        let mut ret = U256::ZERO;
        let mut ret_overflow = false;

        let (high, overflow) = self.0.overflowing_add(rhs.0);
        ret.0 = high;
        ret_overflow |= overflow;

        let (low, overflow) = self.1.overflowing_add(rhs.1);
        ret.1 = low;
        if overflow {
            let (high, overflow) = ret.0.overflowing_add(1);
            ret.0 = high;
            ret_overflow |= overflow;
        }

        (ret, ret_overflow)
    }

    /// Calculates `self` - `rhs`
    ///
    /// Returns a tuple of the subtraction along with a boolean indicating whether an arithmetic
    /// overflow would occur. If an overflow would have occurred then the wrapped value is returned.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    fn overflowing_sub(self, rhs: Self) -> (Self, bool) {
        let ret = self.wrapping_add(!rhs).wrapping_add(Self::ONE);
        let overflow = rhs > self;
        (ret, overflow)
    }

    /// Calculates the multiplication of `self` and `rhs`.
    ///
    /// Returns a tuple of the multiplication along with a boolean
    /// indicating whether an arithmetic overflow would occur. If an
    /// overflow would have occurred then the wrapped value is returned.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    fn overflowing_mul(self, rhs: Self) -> (Self, bool) {
        let mut ret = U256::ZERO;
        let mut ret_overflow = false;

        for i in 0..3 {
            let to_mul = (rhs >> (64 * i)).low_u64();
            let (mul_res, _) = self.mul_u64(to_mul);
            ret = ret.wrapping_add(mul_res << (64 * i));
        }

        let to_mul = (rhs >> 192).low_u64();
        let (mul_res, overflow) = self.mul_u64(to_mul);
        ret_overflow |= overflow;
        let (sum, overflow) = ret.overflowing_add(mul_res);
        ret = sum;
        ret_overflow |= overflow;

        (ret, ret_overflow)
    }

    /// Wrapping (modular) addition. Computes `self + rhs`, wrapping around at the boundary of the
    /// type.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn wrapping_add(self, rhs: Self) -> Self {
        let (ret, _overflow) = self.overflowing_add(rhs);
        ret
    }

    /// Wrapping (modular) subtraction. Computes `self - rhs`, wrapping around at the boundary of
    /// the type.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn wrapping_sub(self, rhs: Self) -> Self {
        let (ret, _overflow) = self.overflowing_sub(rhs);
        ret
    }

    /// Wrapping (modular) multiplication. Computes `self * rhs`, wrapping around at the boundary of
    /// the type.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg(test)]
    fn wrapping_mul(self, rhs: Self) -> Self {
        let (ret, _overflow) = self.overflowing_mul(rhs);
        ret
    }

    /// Returns `self` incremented by 1 wrapping around at the boundary of the type.
    #[must_use = "this returns the result of the increment, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    fn wrapping_inc(&self) -> U256 {
        let mut ret = U256::ZERO;

        ret.1 = self.1.wrapping_add(1);
        if ret.1 == 0 {
            ret.0 = self.0.wrapping_add(1);
        } else {
            ret.0 = self.0;
        }
        ret
    }

    /// Panic-free bitwise shift-left; yields `self << mask(rhs)`, where `mask` removes any
    /// high-order bits of `rhs` that would cause the shift to exceed the bitwidth of the type.
    ///
    /// Note that this is *not* the same as a rotate-left; the RHS of a wrapping shift-left is
    /// restricted to the range of the type, rather than the bits shifted out of the LHS being
    /// returned to the other end. We do not currently support `rotate_left`.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    fn wrapping_shl(self, rhs: u32) -> Self {
        let shift = rhs & 0x000000ff;

        let mut ret = U256::ZERO;
        let word_shift = shift >= 128;
        let bit_shift = shift % 128;

        if word_shift {
            ret.0 = self.1 << bit_shift
        } else {
            ret.0 = self.0 << bit_shift;
            if bit_shift > 0 {
                ret.0 += self.1.wrapping_shr(128 - bit_shift);
            }
            ret.1 = self.1 << bit_shift;
        }
        ret
    }

    /// Panic-free bitwise shift-right; yields `self >> mask(rhs)`, where `mask` removes any
    /// high-order bits of `rhs` that would cause the shift to exceed the bitwidth of the type.
    ///
    /// Note that this is *not* the same as a rotate-right; the RHS of a wrapping shift-right is
    /// restricted to the range of the type, rather than the bits shifted out of the LHS being
    /// returned to the other end. We do not currently support `rotate_right`.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    fn wrapping_shr(self, rhs: u32) -> Self {
        let shift = rhs & 0x000000ff;

        let mut ret = U256::ZERO;
        let word_shift = shift >= 128;
        let bit_shift = shift % 128;

        if word_shift {
            ret.1 = self.0 >> bit_shift
        } else {
            ret.0 = self.0 >> bit_shift;
            ret.1 = self.1 >> bit_shift;
            if bit_shift > 0 {
                ret.1 += self.0.wrapping_shl(128 - bit_shift);
            }
        }
        ret
    }

    /// Format `self` to `f` as a decimal when value is known to be non-zero.
    fn fmt_decimal(&self, f: &mut fmt::Formatter) -> fmt::Result {
        const DIGITS: usize = 78; // U256::MAX has 78 base 10 digits.
        const TEN: U256 = U256(0, 10);

        let mut buf = [0_u8; DIGITS];
        let mut i = DIGITS - 1; // We loop backwards.
        let mut cur = *self;

        loop {
            let digit = (cur % TEN).low_u128() as u8; // Cast after rem 10 is lossless.
            buf[i] = digit + b'0';
            cur = cur / TEN;
            if cur.is_zero() {
                break;
            }
            i -= 1;
        }
        let s = core::str::from_utf8(&buf[i..]).expect("digits 0-9 are valid UTF8");
        f.pad_integral(true, "", s)
    }

    /// Convert self to f64.
    #[inline]
    fn to_f64(self) -> f64 {
        // Reference: https://blog.m-ou.se/floats/
        // Step 1: Get leading zeroes
        let leading_zeroes = 256 - self.bits();
        // Step 2: Get msb to be farthest left bit
        let left_aligned = self.wrapping_shl(leading_zeroes);
        // Step 3: Shift msb to fit in lower 53 bits (128-53=75) to get the mantissa
        // * Shifting the border of the 2 u128s to line up with mantissa and dropped bits
        let middle_aligned = left_aligned >> 75;
        // * This is the 53 most significant bits as u128
        let mantissa = middle_aligned.0;
        // Step 4: Dropped bits (except for last 75 bits) are all in the second u128.
        // Bitwise OR the rest of the bits into it, preserving the highest bit,
        // so we take the lower 75 bits of middle_aligned.1 and mix it in. (See blog for explanation)
        let dropped_bits = middle_aligned.1 | (left_aligned.1 & 0x7FF_FFFF_FFFF_FFFF_FFFF);
        // Step 5: The msb of the dropped bits has been preserved, and all other bits
        // if any were set, would be set somewhere in the other 127 bits.
        // If msb of dropped bits is 0, it is mantissa + 0
        // If msb of dropped bits is 1, it is mantissa + 0 only if mantissa lowest bit is 0
        // and other bits of the dropped bits are all 0.
        // (This is why we only care if the other non-msb dropped bits are all 0 or not,
        // so we can just OR them to make sure any bits show up somewhere.)
        let mantissa =
            (mantissa + ((dropped_bits - (dropped_bits >> 127 & !mantissa)) >> 127)) as u64;
        // Step 6: Calculate the exponent
        // If self is 0, exponent should be 0 (special meaning) and mantissa will end up 0 too
        // Otherwise, (255 - n) + 1022 so it simplifies to 1277 - n
        // 1023 and 1022 are the cutoffs for the exponent having the msb next to the decimal point
        let exponent = if self == Self::ZERO { 0 } else { 1277 - leading_zeroes as u64 };
        // Step 7: sign bit is always 0, exponent is shifted into place
        // Use addition instead of bitwise OR to saturate the exponent if mantissa overflows
        f64::from_bits((exponent << 52) + mantissa)
    }
}

// Target::MAX as a float value. Calculated with U256::to_f64.
// This is validated in the unit tests as well.
const TARGET_MAX_F64: f64 = 2.695953529101131e67;

impl<T: Into<u128>> From<T> for U256 {
    fn from(x: T) -> Self { U256(0, x.into()) }
}

/// Error from `TryFrom<signed type>` implementations, occurs when input is negative.
#[derive(Debug)]
pub struct TryFromError(i128);

impl fmt::Display for TryFromError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "attempt to create unsigned integer type from negative number: {}", self.0)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for TryFromError {}

impl Add for U256 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let (res, overflow) = self.overflowing_add(rhs);
        debug_assert!(!overflow, "Addition of U256 values overflowed");
        res
    }
}

impl Sub for U256 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let (res, overflow) = self.overflowing_sub(rhs);
        debug_assert!(!overflow, "Subtraction of U256 values overflowed");
        res
    }
}

impl Mul for U256 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        let (res, overflow) = self.overflowing_mul(rhs);
        debug_assert!(!overflow, "Multiplication of U256 values overflowed");
        res
    }
}

impl Div for U256 {
    type Output = Self;
    fn div(self, rhs: Self) -> Self { self.div_rem(rhs).0 }
}

impl Rem for U256 {
    type Output = Self;
    fn rem(self, rhs: Self) -> Self { self.div_rem(rhs).1 }
}

impl Not for U256 {
    type Output = Self;

    fn not(self) -> Self { U256(!self.0, !self.1) }
}

impl Shl<u32> for U256 {
    type Output = Self;
    fn shl(self, shift: u32) -> U256 { self.wrapping_shl(shift) }
}

impl Shr<u32> for U256 {
    type Output = Self;
    fn shr(self, shift: u32) -> U256 { self.wrapping_shr(shift) }
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_zero() {
            f.pad_integral(true, "", "0")
        } else {
            self.fmt_decimal(f)
        }
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{:#x}", self) }
}

macro_rules! impl_hex {
    ($hex:ident, $case:expr) => {
        impl $hex for U256 {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                bitcoin_internals::hex::display::fmt_hex_exact!(f, 32, &self.to_be_bytes(), $case)
            }
        }
    };
}
impl_hex!(LowerHex, bitcoin_internals::hex::Case::Lower);
impl_hex!(UpperHex, bitcoin_internals::hex::Case::Upper);

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl crate::serde::Serialize for U256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: crate::serde::Serializer,
    {
        struct DisplayHex(U256);

        impl fmt::Display for DisplayHex {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{:x}", self.0) }
        }

        if serializer.is_human_readable() {
            // TODO: fast hex encoding.
            serializer.collect_str(&DisplayHex(*self))
        } else {
            let bytes = self.to_be_bytes();
            serializer.serialize_bytes(&bytes)
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> crate::serde::Deserialize<'de> for U256 {
    fn deserialize<D: crate::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use core::convert::TryInto;

        use crate::hashes::hex::FromHex;
        use crate::serde::de;

        if d.is_human_readable() {
            struct HexVisitor;

            impl<'de> de::Visitor<'de> for HexVisitor {
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

                    let b = <[u8; 32]>::from_hex(s)
                        .map_err(|_| de::Error::invalid_value(de::Unexpected::Str(s), &self))?;

                    Ok(U256::from_be_bytes(b))
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    if let Ok(hex) = core::str::from_utf8(v) {
                        let b = <[u8; 32]>::from_hex(hex).map_err(|_| {
                            de::Error::invalid_value(de::Unexpected::Str(hex), &self)
                        })?;

                        Ok(U256::from_be_bytes(b))
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl<'de> serde::de::Visitor<'de> for BytesVisitor {
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

/// Splits a 32 byte array into two 16 byte arrays.
fn split_in_half(a: [u8; 32]) -> ([u8; 16], [u8; 16]) {
    let mut high = [0_u8; 16];
    let mut low = [0_u8; 16];

    high.copy_from_slice(&a[..16]);
    low.copy_from_slice(&a[16..]);

    (high, low)
}

#[cfg(kani)]
impl kani::Arbitrary for U256 {
    fn any() -> Self {
        let high: u128 = kani::any();
        let low: u128 = kani::any();
        Self(high, low)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl<T: Into<u128>> From<T> for Target {
        fn from(x: T) -> Self { Self(U256::from(x)) }
    }

    impl<T: Into<u128>> From<T> for Work {
        fn from(x: T) -> Self { Self(U256::from(x)) }
    }

    impl U256 {
        fn bit_at(&self, index: usize) -> bool {
            if index > 255 {
                panic!("index out of bounds");
            }

            let word = if index < 128 { self.1 } else { self.0 };
            (word & (1 << (index % 128))) != 0
        }
    }

    impl U256 {
        /// Creates a U256 from a big-endian array of u64's
        fn from_array(a: [u64; 4]) -> Self {
            let mut ret = U256::ZERO;
            ret.0 = (a[0] as u128) << 64 ^ (a[1] as u128);
            ret.1 = (a[2] as u128) << 64 ^ (a[3] as u128);
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

        let u = U256::from(u128::max_value()) << 1;
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
    fn u256_lower_hex() {
        assert_eq!(
            format!("{:x}", U256::from(0xDEADBEEF_u64)),
            "00000000000000000000000000000000000000000000000000000000deadbeef",
        );
        assert_eq!(
            format!("{:#x}", U256::from(0xDEADBEEF_u64)),
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
    fn u256_upper_hex() {
        assert_eq!(
            format!("{:X}", U256::from(0xDEADBEEF_u64)),
            "00000000000000000000000000000000000000000000000000000000DEADBEEF",
        );
        assert_eq!(
            format!("{:#X}", U256::from(0xDEADBEEF_u64)),
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
    fn u256_display() {
        assert_eq!(format!("{}", U256::from(100_u32)), "100",);
        assert_eq!(format!("{}", U256::ZERO), "0",);
        assert_eq!(format!("{}", U256::from(u64::max_value())), format!("{}", u64::max_value()),);
        assert_eq!(
            format!("{}", U256::MAX),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935",
        );
    }

    macro_rules! check_format {
        ($($test_name:ident, $val:literal, $format_string:literal, $expected:literal);* $(;)?) => {
            $(
                #[test]
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
    }

    #[test]
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
        let u = U256::from(0xdeadbeef_u32);
        assert_eq!(u, U256(0, 0xdeadbeef));
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
        assert_eq!(U256::from(35498456_u32) % U256::from(3435_u32), U256::from(1166_u32));
        let rem_src = mult.wrapping_mul(U256::from(39842_u32)).wrapping_add(U256::from(9054_u32));
        assert_eq!(rem_src % U256::from(39842_u32), U256::from(9054_u32));
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
        let x = U256::from(u128::max_value());
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
        assert_eq!(sub, U256::from(u128::max_value()));
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
        let u = 1_u128 << 64 | 1_u128;
        let x = U256(u, u);

        // Put a digit in the second least significant bit of each 64 bit word.
        let u = 2_u128 << 64 | 2_u128;
        let y = U256(u, u);

        let (got, overflow) = x.overflowing_mul(y);

        let want = U256(
            0x0000_0000_0000_0008_0000_0000_0000_0008,
            0x0000_0000_0000_0006_0000_0000_0000_0004,
        );
        assert!(!overflow);
        assert_eq!(got, want)
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

    #[cfg(feature = "serde")]
    #[test]
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
            U256::from(0xDEADBEEF_u32),
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
    fn u256_is_max_correct_negative() {
        let tc = vec![U256::ZERO, U256::ONE, U256::from(u128::max_value())];
        for t in tc {
            assert!(!t.is_max())
        }
    }

    #[test]
    fn u256_is_max_correct_positive() {
        assert!(U256::MAX.is_max());

        let u = u128::max_value();
        assert!(((U256::from(u) << 128) + U256::from(u)).is_max());
    }

    #[test]
    fn compact_target_from_hex_str_happy_path() {
        let actual = CompactTarget::from_hex_str("0x01003456").unwrap();
        let expected = CompactTarget(0x01003456);
        assert_eq!(actual, expected);
    }

    #[test]
    fn compact_target_from_hex_str_no_prefix_happy_path() {
        let actual = CompactTarget::from_hex_str_no_prefix("01003456").unwrap();
        let expected = CompactTarget(0x01003456);
        assert_eq!(actual, expected);
    }

    #[test]
    fn compact_target_from_hex_invalid_hex_should_err() {
        let hex = "0xzbf9";
        let result = CompactTarget::from_hex_str(hex);
        assert!(result.is_err());
    }

    #[test]
    fn target_from_compact() {
        // (nBits, target)
        let tests = vec![
            (0x0100_3456_u32, 0x00_u64), // High bit set.
            (0x0112_3456_u32, 0x12_u64),
            (0x0200_8000_u32, 0x80_u64),
            (0x0500_9234_u32, 0x9234_0000_u64),
            (0x0492_3456_u32, 0x00_u64), // High bit set (0x80 in 0x92).
            (0x0412_3456_u32, 0x1234_5600_u64), // Inverse of above; no high bit.
        ];

        for (n_bits, target) in tests {
            let want = Target::from(target);
            let got = Target::from_compact(CompactTarget::from_consensus(n_bits));
            assert_eq!(got, want);
        }
    }

    #[test]
    fn target_is_met_by_for_target_equals_hash() {
        use std::str::FromStr;

        use crate::hashes::Hash;

        let hash =
            BlockHash::from_str("ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c")
                .expect("failed to parse block hash");
        let target = Target(U256::from_le_bytes(hash.to_byte_array()));
        assert!(target.is_met_by(hash));
    }

    #[test]
    fn max_target_from_compact() {
        // The highest possible target is defined as 0x1d00ffff
        let bits = 0x1d00ffff_u32;
        let want = Target::MAX;
        let got = Target::from_compact(CompactTarget::from_consensus(bits));
        assert_eq!(got, want)
    }

    #[test]
    fn target_difficulty_float() {
        assert_eq!(Target::MAX.difficulty_float(), 1.0_f64);
        assert_eq!(
            Target::from_compact(CompactTarget::from_consensus(0x1c00ffff_u32)).difficulty_float(),
            256.0_f64
        );
        assert_eq!(
            Target::from_compact(CompactTarget::from_consensus(0x1b00ffff_u32)).difficulty_float(),
            65536.0_f64
        );
        assert_eq!(
            Target::from_compact(CompactTarget::from_consensus(0x1a00f3a2_u32)).difficulty_float(),
            17628585.065897066_f64
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
        let target = Target::from(0xdeadbeef_u32);
        let work = target.to_work();
        let back = work.to_target();
        assert_eq!(back, target)
    }

    #[cfg(feature = "std")]
    #[test]
    fn work_log2() {
        // Compare work log2 to historical Bitcoin Core values found in Core logs.
        let tests: Vec<(u128, f64)> = vec![
            // (chainwork, core log2)                // height
            (0x200020002, 33.000022),                // 1
            (0xa97d67041c5e51596ee7, 79.405055),     // 308004
            (0x1dc45d79394baa8ab18b20, 84.895644),   // 418141
            (0x8c85acb73287e335d525b98, 91.134654),  // 596624
            (0x2ef447e01d1642c40a184ada, 93.553183), // 738965
        ];

        for (chainwork, core_log2) in tests {
            // Core log2 in the logs is rounded to 6 decimal places.
            let log2 = (Work::from(chainwork).log2() * 1e6).round() / 1e6;
            assert_eq!(log2, core_log2)
        }

        assert_eq!(Work(U256::ONE).log2(), 0.0);
        assert_eq!(Work(U256::MAX).log2(), 256.0);
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

        for min in [U256::ZERO, U256::ONE].iter() {
            // lower target means more work required.
            assert_eq!(Target(max).to_work(), Work(U256::ONE));
            assert_eq!(Target(*min).to_work(), Work(max));

            assert_eq!(Work(max).to_target(), Target(U256::ONE));
            assert_eq!(Work(*min).to_target(), Target(max));
        }
    }

    #[test]
    fn u256_wrapping_add_wraps_at_boundry() {
        assert_eq!(U256::MAX.wrapping_add(U256::ONE), U256::ZERO);
        assert_eq!(U256::MAX.wrapping_add(U256::from(2_u8)), U256::ONE);
    }

    #[test]
    fn u256_wrapping_sub_wraps_at_boundry() {
        assert_eq!(U256::ZERO.wrapping_sub(U256::ONE), U256::MAX);
        assert_eq!(U256::ONE.wrapping_sub(U256::from(2_u8)), U256::MAX);
    }

    #[test]
    fn mul_u64_overflows() {
        let (_, overflow) = U256::MAX.mul_u64(2);
        assert!(overflow, "max * 2 should overflow");
    }

    #[test]
    #[should_panic]
    fn u256_overflowing_addition_panics() { let _ = U256::MAX + U256::ONE; }

    #[test]
    #[should_panic]
    fn u256_overflowing_subtraction_panics() { let _ = U256::ZERO - U256::ONE; }

    #[test]
    #[should_panic]
    fn u256_multiplication_by_max_panics() { let _ = U256::MAX * U256::MAX; }

    #[test]
    #[should_panic]
    fn work_overflowing_addition_panics() { let _ = Work(U256::MAX) + Work(U256::ONE); }

    #[test]
    #[should_panic]
    fn work_overflowing_subtraction_panics() { let _ = Work(U256::ZERO) - Work(U256::ONE); }

    #[test]
    fn u256_to_f64() {
        // Validate that the Target::MAX value matches the constant also used in difficulty calculation.
        assert_eq!(Target::MAX.0.to_f64(), TARGET_MAX_F64);
        assert_eq!(U256::ZERO.to_f64(), 0.0_f64);
        assert_eq!(U256::ONE.to_f64(), 1.0_f64);
        assert_eq!(U256::MAX.to_f64(), 1.157920892373162e77_f64);
        assert_eq!((U256::MAX >> 1).to_f64(), 5.78960446186581e76_f64);
        assert_eq!((U256::MAX >> 128).to_f64(), 3.402823669209385e38_f64);
        assert_eq!((U256::MAX >> (256 - 54)).to_f64(), 1.8014398509481984e16_f64);
        // 53 bits and below should not use exponents
        assert_eq!((U256::MAX >> (256 - 53)).to_f64(), 9007199254740991.0_f64);
        assert_eq!((U256::MAX >> (256 - 32)).to_f64(), 4294967295.0_f64);
        assert_eq!((U256::MAX >> (256 - 16)).to_f64(), 65535.0_f64);
        assert_eq!((U256::MAX >> (256 - 8)).to_f64(), 255.0_f64);
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    // TODO: After we verify div_rem assert x * y / y == x
    #[kani::unwind(5)] // mul_u64 loops over 4 64 bit ints so use one more than 4
    #[kani::proof]
    fn check_mul_u64() {
        let x: U256 = kani::any();
        let y: u64 = kani::any();

        let _ = x.mul_u64(y);
    }
}
