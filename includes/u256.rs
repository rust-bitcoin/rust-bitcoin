// SPDX-License-Identifier: CC0-1.0

// NOTE: This is not a normal module.
//
// Unsigned 256-bit integer type
//
// File is included in other files using `include!` allowing us to
// follow the DRY principle without using macros.

/// Big-endian 256 bit integer type.
// (high, low): u.0 contains the high bits, u.1 contains the low bits.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
struct U256(u128, u128);

#[allow(dead_code)]
impl U256 {
    const MAX: Self =
        Self(0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff);

    const ZERO: Self = Self(0, 0);

    const ONE: Self = Self(0, 1);

    /// Constructs a new `U256` from a prefixed hex string.
    fn from_hex(s: &str) -> Result<Self, PrefixedHexError> {
        let checked = parse_int::hex_remove_prefix(s)?;
        Ok(Self::from_hex_internal(checked)?)
    }

    /// Constructs a new `U256` from an unprefixed hex string.
    fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError> {
        let checked = parse_int::hex_check_unprefixed(s)?;
        Ok(Self::from_hex_internal(checked)?)
    }

    // Caller to ensure `s` does not contain a prefix.
    fn from_hex_internal(s: &str) -> Result<Self, ParseIntError> {
        let (high, low) = if s.len() <= 32 {
            let low = parse_int::hex_u128_unchecked(s)?;
            (0, low)
        } else {
            let high_len = s.len() - 32;
            let high_s = &s[..high_len];
            let low_s = &s[high_len..];

            let high = parse_int::hex_u128_unchecked(high_s)?;
            let low = parse_int::hex_u128_unchecked(low_s)?;
            (high, low)
        };

        Ok(Self(high, low))
    }

    /// Constructs a new `U256` from a big-endian array of `u8`s.
    fn from_be_bytes(a: [u8; 32]) -> Self {
        let (high, low) = split_in_half(a);
        let big = u128::from_be_bytes(high);
        let little = u128::from_be_bytes(low);
        Self(big, little)
    }

    /// Constructs a new `U256` from a little-endian array of `u8`s.
    fn from_le_bytes(a: [u8; 32]) -> Self {
        let (high, low) = split_in_half(a);
        let little = u128::from_le_bytes(high);
        let big = u128::from_le_bytes(low);
        Self(big, little)
    }

    /// Converts `U256` to a big-endian array of `u8`s.
    fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0; 32];
        out[..16].copy_from_slice(&self.0.to_be_bytes());
        out[16..].copy_from_slice(&self.1.to_be_bytes());
        out
    }

    /// Converts `U256` to a little-endian array of `u8`s.
    fn to_le_bytes(self) -> [u8; 32] {
        let mut out = [0; 32];
        out[..16].copy_from_slice(&self.1.to_le_bytes());
        out[16..].copy_from_slice(&self.0.to_le_bytes());
        out
    }

    /// Calculates 2^256 / (x + 1) where x is a 256 bit unsigned integer.
    ///
    /// ref: <https://github.com/bitcoin/bitcoin/blob/5fe753b56f450b054c42227c5df8346c72447490/src/chain.cpp#L133>
    ///
    /// 2**256 / (x + 1) == ~x / (x + 1) + 1
    ///
    /// (Equation shamelessly stolen from bitcoind)
    fn inverse(&self) -> Self {
        // We should never have a target/work of zero so this doesn't matter
        // that much but we define the inverse of 0 as max.
        if self.is_zero() {
            return Self::MAX;
        }
        // We define the inverse of 1 as max.
        if self.is_one() {
            return Self::MAX;
        }
        // We define the inverse of max as 1.
        if self.is_max() {
            return Self::ONE;
        }

        let ret = !*self / self.wrapping_inc();
        ret.wrapping_inc()
    }

    fn is_zero(&self) -> bool { self.0 == 0 && self.1 == 0 }

    fn is_one(&self) -> bool { self.0 == 0 && self.1 == 1 }

    fn is_max(&self) -> bool { self.0 == u128::MAX && self.1 == u128::MAX }

    /// Returns the low 32 bits.
    fn low_u32(&self) -> u32 { self.low_u128() as u32 }

    /// Returns the low 64 bits.
    fn low_u64(&self) -> u64 { self.low_u128() as u64 }

    /// Returns the low 128 bits.
    fn low_u128(&self) -> u128 { self.1 }

    /// Returns this `U256` as a `u128` saturating to `u128::MAX` if `self` is too big.
    // Mutagen gives false positive because >= and > both return u128::MAX
    fn saturating_to_u128(&self) -> u128 {
        if *self > Self::from(u128::MAX) {
            u128::MAX
        } else {
            self.low_u128()
        }
    }

    /// Returns the least number of bits needed to represent the number.
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
    fn mul_u64(self, rhs: u64) -> (Self, bool) {
        let mut carry: u128 = 0;
        let mut split_le =
            [self.1 as u64, (self.1 >> 64) as u64, self.0 as u64, (self.0 >> 64) as u64];

        for word in &mut split_le {
            // This will not overflow, for proof see https://github.com/rust-bitcoin/rust-bitcoin/pull/1496#issuecomment-1365938572
            let n = carry + u128::from(rhs) * u128::from(*word);

            *word = n as u64; // Intentional truncation, save the low bits
            carry = n >> 64; // and carry the high bits.
        }

        let low = u128::from(split_le[0]) | (u128::from(split_le[1]) << 64);
        let high = u128::from(split_le[2]) | (u128::from(split_le[3]) << 64);
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
    #[allow(clippy::indexing_slicing)]
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
            return (Self::ZERO, sub_copy);
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

        (Self(ret[0], ret[1]), sub_copy)
    }

    /// Calculates `self` + `rhs`
    ///
    /// Returns a tuple of the addition along with a boolean indicating whether an arithmetic
    /// overflow would occur. If an overflow would have occurred then the wrapped value is returned.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn overflowing_add(self, rhs: Self) -> (Self, bool) {
        let mut ret = Self::ZERO;
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
    fn overflowing_mul(self, rhs: Self) -> (Self, bool) {
        let mut ret = Self::ZERO;
        let mut ret_overflow = false;

        for i in 0..=3 {
            let to_mul = (rhs >> (64 * i)).low_u64();
            let (mul_res, overflow) = self.mul_u64(to_mul);
            ret_overflow |= overflow; // If multiplying lhs by the u64 overflowed, that's an overflow

            // Calculate the bits that will overflow during the shift below.
            let overflow_bits = if i > 0 { mul_res >> (256 - (64 * i)) } else { Self::ZERO };
            ret_overflow |= overflow_bits > Self::ZERO; // If there are bits that will be shifted out below, that's an overflow

            let (sum, overflow) = ret.overflowing_add(mul_res << (64 * i));
            ret = sum;
            ret_overflow |= overflow; // If adding the mul_u64 result overflowed, that's an overflow
        }

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
    fn wrapping_inc(&self) -> Self {
        let mut ret = Self::ZERO;

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
    fn wrapping_shl(self, rhs: u32) -> Self {
        let shift = rhs & 0x0000_00ff;

        let mut ret = Self::ZERO;
        let word_shift = shift >= 128;
        let bit_shift = shift % 128;

        if word_shift {
            ret.0 = self.1 << bit_shift;
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
    fn wrapping_shr(self, rhs: u32) -> Self {
        let shift = rhs & 0x0000_00ff;

        let mut ret = Self::ZERO;
        let word_shift = shift >= 128;
        let bit_shift = shift % 128;

        if word_shift {
            ret.1 = self.0 >> bit_shift;
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
    #[allow(clippy::indexing_slicing)]
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

    /// Converts self to f64.
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
            (mantissa + ((dropped_bits - ((dropped_bits >> 127) & !mantissa)) >> 127)) as u64;
        // Step 6: Calculate the exponent
        // If self is 0, exponent should be 0 (special meaning) and mantissa will end up 0 too
        // Otherwise, (255 - n) + 1022 so it simplifies to 1277 - n
        // 1023 and 1022 are the cutoffs for the exponent having the msb next to the decimal point
        let exponent = if self == Self::ZERO { 0 } else { 1277 - u64::from(leading_zeroes) };
        // Step 7: sign bit is always 0, exponent is shifted into place
        // Use addition instead of bitwise OR to saturate the exponent if mantissa overflows
        f64::from_bits((exponent << 52) + mantissa)
    }
}

impl<T: Into<u128>> From<T> for U256 {
    fn from(x: T) -> Self { Self(0, x.into()) }
}

impl Add for U256 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let (res, overflow) = self.overflowing_add(rhs);
        debug_assert!(!overflow, "addition of U256 values overflowed");
        res
    }
}

impl Sub for U256 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let (res, overflow) = self.overflowing_sub(rhs);
        debug_assert!(!overflow, "subtraction of U256 values overflowed");
        res
    }
}

impl Mul for U256 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        let (res, overflow) = self.overflowing_mul(rhs);
        debug_assert!(!overflow, "multiplication of U256 values overflowed");
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

    fn not(self) -> Self { Self(!self.0, !self.1) }
}

impl Shl<u32> for U256 {
    type Output = Self;
    fn shl(self, shift: u32) -> Self { self.wrapping_shl(shift) }
}

impl Shr<u32> for U256 {
    type Output = Self;
    fn shr(self, shift: u32) -> Self { self.wrapping_shr(shift) }
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

impl fmt::Binary for U256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use fmt::Write as _;

        if f.alternate() {
            f.write_str("0b")?;
        }

        let mut write_buf: Self = *self;

        #[allow(clippy::indexing_slicing)]
        while write_buf > Self::ZERO {
            let bit = write_buf.low_u64() & 0x1;
            f.write_char(if bit > 0 { '1' } else { '0' })?;
            write_buf = write_buf >> 1;
        }
        Ok(())
    }
}

impl fmt::Octal for U256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use fmt::Write as _;

        const CHARS: [char; 8] = ['0', '1', '2', '3', '4', '5', '6', '7'];

        if f.alternate() {
            f.write_str("0o")?;
        }

        let mut write_buf: Self = *self;

        #[allow(clippy::indexing_slicing)]
        while write_buf > Self::ZERO {
            let chunk = write_buf.low_u64() & 0x7;
            f.write_char(CHARS[chunk as usize])?;
            write_buf = write_buf >> 1;
        }
        Ok(())
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
