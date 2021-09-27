// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Big unsigned integer types
//!
//! Implementation of a various large-but-fixed sized unsigned integer types.
//! The functions here are designed to be fast.
//!

macro_rules! construct_uint {
    ($name:ident, $n_words:expr) => (
        /// Little-endian large integer type
        #[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
        pub struct $name(pub [u64; $n_words]);
        impl_array_newtype!($name, u64, $n_words);

        impl $name {
            /// Conversion to u32
            #[inline]
            pub fn low_u32(&self) -> u32 {
                let &$name(ref arr) = self;
                arr[0] as u32
            }

            /// Conversion to u64
            #[inline]
            pub fn low_u64(&self) -> u64 {
                let &$name(ref arr) = self;
                arr[0] as u64
            }


            /// Return the least number of bits needed to represent the number
            #[inline]
            pub fn bits(&self) -> usize {
                let &$name(ref arr) = self;
                for i in 1..$n_words {
                    if arr[$n_words - i] > 0 { return (0x40 * ($n_words - i + 1)) - arr[$n_words - i].leading_zeros() as usize; }
                }
                0x40 - arr[0].leading_zeros() as usize
            }

            /// Multiplication by u32
            pub fn mul_u32(self, other: u32) -> $name {
                let $name(ref arr) = self;
                let mut carry = [0u64; $n_words];
                let mut ret = [0u64; $n_words];
                for i in 0..$n_words {
                    let not_last_word = i < $n_words - 1;
                    let upper = other as u64 * (arr[i] >> 32);
                    let lower = other as u64 * (arr[i] & 0xFFFFFFFF);
                    if not_last_word {
                        carry[i + 1] += upper >> 32;
                    }
                    let (sum, overflow) = lower.overflowing_add(upper << 32);
                    ret[i] = sum;
                    if overflow && not_last_word {
                        carry[i + 1] += 1;
                    }
                }
                $name(ret) + $name(carry)
            }

            /// Create an object from a given unsigned 64-bit integer
            #[inline]
            pub fn from_u64(init: u64) -> Option<$name> {
                let mut ret = [0; $n_words];
                ret[0] = init;
                Some($name(ret))
            }

            /// Create an object from a given signed 64-bit integer
            #[inline]
            pub fn from_i64(init: i64) -> Option<$name> {
                if init >= 0 {
                    $name::from_u64(init as u64)
                } else {
                    None
                }
            }

            /// Creates big integer value from a byte array using
            /// big-endian encoding
            pub fn from_be_bytes(bytes: [u8; $n_words * 8]) -> $name {
                Self::_from_be_slice(&bytes)
            }

            /// Creates big integer value from a byte slice using
            /// big-endian encoding
            pub fn from_be_slice(bytes: &[u8]) -> Result<$name, ParseLengthError> {
                if bytes.len() != $n_words * 8 {
                    Err(ParseLengthError { actual: bytes.len(), expected: $n_words*8 })
                } else {
                    Ok(Self::_from_be_slice(bytes))
                }
            }

            fn _from_be_slice(bytes: &[u8]) -> $name {
                use super::endian::slice_to_u64_be;
                let mut slice = [0u64; $n_words];
                slice.iter_mut()
                    .rev()
                    .zip(bytes.chunks(8))
                    .for_each(|(word, bytes)| *word = slice_to_u64_be(bytes));
                $name(slice)
            }

            /// Convert a big integer into a byte array using big-endian encoding
            pub fn to_be_bytes(&self) -> [u8; $n_words * 8] {
                use super::endian::u64_to_array_be;
                let mut res = [0; $n_words * 8];
                for i in 0..$n_words {
                    let start = i * 8;
                    res[start..start+8].copy_from_slice(&u64_to_array_be(self.0[$n_words - (i+1)]));
                }
                res
            }

            // divmod like operation, returns (quotient, remainder)
            #[inline]
            fn div_rem(self, other: Self) -> (Self, Self) {
                let mut sub_copy = self;
                let mut shift_copy = other;
                let mut ret = [0u64; $n_words];

                let my_bits = self.bits();
                let your_bits = other.bits();

                // Check for division by 0
                assert!(your_bits != 0);

                // Early return in case we are dividing by a larger number than us
                if my_bits < your_bits {
                    return ($name(ret), sub_copy);
                }

                // Bitwise long division
                let mut shift = my_bits - your_bits;
                shift_copy = shift_copy << shift;
                loop {
                    if sub_copy >= shift_copy {
                        ret[shift / 64] |= 1 << (shift % 64);
                        sub_copy = sub_copy - shift_copy;
                    }
                    shift_copy = shift_copy >> 1;
                    if shift == 0 {
                        break;
                    }
                    shift -= 1;
                }

                ($name(ret), sub_copy)
            }

            /// Increment by 1
            #[inline]
            pub fn increment(&mut self) {
                let &mut $name(ref mut arr) = self;
                for i in 0..$n_words {
                    arr[i] = arr[i].wrapping_add(1);
                    if arr[i] != 0 { break; }
                }
            }
        }

        impl PartialOrd for $name {
            #[inline]
            fn partial_cmp(&self, other: &$name) -> Option<::core::cmp::Ordering> {
                Some(self.cmp(&other))
            }
        }

        impl Ord for $name {
            #[inline]
            fn cmp(&self, other: &$name) -> ::core::cmp::Ordering {
                // We need to manually implement ordering because we use little-endian
                // and the auto derive is a lexicographic ordering(i.e. memcmp)
                // which with numbers is equivalent to big-endian
                for i in 0..$n_words {
                    if self[$n_words - 1 - i] < other[$n_words - 1 - i] { return ::core::cmp::Ordering::Less; }
                    if self[$n_words - 1 - i] > other[$n_words - 1 - i] { return ::core::cmp::Ordering::Greater; }
                }
                ::core::cmp::Ordering::Equal
            }
        }

        impl ::core::ops::Add<$name> for $name {
            type Output = $name;

            fn add(self, other: $name) -> $name {
                let $name(ref me) = self;
                let $name(ref you) = other;
                let mut ret = [0u64; $n_words];
                let mut carry = [0u64; $n_words];
                let mut b_carry = false;
                for i in 0..$n_words {
                    ret[i] = me[i].wrapping_add(you[i]);
                    if i < $n_words - 1 && ret[i] < me[i] {
                        carry[i + 1] = 1;
                        b_carry = true;
                    }
                }
                if b_carry { $name(ret) + $name(carry) } else { $name(ret) }
            }
        }

        impl ::core::ops::Sub<$name> for $name {
            type Output = $name;

            #[inline]
            fn sub(self, other: $name) -> $name {
                self + !other + $crate::util::BitArray::one()
            }
        }

        impl ::core::ops::Mul<$name> for $name {
            type Output = $name;

            fn mul(self, other: $name) -> $name {
                use $crate::util::BitArray;
                let mut me = $name::zero();
                // TODO: be more efficient about this
                for i in 0..(2 * $n_words) {
                    let to_mul = (other >> (32 * i)).low_u32();
                    me = me + (self.mul_u32(to_mul) << (32 * i));
                }
                me
            }
        }

        impl ::core::ops::Div<$name> for $name {
            type Output = $name;

            fn div(self, other: $name) -> $name {
                self.div_rem(other).0
            }
        }

        impl ::core::ops::Rem<$name> for $name {
            type Output = $name;

            fn rem(self, other: $name) -> $name {
                self.div_rem(other).1
            }
        }

        impl $crate::util::BitArray for $name {
            #[inline]
            fn bit(&self, index: usize) -> bool {
                let &$name(ref arr) = self;
                arr[index / 64] & (1 << (index % 64)) != 0
            }

            #[inline]
            fn bit_slice(&self, start: usize, end: usize) -> $name {
                (*self >> start).mask(end - start)
            }

            #[inline]
            fn mask(&self, n: usize) -> $name {
                let &$name(ref arr) = self;
                let mut ret = [0; $n_words];
                for i in 0..$n_words {
                    if n >= 0x40 * (i + 1) {
                        ret[i] = arr[i];
                    } else {
                        ret[i] = arr[i] & ((1 << (n - 0x40 * i)) - 1);
                        break;
                    }
                }
                $name(ret)
            }

            #[inline]
            fn trailing_zeros(&self) -> usize {
                let &$name(ref arr) = self;
                for i in 0..($n_words - 1) {
                    if arr[i] > 0 { return (0x40 * i) + arr[i].trailing_zeros() as usize; }
                }
                (0x40 * ($n_words - 1)) + arr[$n_words - 1].trailing_zeros() as usize
            }

            fn zero() -> $name { Default::default() }
            fn one() -> $name {
                $name({ let mut ret = [0; $n_words]; ret[0] = 1; ret })
            }
        }

        impl ::core::ops::BitAnd<$name> for $name {
            type Output = $name;

            #[inline]
            fn bitand(self, other: $name) -> $name {
                let $name(ref arr1) = self;
                let $name(ref arr2) = other;
                let mut ret = [0u64; $n_words];
                for i in 0..$n_words {
                    ret[i] = arr1[i] & arr2[i];
                }
                $name(ret)
            }
        }

        impl ::core::ops::BitXor<$name> for $name {
            type Output = $name;

            #[inline]
            fn bitxor(self, other: $name) -> $name {
                let $name(ref arr1) = self;
                let $name(ref arr2) = other;
                let mut ret = [0u64; $n_words];
                for i in 0..$n_words {
                    ret[i] = arr1[i] ^ arr2[i];
                }
                $name(ret)
            }
        }

        impl ::core::ops::BitOr<$name> for $name {
            type Output = $name;

            #[inline]
            fn bitor(self, other: $name) -> $name {
                let $name(ref arr1) = self;
                let $name(ref arr2) = other;
                let mut ret = [0u64; $n_words];
                for i in 0..$n_words {
                    ret[i] = arr1[i] | arr2[i];
                }
                $name(ret)
            }
        }

        impl ::core::ops::Not for $name {
            type Output = $name;

            #[inline]
            fn not(self) -> $name {
                let $name(ref arr) = self;
                let mut ret = [0u64; $n_words];
                for i in 0..$n_words {
                    ret[i] = !arr[i];
                }
                $name(ret)
            }
        }

        impl ::core::ops::Shl<usize> for $name {
            type Output = $name;

            fn shl(self, shift: usize) -> $name {
                let $name(ref original) = self;
                let mut ret = [0u64; $n_words];
                let word_shift = shift / 64;
                let bit_shift = shift % 64;
                for i in 0..$n_words {
                    // Shift
                    if bit_shift < 64 && i + word_shift < $n_words {
                        ret[i + word_shift] += original[i] << bit_shift;
                    }
                    // Carry
                    if bit_shift > 0 && i + word_shift + 1 < $n_words {
                        ret[i + word_shift + 1] += original[i] >> (64 - bit_shift);
                    }
                }
                $name(ret)
            }
        }

        impl ::core::ops::Shr<usize> for $name {
            type Output = $name;

            fn shr(self, shift: usize) -> $name {
                let $name(ref original) = self;
                let mut ret = [0u64; $n_words];
                let word_shift = shift / 64;
                let bit_shift = shift % 64;
                for i in word_shift..$n_words {
                    // Shift
                    ret[i - word_shift] += original[i] >> bit_shift;
                    // Carry
                    if bit_shift > 0 && i < $n_words - 1 {
                        ret[i - word_shift] += original[i + 1] << (64 - bit_shift);
                    }
                }
                $name(ret)
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                let &$name(ref data) = self;
                write!(f, "0x")?;
                for ch in data.iter().rev() {
                    write!(f, "{:016x}", ch)?;
                }
                Ok(())
            }
        }

        display_from_debug!($name);

        impl $crate::consensus::Encodable for $name {
            #[inline]
            fn consensus_encode<S: $crate::io::Write>(
                &self,
                mut s: S,
            ) -> Result<usize, $crate::io::Error> {
                let &$name(ref data) = self;
                let mut len = 0;
                for word in data.iter() {
                    len += word.consensus_encode(&mut s)?;
                }
                Ok(len)
            }
        }

        impl $crate::consensus::Decodable for $name {
            fn consensus_decode<D: $crate::io::Read>(
                mut d: D,
            ) -> Result<$name, $crate::consensus::encode::Error> {
                use $crate::consensus::Decodable;
                let mut ret: [u64; $n_words] = [0; $n_words];
                for i in 0..$n_words {
                    ret[i] = Decodable::consensus_decode(&mut d)?;
                }
                Ok($name(ret))
            }
        }

        #[cfg(feature = "serde")]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                use $crate::hashes::hex::ToHex;
                let bytes = self.to_be_bytes();
                if serializer.is_human_readable() {
                    serializer.serialize_str(&bytes.to_hex())
                } else {
                    serializer.serialize_bytes(&bytes)
                }
            }
        }

        #[cfg(feature = "serde")]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D: $crate::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                use ::core::fmt;
                use $crate::hashes::hex::FromHex;
                use $crate::serde::de;
                struct Visitor;
                impl<'de> de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        write!(f, "{} bytes or a hex string with {} characters", $n_words * 8, $n_words * 8 * 2)
                    }

                    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        let bytes = $crate::prelude::Vec::from_hex(s)
                            .map_err(|_| de::Error::invalid_value(de::Unexpected::Str(s), &self))?;
                        $name::from_be_slice(&bytes)
                            .map_err(|_| de::Error::invalid_length(bytes.len() * 2, &self))
                    }

                    fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        $name::from_be_slice(bytes)
                            .map_err(|_| de::Error::invalid_length(bytes.len(), &self))
                    }
                }

                if deserializer.is_human_readable() {
                    deserializer.deserialize_str(Visitor)
                } else {
                    deserializer.deserialize_bytes(Visitor)
                }
            }
        }
    );
}

construct_uint!(Uint256, 4);
construct_uint!(Uint128, 2);

/// Invalid slice length
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
/// Invalid slice length
pub struct ParseLengthError {
    /// The length of the slice de-facto
    pub actual: usize,
    /// The required length of the slice
    pub expected: usize,
}

impl ::core::fmt::Display for ParseLengthError {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "Invalid length: got {}, expected {}", self.actual, self.expected)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl ::std::error::Error for ParseLengthError {}

impl Uint256 {
    /// Decay to a uint128
    #[inline]
    pub fn low_128(&self) -> Uint128 {
        let &Uint256(data) = self;
        Uint128([data[0], data[1]])
    }
}

#[cfg(test)]
mod tests {
    use consensus::{deserialize, serialize};
    use util::uint::{Uint256, Uint128};
    use util::BitArray;

    #[test]
    pub fn uint256_bits_test() {
        assert_eq!(Uint256::from_u64(255).unwrap().bits(), 8);
        assert_eq!(Uint256::from_u64(256).unwrap().bits(), 9);
        assert_eq!(Uint256::from_u64(300).unwrap().bits(), 9);
        assert_eq!(Uint256::from_u64(60000).unwrap().bits(), 16);
        assert_eq!(Uint256::from_u64(70000).unwrap().bits(), 17);

        // Try to read the following lines out loud quickly
        let mut shl = Uint256::from_u64(70000).unwrap();
        shl = shl << 100;
        assert_eq!(shl.bits(), 117);
        shl = shl << 100;
        assert_eq!(shl.bits(), 217);
        shl = shl << 100;
        assert_eq!(shl.bits(), 0);

        // Bit set check
        assert!(!Uint256::from_u64(10).unwrap().bit(0));
        assert!(Uint256::from_u64(10).unwrap().bit(1));
        assert!(!Uint256::from_u64(10).unwrap().bit(2));
        assert!(Uint256::from_u64(10).unwrap().bit(3));
        assert!(!Uint256::from_u64(10).unwrap().bit(4));
    }

    #[test]
    pub fn uint256_display_test() {
        assert_eq!(format!("{}", Uint256::from_u64(0xDEADBEEF).unwrap()),
                   "0x00000000000000000000000000000000000000000000000000000000deadbeef");
        assert_eq!(format!("{}", Uint256::from_u64(u64::max_value()).unwrap()),
                   "0x000000000000000000000000000000000000000000000000ffffffffffffffff");

        let max_val = Uint256([0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                               0xFFFFFFFFFFFFFFFF]);
        assert_eq!(format!("{}", max_val),
                   "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    }

    #[test]
    pub fn uint256_comp_test() {
        let small = Uint256([10u64, 0, 0, 0]);
        let big = Uint256([0x8C8C3EE70C644118u64, 0x0209E7378231E632, 0, 0]);
        let bigger = Uint256([0x9C8C3EE70C644118u64, 0x0209E7378231E632, 0, 0]);
        let biggest = Uint256([0x5C8C3EE70C644118u64, 0x0209E7378231E632, 0, 1]);

        assert!(small < big);
        assert!(big < bigger);
        assert!(bigger < biggest);
        assert!(bigger <= biggest);
        assert!(biggest <= biggest);
        assert!(bigger >= big);
        assert!(bigger >= small);
        assert!(small <= small);
    }

    #[test]
    pub fn uint_from_be_bytes() {
        assert_eq!(Uint128::from_be_bytes([0x1b, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe, 0x2b, 0xed, 0xfe, 0xed]),
                   Uint128([0xdeafbabe2bedfeed, 0x1badcafedeadbeef]));

        assert_eq!(Uint256::from_be_bytes([0x1b, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe, 0x2b, 0xed, 0xfe, 0xed,
                                           0xba, 0xad, 0xf0, 0x0d, 0xde, 0xfa, 0xce, 0xda, 0x11, 0xfe, 0xd2, 0xba, 0xd1, 0xc0, 0xff, 0xe0]),
                   Uint256([0x11fed2bad1c0ffe0, 0xbaadf00ddefaceda, 0xdeafbabe2bedfeed, 0x1badcafedeadbeef]));
    }

    #[test]
    pub fn uint_to_be_bytes() {
        assert_eq!(Uint128([0xdeafbabe2bedfeed, 0x1badcafedeadbeef]).to_be_bytes(),
                   [0x1b, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe, 0x2b, 0xed, 0xfe, 0xed]);

        assert_eq!(Uint256([0x11fed2bad1c0ffe0, 0xbaadf00ddefaceda, 0xdeafbabe2bedfeed, 0x1badcafedeadbeef]).to_be_bytes(),
                   [0x1b, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe, 0x2b, 0xed, 0xfe, 0xed,
                    0xba, 0xad, 0xf0, 0x0d, 0xde, 0xfa, 0xce, 0xda, 0x11, 0xfe, 0xd2, 0xba, 0xd1, 0xc0, 0xff, 0xe0]);
    }

    #[test]
    pub fn uint256_arithmetic_test() {
        let init = Uint256::from_u64(0xDEADBEEFDEADBEEF).unwrap();
        let copy = init;

        let add = init + copy;
        assert_eq!(add, Uint256([0xBD5B7DDFBD5B7DDEu64, 1, 0, 0]));
        // Bitshifts
        let shl = add << 88;
        assert_eq!(shl, Uint256([0u64, 0xDFBD5B7DDE000000, 0x1BD5B7D, 0]));
        let shr = shl >> 40;
        assert_eq!(shr, Uint256([0x7DDE000000000000u64, 0x0001BD5B7DDFBD5B, 0, 0]));
        // Increment
        let mut incr = shr;
        incr.increment();
        assert_eq!(incr, Uint256([0x7DDE000000000001u64, 0x0001BD5B7DDFBD5B, 0, 0]));
        // Subtraction
        let sub = incr - init;
        assert_eq!(sub, Uint256([0x9F30411021524112u64, 0x0001BD5B7DDFBD5A, 0, 0]));
        // Multiplication
        let mult = sub.mul_u32(300);
        assert_eq!(mult, Uint256([0x8C8C3EE70C644118u64, 0x0209E7378231E632, 0, 0]));
        // Division
        assert_eq!(Uint256::from_u64(105).unwrap() /
                   Uint256::from_u64(5).unwrap(),
                   Uint256::from_u64(21).unwrap());
        let div = mult / Uint256::from_u64(300).unwrap();
        assert_eq!(div, Uint256([0x9F30411021524112u64, 0x0001BD5B7DDFBD5A, 0, 0]));

        assert_eq!(Uint256::from_u64(105).unwrap() % Uint256::from_u64(5).unwrap(),
                   Uint256::from_u64(0).unwrap());
        assert_eq!(Uint256::from_u64(35498456).unwrap() % Uint256::from_u64(3435).unwrap(),
                   Uint256::from_u64(1166).unwrap());
        let rem_src = mult * Uint256::from_u64(39842).unwrap() + Uint256::from_u64(9054).unwrap();
        assert_eq!(rem_src % Uint256::from_u64(39842).unwrap(),
                   Uint256::from_u64(9054).unwrap());
        // TODO: bit inversion
    }

    #[test]
    pub fn mul_u32_test() {
        let u64_val = Uint256::from_u64(0xDEADBEEFDEADBEEF).unwrap();

        let u96_res = u64_val.mul_u32(0xFFFFFFFF);
        let u128_res = u96_res.mul_u32(0xFFFFFFFF);
        let u160_res = u128_res.mul_u32(0xFFFFFFFF);
        let u192_res = u160_res.mul_u32(0xFFFFFFFF);
        let u224_res = u192_res.mul_u32(0xFFFFFFFF);
        let u256_res = u224_res.mul_u32(0xFFFFFFFF);

        assert_eq!(u96_res, Uint256([0xffffffff21524111u64, 0xDEADBEEE, 0, 0]));
        assert_eq!(u128_res, Uint256([0x21524111DEADBEEFu64, 0xDEADBEEE21524110, 0, 0]));
        assert_eq!(u160_res, Uint256([0xBD5B7DDD21524111u64, 0x42A4822200000001, 0xDEADBEED, 0]));
        assert_eq!(u192_res, Uint256([0x63F6C333DEADBEEFu64, 0xBD5B7DDFBD5B7DDB, 0xDEADBEEC63F6C334, 0]));
        assert_eq!(u224_res, Uint256([0x7AB6FBBB21524111u64, 0xFFFFFFFBA69B4558, 0x854904485964BAAA, 0xDEADBEEB]));
        assert_eq!(u256_res, Uint256([0xA69B4555DEADBEEFu64, 0xA69B455CD41BB662, 0xD41BB662A69B4550, 0xDEADBEEAA69B455C]));
    }

    #[test]
    pub fn multiplication_test() {
        let u64_val = Uint256::from_u64(0xDEADBEEFDEADBEEF).unwrap();

        let u128_res = u64_val * u64_val;

        assert_eq!(u128_res, Uint256([0x048D1354216DA321u64, 0xC1B1CD13A4D13D46, 0, 0]));

        let u256_res = u128_res * u128_res;

        assert_eq!(u256_res, Uint256([0xF4E166AAD40D0A41u64, 0xF5CF7F3618C2C886u64,
                                      0x4AFCFF6F0375C608u64, 0x928D92B4D7F5DF33u64]));
    }

    #[test]
    pub fn increment_test() {
        let mut val = Uint256([
            0xFFFFFFFFFFFFFFFEu64,
            0xFFFFFFFFFFFFFFFFu64,
            0xFFFFFFFFFFFFFFFFu64,
            0xEFFFFFFFFFFFFFFFu64,
        ]);
        val.increment();
        assert_eq!(
            val,
            Uint256([
                0xFFFFFFFFFFFFFFFFu64,
                0xFFFFFFFFFFFFFFFFu64,
                0xFFFFFFFFFFFFFFFFu64,
                0xEFFFFFFFFFFFFFFFu64,
            ])
        );
        val.increment();
        assert_eq!(
            val,
            Uint256([
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0xF000000000000000u64,
            ])
        );

        let mut val = Uint256([
            0xFFFFFFFFFFFFFFFFu64,
            0xFFFFFFFFFFFFFFFFu64,
            0xFFFFFFFFFFFFFFFFu64,
            0xFFFFFFFFFFFFFFFFu64,
        ]);
        val.increment();
        assert_eq!(
            val,
            Uint256([
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
            ])
        );
    }

    #[test]
    pub fn uint256_bitslice_test() {
        let init = Uint256::from_u64(0xDEADBEEFDEADBEEF).unwrap();
        let add = init + (init << 64);
        assert_eq!(add.bit_slice(64, 128), init);
        assert_eq!(add.mask(64), init);
    }

    #[test]
    pub fn uint256_extreme_bitshift_test() {
        // Shifting a u64 by 64 bits gives an undefined value, so make sure that
        // we're doing the Right Thing here
        let init = Uint256::from_u64(0xDEADBEEFDEADBEEF).unwrap();

        assert_eq!(init << 64, Uint256([0, 0xDEADBEEFDEADBEEF, 0, 0]));
        let add = (init << 64) + init;
        assert_eq!(add, Uint256([0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 0, 0]));
        assert_eq!(add >> 0, Uint256([0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 0, 0]));
        assert_eq!(add << 0, Uint256([0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 0, 0]));
        assert_eq!(add >> 64, Uint256([0xDEADBEEFDEADBEEF, 0, 0, 0]));
        assert_eq!(add << 64, Uint256([0, 0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 0]));
    }

    #[test]
    pub fn uint256_serialize_test() {
        let start1 = Uint256([0x8C8C3EE70C644118u64, 0x0209E7378231E632, 0, 0]);
        let start2 = Uint256([0x8C8C3EE70C644118u64, 0x0209E7378231E632, 0xABCD, 0xFFFF]);
        let serial1 = serialize(&start1);
        let serial2 = serialize(&start2);
        let end1: Result<Uint256, _> = deserialize(&serial1);
        let end2: Result<Uint256, _> = deserialize(&serial2);

        assert_eq!(end1.ok(), Some(start1));
        assert_eq!(end2.ok(), Some(start2));
    }

    #[cfg(feature = "serde")]
    #[test]
    pub fn uint256_serde_test() {
        let check = |uint, hex| {
            let json = format!("\"{}\"", hex);
            assert_eq!(::serde_json::to_string(&uint).unwrap(), json);
            assert_eq!(::serde_json::from_str::<Uint256>(&json).unwrap(), uint);

            let bin_encoded = ::bincode::serialize(&uint).unwrap();
            let bin_decoded: Uint256 = ::bincode::deserialize(&bin_encoded).unwrap();
            assert_eq!(bin_decoded, uint);
        };

        check(
            Uint256::from_u64(0).unwrap(),
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        check(
            Uint256::from_u64(0xDEADBEEF).unwrap(),
            "00000000000000000000000000000000000000000000000000000000deadbeef",
        );
        check(
            Uint256([0xaa11, 0xbb22, 0xcc33, 0xdd44]),
            "000000000000dd44000000000000cc33000000000000bb22000000000000aa11",
        );
        check(
            Uint256([u64::max_value(), u64::max_value(), u64::max_value(), u64::max_value()]),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        check(
            Uint256([ 0xA69B4555DEADBEEF, 0xA69B455CD41BB662, 0xD41BB662A69B4550, 0xDEADBEEAA69B455C ]),
            "deadbeeaa69b455cd41bb662a69b4550a69b455cd41bb662a69b4555deadbeef",
        );

        assert!(::serde_json::from_str::<Uint256>("\"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffg\"").is_err()); // invalid char
        assert!(::serde_json::from_str::<Uint256>("\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"").is_err()); // invalid length
        assert!(::serde_json::from_str::<Uint256>("\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"").is_err()); // invalid length
    }
}
