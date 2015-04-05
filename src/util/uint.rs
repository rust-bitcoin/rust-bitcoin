// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! # Big unsigned integer types
//!
//! Implementation of a various large-but-fixed sized unsigned integer types.
//! The functions here are designed to be fast.
//!

use std::fmt;
use std::num::{Zero, One};

use network::serialize::RawEncoder;
use util::BitArray;

macro_rules! construct_uint {
  ($name:ident, $n_words:expr) => (
    /// Little-endian large integer type
    #[repr(C)]
    pub struct $name(pub [u64; $n_words]);
    impl_array_newtype!($name, u64, $n_words);

    impl $name {
      /// Conversion to u32
      #[inline]
      pub fn low_u32(&self) -> u32 {
        let &$name(ref arr) = self;
        arr[0] as u32
      }

      /// Return the least number of bits needed to represent the number
      #[inline]
      pub fn bits(&self) -> usize {
        let &$name(ref arr) = self;
        for i in 1..$n_words {
          if arr[$n_words - i] > 0 { return (0x40 * ($n_words - i + 1)) - arr[$n_words - i].leading_zeros() as usize; }
        }
        0x40 - arr[0].leading_zeros()
      }

      /// Multiplication by u32
      pub fn mul_u32(&self, other: u32) -> $name {
        let &$name(ref arr) = self;
        let mut carry = [0u64; $n_words];
        let mut ret = [0u64; $n_words];
        for i in 0..$n_words {
          let upper = other as u64 * (arr[i] >> 32);
          let lower = other as u64 * (arr[i] & 0xFFFFFFFF);
          if i < 3 {
            carry[i + 1] += upper >> 32;
          }
          ret[i] = lower + (upper << 32);
        }
        $name(ret) + $name(carry)
      }
    }

    impl ::std::num::FromPrimitive for $name {
      #[inline]
      fn from_u64(init: u64) -> Option<$name> {
        let mut ret = [0; $n_words];
        ret[0] = init;
        Some($name(ret))
      }

      #[inline]
      fn from_i64(init: i64) -> Option<$name> {
        ::std::num::FromPrimitive::from_u64(init as u64)
      }
    }

    impl ::std::num::Zero for $name {
      fn zero() -> $name { $name([0; $n_words]) }
    }

    impl ::std::num::One for $name {
      fn one() -> $name {
        $name({ let mut ret = [0; $n_words]; ret[0] = 1; ret })
      }
    }

    impl ::std::ops::Add<$name,$name> for $name {
      fn add(&self, other: &$name) -> $name {
        let &$name(ref me) = self;
        let &$name(ref you) = other;
        let mut ret = [0u64; $n_words];
        let mut carry = [0u64; $n_words];
        let mut b_carry = false;
        for i in 0..$n_words {
          ret[i] = me[i] + you[i];
          if i < $n_words - 1 && ret[i] < me[i] {
            carry[i + 1] = 1;
            b_carry = true;
          }
        }
        if b_carry { $name(ret) + $name(carry) } else { $name(ret) }
      }
    }

    impl ::std::ops::Sub<$name,$name> for $name {
      #[inline]
      fn sub(&self, other: &$name) -> $name {
        *self + !*other + One::one()
      }
    }

    impl ::std::ops::Mul<$name,$name> for $name {
      fn mul(&self, other: &$name) -> $name {
        let mut me = *self;
        // TODO: be more efficient about this
        for i in 0..(2 * $n_words) {
          me = me + me.mul_u32((other >> (32 * i)).low_u32()) << (32 * i);
        }
        me
      }
    }

    impl ::std::ops::Div<$name,$name> for $name {
      fn div(&self, other: &$name) -> $name {
        let mut sub_copy = *self;
        let mut shift_copy = *other;
        let mut ret = [0u64; $n_words];
    
        let my_bits = self.bits();
        let your_bits = other.bits();

        // Check for division by 0
        assert!(your_bits != 0);

        // Early return in case we are dividing by a larger number than us
        if my_bits < your_bits {
          return $name(ret);
        }

        // Bitwise long division
        let mut shift = my_bits - your_bits;
        shift_copy = shift_copy << shift;
        loop {
          if sub_copy >= shift_copy {
            ret[shift / 64] |= 1 << (shift % 64);
            sub_copy = sub_copy.sub(&shift_copy);
          }
          shift_copy = shift_copy >> 1;
          if shift == 0 { break; }
          shift -= 1;
        }

        $name(ret)
      }
    }

    impl BitArray for $name {
      #[inline]
      fn bit(&self, index: usize) -> bool {
        let &$name(ref arr) = self;
        arr[index / 64] & (1 << (index % 64)) != 0
      }

      #[inline]
      fn bit_slice(&self, start: usize, end: usize) -> $name {
        (self >> start).mask(end - start)
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
          if arr[i] > 0 { return (0x40 * i) + arr[i].trailing_zeros(); }
        }
        (0x40 * ($n_words - 1)) + arr[3].trailing_zeros()
      }
    }

    impl ::std::ops::BitAnd<$name,$name> for $name {
      #[inline]
      fn bitand(&self, other: &$name) -> $name {
        let &$name(ref arr1) = self;
        let &$name(ref arr2) = other;
        let mut ret = [0u64; $n_words];
        for i in 0..$n_words {
          ret[i] = arr1[i] & arr2[i];
        }
        $name(ret)
      }
    }

    impl ::std::ops::BitXor<$name,$name> for $name {
      #[inline]
      fn bitxor(&self, other: &$name) -> $name {
        let &$name(ref arr1) = self;
        let &$name(ref arr2) = other;
        let mut ret = [0u64; $n_words];
        for i in 0..$n_words {
          ret[i] = arr1[i] ^ arr2[i];
        }
        $name(ret)
      }
    }

    impl ::std::ops::BitOr<$name,$name> for $name {
      #[inline]
      fn bitor(&self, other: &$name) -> $name {
        let &$name(ref arr1) = self;
        let &$name(ref arr2) = other;
        let mut ret = [0u64; $n_words];
        for i in 0..$n_words {
          ret[i] = arr1[i] | arr2[i];
        }
        $name(ret)
      }
    }

    impl ::std::ops::Not<$name> for $name {
      #[inline]
      fn not(&self) -> $name {
        let &$name(ref arr) = self;
        let mut ret = [0u64; $n_words];
        for i in 0..$n_words {
          ret[i] = !arr[i];
        }
        $name(ret)
      }
    }

    impl ::std::ops::Shl<usize, $name> for $name {
      fn shl(&self, shift: &usize) -> $name {
        let &$name(ref original) = self;
        let mut ret = [0u64; $n_words];
        let word_shift = *shift / 64;
        let bit_shift = *shift % 64;
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

    impl ::std::ops::Shr<usize, $name> for $name {
      #[allow(unsigned_negate)]
      fn shr(&self, shift: &usize) -> $name {
        let &$name(ref original) = self;
        let mut ret = [0u64; $n_words];
        let word_shift = *shift / 64;
        let bit_shift = *shift % 64;
        for i in 0..$n_words {
          // Shift
          if bit_shift < 64 && i - word_shift < $n_words {
            ret[i - word_shift] += original[i] >> bit_shift;
          }
          // Carry
          if bit_shift > 0 && i - word_shift - 1 < $n_words {
            ret[i - word_shift - 1] += original[i] << (64 - bit_shift);
          }
        }
        $name(ret)
      }
    }

    impl ::std::cmp::Ord for $name {
      fn cmp(&self, other: &$name) -> ::std::cmp::Ordering {
        let &$name(ref me) = self;
        let &$name(ref you) = other;
        for i in 0..$n_words {
          if me[$n_words - 1 - i] < you[$n_words - 1 - i] { return ::std::cmp::Ordering::Less; }
          if me[$n_words - 1 - i] > you[$n_words - 1 - i] { return ::std::cmp::Ordering::Greater; }
        }
        return ::std::cmp::Ordering::Equal;
      }
    }

    impl ::std::cmp::PartialOrd for $name {
      fn partial_cmp(&self, other: &$name) -> Option<::std::cmp::Ordering> {
        Some(self.cmp(other))
      }
    }

    impl fmt::Debug for $name {
      fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::fmt::Error;
        use network::encodable::ConsensusEncodable;
        let mut encoder = RawEncoder::new(f.by_ref());
        self.consensus_encode(&mut encoder).map_err(|_| Error)
      }
    }

    impl<S: ::network::serialize::SimpleEncoder<E>, E> ::network::encodable::ConsensusEncodable<S, E> for $name {
      #[inline]
      fn consensus_encode(&self, s: &mut S) -> Result<(), E> {
        use network::encodable::ConsensusEncodable;
        let &$name(ref data) = self;
        for word in data.iter() { try!(word.consensus_encode(s)); }
        Ok(())
      }
    }

    impl<D: ::network::serialize::SimpleDecoder<E>, E> ::network::encodable::ConsensusDecodable<D, E> for $name {
      fn consensus_decode(d: &mut D) -> Result<$name, E> {
        use network::encodable::ConsensusDecodable;
        let ret: [u64; $n_words] = try!(ConsensusDecodable::consensus_decode(d));
        Ok($name(ret))
      }
    }
  );
}

construct_uint!(Uint256, 4);
construct_uint!(Uint128, 2);

impl Uint256 {
  /// Increment by 1
  #[inline]
  pub fn increment(&mut self) {
    let &Uint256(ref mut arr) = self;
    arr[0] += 1;
    if arr[0] == 0 {
      arr[1] += 1;
      if arr[1] == 0 {
        arr[2] += 1;
        if arr[2] == 0 {
          arr[3] += 1;
        }
      }
    }
  }

  /// Decay to a uint128
  #[inline]
  pub fn low_128(&self) -> Uint128 {
    let &Uint256(data) = self;
    Uint128([data[0], data[1]])
  }
}

#[cfg(test)]
mod tests {
  use std::io::IoResult;
  use std::num::from_u64;

  use network::serialize::{deserialize, serialize};
  use util::uint::Uint256;
  use util::BitArray;

  #[test]
  pub fn uint256_bits_test() {
    assert_eq!(from_u64::<Uint256>(255).unwrap().bits(), 8);
    assert_eq!(from_u64::<Uint256>(256).unwrap().bits(), 9);
    assert_eq!(from_u64::<Uint256>(300).unwrap().bits(), 9);
    assert_eq!(from_u64::<Uint256>(60000).unwrap().bits(), 16);
    assert_eq!(from_u64::<Uint256>(70000).unwrap().bits(), 17);

    // Try to read the following lines out loud quickly
    let mut shl: Uint256 = from_u64(70000).unwrap();
    shl = shl << 100;
    assert_eq!(shl.bits(), 117);
    shl = shl << 100;
    assert_eq!(shl.bits(), 217);
    shl = shl << 100;
    assert_eq!(shl.bits(), 0);

    // Bit set check
    assert!(!from_u64::<Uint256>(10).unwrap().bit(0));
    assert!(from_u64::<Uint256>(10).unwrap().bit(1));
    assert!(!from_u64::<Uint256>(10).unwrap().bit(2));
    assert!(from_u64::<Uint256>(10).unwrap().bit(3));
    assert!(!from_u64::<Uint256>(10).unwrap().bit(4));
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
  pub fn uint256_arithmetic_test() {
    let init: Uint256 = from_u64(0xDEADBEEFDEADBEEF).unwrap();
    let copy = init;

    let add = init.add(&copy);
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
    let sub = incr.sub(&init);
    assert_eq!(sub, Uint256([0x9F30411021524112u64, 0x0001BD5B7DDFBD5A, 0, 0]));
    // Multiplication
    let mult = sub.mul_u32(300);
    assert_eq!(mult, Uint256([0x8C8C3EE70C644118u64, 0x0209E7378231E632, 0, 0]));
    // Division
    assert_eq!(from_u64::<Uint256>(105).unwrap() /
               from_u64::<Uint256>(5).unwrap(),
               from_u64::<Uint256>(21).unwrap());
    let div = mult / from_u64::<Uint256>(300).unwrap();
    assert_eq!(div, Uint256([0x9F30411021524112u64, 0x0001BD5B7DDFBD5A, 0, 0]));
    // TODO: bit inversion
  }

  #[test]
  pub fn uint256_bitslice_test() {
    let init = from_u64::<Uint256>(0xDEADBEEFDEADBEEF).unwrap();
    let add = init + (init << 64);
    assert_eq!(add.bit_slice(64, 128), init);
    assert_eq!(add.mask(64), init);
  }

  #[test]
  pub fn uint256_extreme_bitshift_test() {
    // Shifting a u64 by 64 bits gives an undefined value, so make sure that
    // we're doing the Right Thing here
    let init = from_u64::<Uint256>(0xDEADBEEFDEADBEEF).unwrap();

    assert_eq!(init << 64, Uint256([0, 0xDEADBEEFDEADBEEF, 0, 0]));
    let add = (init << 64).add(&init);
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
    let serial1 = serialize(&start1).unwrap();
    let serial2 = serialize(&start2).unwrap();
    let end1: IoResult<Uint256> = deserialize(serial1);
    let end2: IoResult<Uint256> = deserialize(serial2);

    assert_eq!(end1, Ok(start1));
    assert_eq!(end2, Ok(start2));
  }
}

