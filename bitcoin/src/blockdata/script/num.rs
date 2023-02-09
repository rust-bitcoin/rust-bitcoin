//! Provides the [`ScriptNum`] type which is equivalent to `CScriptNum` from Bitcoin Core.
//!
//! For `CScriptNum` see `script.h` in the Bitcoin Core source code.

use core::convert::TryInto;
use core::fmt;
// We specifically only implement ops that are implemented by `CScriptNum`. Furthermore we do not
// implement ops from `CScriptNum` that use i64 as the `Rhs`, only those that use `Self` - this is
// inline with the Rust standard integer types.
use core::ops::{Add, AddAssign, BitAnd, BitAndAssign, Sub, SubAssign, Neg};

#[cfg(all(test, mutate))]
use mutagen::mutate;

use crate::blockdata::locktime::absolute;
use crate::blockdata::transaction::Sequence;

/// A signed integer used in Bitcoin Script.
///
/// Bitcoin uses 32 bit integers however, for various reasons, the `CScriptNum` has a few quirks.
/// Primarily, the `ScriptNum` is a signed 64 bit integer but the number of bytes in use is
/// restricted in certain instances:
///
/// - Only 4 bytes (signed 32 bit integer) can be decoded from a script (excl. CSV and CLTV arguments).
/// - For CSV and CLTV arguments up to 5 bytes can be decoded (unsigned 32 bit integer).
/// - The whole 8 bytes can be encoded - this means one can encode a number that cannot be decoded.
///
/// From Bitcoin Core:
///
/// > Numeric opcodes (OP_1ADD, etc) are restricted to operating on 4-byte integers.
/// > The semantics are subtle, though: operands must be in the range [-2^31 +1...2^31 -1],
/// > but results may overflow (and are valid as long as they are not used in a subsequent
/// > numeric operation). CScriptNum enforces those semantics by storing results as
/// > an int64 and allowing out-of-range values to be returned as a vector of bytes but
/// > throwing an exception if arithmetic is done or the result is interpreted as an integer.
///
/// ## Operands
///
/// - Operands must be in the range [-2^31 + 1 ... 2^31 - 1]
/// - Note the range above _excludes_ i32::MIN. This because it requires 5 bytes to encode.
/// - Operands (4 bytes) can be added together (up to 5 bytes), the resulting number _cannot_ be
///   used as an operand but can appear in a script.
/// - Note that the operands range _excludes_ i32::MIN
///
/// ## Minimal encoding
///
/// Encoding tries to use the least number of bytes, in doing so there can be ambiguity with
/// negative numbers which must be explicitly resolved by pushing an extra byte.
///
/// The algorithm to encode `x` is as follows:
///
/// - First encode the absolute value of `x` as a little-endian array of bytes.
/// - If the most significant byte is >= 0x80 and the value is positive, add a
///   new zero-byte to make the significant byte < 0x80 again.
/// - If the most significant byte is >= 0x80 and the value is negative, add a
///   new 0x80 byte that will be popped off when decoding.
/// - If the most significant byte is < 0x80 and the value is negative, add a
///   now 0x80 byte, since it will be subtracted and interpreted as a negative
///   when decoding.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScriptNum(pub i64);

impl ScriptNum {
    /// The zero `ScriptNum`.
    pub const ZERO: Self = ScriptNum(0);

    /// The minimum value for a `ScriptNum` when used as an operand.
    pub const OPERAND_MIN: Self = ScriptNum((i32::min_value() + 1) as i64);

    /// The maximum value for a `ScriptNum` when used as an operand.
    pub const OPERAND_MAX: Self = ScriptNum(i32::max_value() as i64);

    /// Constructs a [`ScriptNum`] from a sequence number.
    #[inline]
    pub fn from_lock_time(lock_time: absolute::LockTime) -> Self {
        Self(lock_time.to_consensus_u32().into())
    }

    /// Constructs a [`ScriptNum`] from an absolute lock time.
    #[inline]
    pub fn from_sequence(sequence: Sequence) -> Self {
        Self(sequence.to_consensus_u32().into())
    }

    /// Encodes this [`ScriptNum`] into `out` in the required script format.
    ///
    /// This is equivalent to `CScriptNum::serialize` in Bitcoin Core.
    ///
    /// # Returns
    ///
    /// The number of bytes encoded into the `out` array.
    #[cfg_attr(all(test, mutate), mutate)]
    pub fn encode(&self, out: &mut [u8; 8]) -> usize {
        if self.0 == 0 {
            return 0;
        }

        let mut len = 0;
        let n = self.0;
        let neg = n < 0;

        // We encode the absolute value byte by byte, shifting `x` right as we do so.
        let mut x = if neg { -n } else { n } as u64;

        while x > 0xFF {
            out[len] = (x & 0xFF) as u8;
            len += 1;
            x >>= 8;
        }

        // If the last byte causes the sign bit to be set, we need an extra byte to get the
        // correct value and correct sign bit. Otherwise we just set the sign bit ourselves.
        if x & 0x80 != 0 {
            out[len] = x as u8; // x only holds the last byte at this stage.
            len += 1;
            out[len] = if neg { 0x80 } else { 0x00 };
            len += 1;
        } else {
            x |= if neg { 0x80 } else { 0x00 };
            out[len] = x as u8;
            len += 1;
        }
        len
    }

    /// Decodes a new [`ScriptNum`] meant to be used with CSV or CLTV.
    ///
    /// Note that the decoded value may be bigger than the `u32` value stored in [`Sequence`] or
    /// [`absolute::LockTime`] - this is inline with Bitcoin Core.
    ///
    /// From Bitcoin Core:
    ///
    /// > Note that elsewhere numeric opcodes are limited to
    /// > operands in the range -2**31+1 to 2**31-1, however it is
    /// > legal for opcodes to produce results exceeding that
    /// > range. This limitation is implemented by CScriptNum's
    /// > default 4-byte limit.
    /// >
    /// > If we kept to that limit we'd have a year 2038 problem,
    /// > even though the nLockTime field in transactions
    /// > themselves is uint32 which only becomes meaningless
    /// > after the year 2106.
    /// >
    /// > Thus as a special case we tell CScriptNum to accept up
    /// > to 5-byte bignums, which are good until 2**39-1, well
    /// > beyond the 2**32-1 limit of the nLockTime field itself.
    #[inline]
    pub fn decode_lock(v: &[u8]) -> Result<Self, Error> {
        ScriptNum::decode_minimal(v, 5)
    }

    /// Decodes a new [`ScriptNum`] meant for use as an operand.
    ///
    /// Only 4-byte encodings are supported, this is inline with Bitcoin Core (see the `CScriptNum`
    /// constructor and usage of the`nMaxNumSize` parameter codebase wide).
    ///
    /// If you need to decode a `ScriptNum` for use with CSV or CLTV use [`decode_lock`].
    #[inline]
    pub fn decode(v: &[u8]) -> Result<Self, Error> {
        ScriptNum::decode_minimal(v, 4)
    }

    /// Constructs a new [`ScriptNum`] from a minimal slice representation.
    #[cfg_attr(all(test, mutate), mutate)]
    fn decode_minimal(v: &[u8], max_size: usize) -> Result<Self, Error> {
        debug_assert!(max_size <= 8);

        let last = match v.last() {
            Some(last) => *last,
            // An empty slice is defined as equal to zero and is minimal.
            None => return Ok(ScriptNum(0)),
        };

        let len = v.len();

        if len > max_size {
            return Err(Error::Overflow);
        }

        if !is_minimal_encoding(v) {
            return Err(Error::NonMinimal);
        }

        let (mut ret, sh) = v.iter()
            .fold((0, 0), |(acc, sh), n| (acc + ((*n as i64) << sh), sh + 8));

        if last & 0x80 != 0 {
            ret &= (1 << (sh - 1)) - 1;
            ret = -ret;
        }
        Ok(Self(ret))
    }

    /// Returns the script num as an `i32` saturating to the min/max values for an `i32`.
    ///
    /// This is equivalent to `CScriptNum::getint()` in Bitcoin Core.
    #[inline]
    #[cfg_attr(all(test, mutate), mutate)]
    pub fn saturating_value(&self) -> i32 {
        if self.0 < i32::min_value().into() {
            return i32::min_value();
        }

        if self.0 > i32::max_value().into() {
            return i32::max_value();
        }

        self.0.try_into().expect("checked above")
    }
}

/// Checks that the encoding is "minimal" as defined by Bitcoin Core (see docs on [`ScriptNum`]).
#[inline]
#[cfg_attr(all(test, mutate), mutate)]
fn is_minimal_encoding(v: &[u8]) -> bool {
    // An empty slice is defined as equal to zero and is minimal. 
    let last = match v.last() {
        Some(last) => last,
        None => return true,
    };

    // If the most-significant-byte - excluding the sign bit - is zero
    // then we're not minimal. Note how this test also rejects the
    // negative-zero encoding, 0x80.
    if last & 0x7f == 0 {
        // One exception: if there's more than one byte and the most
        // significant bit of the second-most-significant-byte is set
        // it would conflict with the sign bit. An example of this case
        // is +-255, which encode to 0xff00 and 0xff80 respectively.
        // (big-endian).
        if v.len() <= 1 || (v[v.len() - 2] & 0x80) == 0 {
            return false;
        }
    }

    true
}

impl From<i32> for ScriptNum {
    #[inline]
    fn from(x: i32) -> Self {
        Self(x.into())
    }
}

impl From<i64> for ScriptNum {
    #[inline]
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl From<ScriptNum> for i64 {
    #[inline]
    fn from(x: ScriptNum) -> Self {
        x.0
    }
}

// FIXME: Do we want this?
impl From<ScriptNum> for i32 {
    #[inline]
    fn from(x: ScriptNum) -> Self {
        x.saturating_value()
    }
}

impl Add for ScriptNum {
    type Output = Self;

    #[inline]
    fn add(self, other: Self) -> Self::Output {
        Self(self.0 + other.0)
    }
}

impl AddAssign for ScriptNum {
    #[inline]
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0;
    }
}

impl Sub for ScriptNum {
    type Output = Self;

    #[inline]
    fn sub(self, other: Self) -> Self::Output {
        Self(self.0 - other.0)
    }
}

impl SubAssign for ScriptNum {
    #[inline]
    fn sub_assign(&mut self, other: Self) {
        self.0 -= other.0;
    }
}

impl Neg for ScriptNum {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl BitAnd for ScriptNum {
    type Output = Self;

    #[inline]
    fn bitand(self, other: Self) -> Self::Output {
        Self(self.0 & other.0)
    }
}

impl BitAndAssign for ScriptNum {
    #[inline]
    fn bitand_assign(&mut self, other: Self) {
        self.0 &= other.0;
    }
}

/// [`ScriptNum`] error.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Attempted to create a [`ScriptNum`] for a non-minimal value.
    NonMinimal,
    /// Encoded byte slice overflows script num.
    Overflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            NonMinimal => write!(f, "attempted to create a script num from a non-minal value"),
            Overflow => write!(f, "encoded byte slice overflows script num"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match *self {
            NonMinimal | Overflow  => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! check_is_minimal_encoding {
        ($($test_name:ident, $val:expr, $expected:expr);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    assert_eq!(is_minimal_encoding(&$val), $expected)
                }
            )*
        }
    }
    check_is_minimal_encoding! {
        is_minimal_encoding_0, [0xff], true; // negative 0x7f
        is_minimal_encoding_1, [0xff, 0x80], true; // negative 0xff
        is_minimal_encoding_2, [0xff, 0x00], true; // positive 0xff
        is_minimal_encoding_3, [0x81], true;
        is_minimal_encoding_4, [0x80], false;
        is_minimal_encoding_5, [0x8f, 0x00, 0x00], false;
        is_minimal_encoding_6, Vec::<u8>::new(), true;
        is_minimal_encoding_7, [0x00], false;
        is_minimal_encoding_8, [0xff, 0xff], true;
        is_minimal_encoding_9, [0xff, 0xff, 0x80], true;
        is_minimal_encoding_10, [0xff, 0xff, 0x00], true;
        is_minimal_encoding_11, [0x7f, 0x80], false;
        is_minimal_encoding_12, [0x7f, 0x00], false;
    }

    macro_rules! check_encode {
        ($($test_name:ident, $int:expr, $expected:expr);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    let n = ScriptNum::from($int);
                    let mut buf = [0_u8; 8];
                    let nbytes = n.encode(&mut buf);
                    assert_eq!(&buf[..nbytes], &$expected)
                }
            )*
        }
    }
    check_encode! {
        script_num_encode_0, 0, Vec::<u8>::new();
        script_num_encode_1, 1, vec![0x01];
        script_num_encode_2, -1, vec![0x81];
        script_num_encode_3, 255, vec![255, 0];
        script_num_encode_4, 256, vec![0, 1];
        script_num_encode_5, 257, vec![1, 1];
        script_num_encode_6, -255, vec![255, 0x80];
        script_num_encode_7, -256, vec![0, 0x81];
        script_num_encode_8, -257, vec![1, 0x81];
        script_num_encode_9, 511, vec![255, 1];
        script_num_encode_10, -511, vec![255, 0x81];
    }

    #[test]
    fn roundtrip_encode_ok() {
        let test_vectors = [
            0, 10, 100, 255, 256, 1000, 10000, 25000, 200000, 5000000, 1000000000,
            (1 << 31) - 1, -((1 << 31) - 1),
        ];
        for tc in test_vectors {
            let n = ScriptNum::from(tc);
            let mut buf = [0_u8; 8];
            let nbytes = n.encode(&mut buf);
            let decoded = ScriptNum::decode(&buf[..nbytes]).expect("decode failed");
            if decoded.0 != tc {
                panic!("failed to roundtrip {}: decoded: {}", tc, decoded.0);
            }
        }
    }

    #[test]
    fn roundtrip_encode_err() {
        let test_vectors = [(1 << 31), (-(1_i64 << 31))];
        for tc in test_vectors {
            let n = ScriptNum::from(tc);
            let mut buf = [0_u8; 8];
            let nbytes = n.encode(&mut buf);
            assert!(ScriptNum::decode(&buf[..nbytes]).is_err())
        }
    }

    #[test]
    fn roundtrip_encode_time_lock_time_ok() {
        let test_vectors = [
            1653195600,         // May 22nd, 5am UTC.
            u32::max_value(),
        ];
        for tc in test_vectors {
            let lock = absolute::LockTime::from_consensus(tc);
            let n = ScriptNum::from_lock_time(lock);
            let mut buf = [0_u8; 8];
            let nbytes = n.encode(&mut buf);
            let decoded = ScriptNum::decode_lock(&buf[..nbytes]).expect("decode failed");
            if decoded.0 != i64::from(tc) {
                panic!("failed to roundtrip {}: decoded: {}", tc, decoded.0);
            }
        }
    }

    #[test]
    fn roundtrip_encode_height_lock_time_ok() {
        let test_vectors = [
            0,
            100,
            absolute::Height::MAX.to_consensus_u32(),
        ];
        for tc in test_vectors {
            let lock = absolute::LockTime::from_consensus(tc);
            let n = ScriptNum::from_lock_time(lock);
            let mut buf = [0_u8; 8];
            let nbytes = n.encode(&mut buf);
            let decoded = ScriptNum::decode_lock(&buf[..nbytes]).expect("decode failed");
            if decoded.0 != i64::from(tc) {
                panic!("failed to roundtrip {}: decoded: {}", tc, decoded.0);
            }
        }
    }

    #[test]
    fn saturating_value_in_range() {
        let test_vectors = vec![0, i32::max_value(), (i32::max_value() - 1), i32::min_value(), (i32::min_value() + 1)];
        for (i, tc) in test_vectors.iter().enumerate() {
            let x = ScriptNum::from(*tc);
            if x.saturating_value() != *tc {
                panic!("saturating_value failed with: {} index: {}", tc, i);
            }
        }
    }

    #[test]
    fn saturating_value_too_small() {
        let test_vectors = vec![i64::min_value(), (i32::min_value() as i64 - 1)];
        for (i, tc) in test_vectors.iter().enumerate() {
            let x = ScriptNum::from(*tc);
            if x.saturating_value() != i32::min_value() {
                panic!("saturating_value failed with: {} index: {}", tc, i);
            }
        }
    }

    #[test]
    fn saturating_value_too_big() {
        let test_vectors = vec![i64::max_value(), (i32::max_value() as i64 + 1)];
        for (i, tc) in test_vectors.iter().enumerate() {
            let x = ScriptNum::from(*tc);
            if x.saturating_value() != i32::max_value() {
                panic!("saturating_value failed with: {} index: {}", tc, i);
            }
        }
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn roundtrip_i32() {
        let x: i32 = kani::any();
        kani::assume(x != -2147483648); // 1 << 31 (needs 5 bytes to encode)
        kani::assume(x != 0); // uses 0 bytes to encode)

        let orig = ScriptNum::from(x);

        let mut buf = [0_u8; 8];
        let nbytes = orig.encode(&mut buf);

        let abs = x.unsigned_abs();
        let leading_zeros = abs.leading_zeros();

        if leading_zeros < 9 {
            assert_eq!(nbytes, 4, "4-byte unsigned integer requires 4 bytes to encode");
        } else if leading_zeros < 17 {
            assert_eq!(nbytes, 3, "3-byte unsigned integer requires 3 bytes to encode");
        } else if leading_zeros < 25 {
            assert_eq!(nbytes, 2, "2-byte unsigned integer requires 2 bytes to encode");
        } else {
            assert_eq!(nbytes, 1, "1-byte unsigned integer requires 1 bytes to encode");
        }

        let decoded = ScriptNum::decode_lock(&buf[..nbytes]).expect("failed to decode script num");

        assert_eq!(decoded, orig);
    }

    #[kani::proof]
    fn roundtrip_u32() {
        let x: u32 = kani::any();

        let seq = Sequence::from_consensus(x);
        let orig = ScriptNum::from_sequence(seq);

        let mut buf = [0_u8; 8];
        let nbytes = orig.encode(&mut buf);
        let decoded = ScriptNum::decode_lock(&buf[..nbytes]);

        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap(), orig);
    }

    #[kani::proof]
    fn saturating_value() {
        let x: i64 = kani::any();
        let n = ScriptNum(x);

        let v = n.saturating_value();
        assert!(v >= i32::min_value() && v <= i32::max_value());
    }
}
