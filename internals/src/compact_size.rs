// SPDX-License-Identifier: CC0-1.0

//! Variable length integer encoding A.K.A [`CompactSize`].
//!
//! An integer can be encoded depending on the represented value to save space. Variable length
//! integers always precede an array/vector of a type of data that may vary in length.
//!
//! [`CompactSize`]: <https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer>

use crate::array_vec::ArrayVec;
use crate::ToU64;

/// The maximum size of a serialized object in bytes or number of elements
/// (for eg vectors) when the size is encoded as `CompactSize`.
///
/// This is `MAX_SIZE` in Bitcoin Core.
// Issue: https://github.com/rust-bitcoin/rust-bitcoin/issues/3264
pub const MAX_ENCODABLE_VALUE: u64 = 0x0200_0000;

/// The maximum length of an encoding.
const MAX_ENCODING_SIZE: usize = 9;

/// Returns the number of bytes used to encode this `CompactSize` value.
///
/// # Returns
///
/// - 1 for 0..=0xFC
/// - 3 for 0xFD..=(2^16-1)
/// - 5 for 0x10000..=(2^32-1)
/// - 9 otherwise.
#[inline]
pub fn encoded_size(value: impl ToU64) -> usize {
    match value.to_u64() {
        0..=0xFC => 1,
        0xFD..=0xFFFF => 3,
        0x10000..=0xFFFFFFFF => 5,
        _ => 9,
    }
}

/// Encodes `CompactSize` without allocating.
#[inline]
pub fn encode(value: impl ToU64) -> ArrayVec<u8, MAX_ENCODING_SIZE> {
    let value = value.to_u64();
    let mut res = ArrayVec::<u8, MAX_ENCODING_SIZE>::new();
    match value {
        0..=0xFC => {
            res.push(value as u8); // Cast ok because of match.
        }
        0xFD..=0xFFFF => {
            let v = value as u16; // Cast ok because of match.
            res.push(0xFD);
            res.extend_from_slice(&v.to_le_bytes());
        }
        0x10000..=0xFFFFFFFF => {
            let v = value as u32; // Cast ok because of match.
            res.push(0xFE);
            res.extend_from_slice(&v.to_le_bytes());
        }
        _ => {
            let v = value;
            res.push(0xFF);
            res.extend_from_slice(&v.to_le_bytes());
        }
    }
    res
}

/// Gets the compact size encoded value from `slice` and moves slice past the encoding.
///
/// Caller to guarantee that the encoding is well formed. Well formed is defined as:
///
/// * Being at least long enough.
/// * Containing a minimal encoding.
///
/// # Panics
///
/// * Panics in release mode if the `slice` does not contain a valid minimal compact size encoding.
/// * Panics in debug mode if the encoding is not minimal (referred to as "non-canonical" in Core).
pub fn decode_unchecked(slice: &mut &[u8]) -> u64 {
    if slice.is_empty() {
        panic!("tried to decode an empty slice");
    }

    match slice[0] {
        0xFF => {
            const SIZE: usize = 9;
            if slice.len() < SIZE {
                panic!("slice too short, expected at least 9 bytes");
            };

            let mut bytes = [0_u8; SIZE - 1];
            bytes.copy_from_slice(&slice[1..SIZE]);

            let v = u64::from_le_bytes(bytes);
            debug_assert!(v > u32::MAX.into(), "non-minimal encoding of a u64");
            *slice = &slice[SIZE..];
            v
        }
        0xFE => {
            const SIZE: usize = 5;
            if slice.len() < SIZE {
                panic!("slice too short, expected at least 5 bytes");
            };

            let mut bytes = [0_u8; SIZE - 1];
            bytes.copy_from_slice(&slice[1..SIZE]);

            let v = u32::from_le_bytes(bytes);
            debug_assert!(v > u16::MAX.into(), "non-minimal encoding of a u32");
            *slice = &slice[SIZE..];
            u64::from(v)
        }
        0xFD => {
            const SIZE: usize = 3;
            if slice.len() < SIZE {
                panic!("slice too short, expected at least 3 bytes");
            };

            let mut bytes = [0_u8; SIZE - 1];
            bytes.copy_from_slice(&slice[1..SIZE]);

            let v = u16::from_le_bytes(bytes);
            debug_assert!(v >= 0xFD, "non-minimal encoding of a u16");
            *slice = &slice[SIZE..];
            u64::from(v)
        }
        n => {
            *slice = &slice[1..];
            u64::from(n)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_value_1_byte() {
        // Check lower bound, upper bound (and implicitly endian-ness).
        for v in [0x00, 0x01, 0x02, 0xFA, 0xFB, 0xFC] {
            let v = v as u32;
            assert_eq!(encoded_size(v), 1);
            // Should be encoded as the value as a u8.
            let want = [v as u8];
            let got = encode(v);
            assert_eq!(got.as_slice().len(), 1); // sanity check
            assert_eq!(got.as_slice(), want);
        }
    }

    #[test]
    fn decode_value_1_byte() {
        // Check lower bound, upper bound.
        for v in [0x00, 0x01, 0x02, 0xFA, 0xFB, 0xFC] {
            let raw = [v];
            let mut slice = raw.as_slice();
            let got = decode_unchecked(&mut slice);
            assert_eq!(got, u64::from(v));
            assert!(slice.is_empty());
        }
    }

    macro_rules! check_encode {
        ($($test_name:ident, $size:expr, $value:expr, $want:expr);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    let value = $value as u64; // Because default integer type is i32.
                    let got = encode(value);
                    assert_eq!(got.as_slice().len(), $size); // sanity check
                    assert_eq!(got.as_slice(), &$want);
                }
            )*
        }
    }

    check_encode! {
        // 3 byte encoding.
        encoded_value_3_byte_lower_bound, 3, 0xFD, [0xFD, 0xFD, 0x00]; // 0x00FD
        encoded_value_3_byte_endianness, 3, 0xABCD, [0xFD, 0xCD, 0xAB];
        encoded_value_3_byte_upper_bound, 3, 0xFFFF, [0xFD, 0xFF, 0xFF];
        // 5 byte encoding.
        encoded_value_5_byte_lower_bound, 5, 0x0001_0000, [0xFE, 0x00, 0x00, 0x01, 0x00];
        encoded_value_5_byte_endianness, 5, 0x0123_4567, [0xFE, 0x67, 0x45, 0x23, 0x01];
        encoded_value_5_byte_upper_bound, 5, 0xFFFF_FFFF, [0xFE, 0xFF, 0xFF, 0xFF, 0xFF];
        // 9 byte encoding.
        encoded_value_9_byte_lower_bound, 9, 0x0000_0001_0000_0000, [0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        encoded_value_9_byte_endianness, 9, 0x0123_4567_89AB_CDEF, [0xFF, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
        encoded_value_9_byte_upper_bound, 9, u64::MAX, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    }

    macro_rules! check_decode {
        ($($test_name:ident, $size:expr, $want:expr, $encoded:expr);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    let mut slice = $encoded.as_slice();
                    let got = decode_unchecked(&mut slice);
                    assert_eq!(got, $want);
                    assert_eq!(slice.len(), $encoded.len() - $size);
                }
            )*
        }
    }

    check_decode! {
        // 3 byte encoding.
        decode_from_3_byte_slice_lower_bound, 3, 0xFD, [0xFD, 0xFD, 0x00];
        decode_from_3_byte_slice_endianness, 3, 0xABCD, [0xFD, 0xCD, 0xAB];
        decode_from_3_byte_slice_upper_bound, 3, 0xFFFF, [0xFD, 0xFF, 0xFF];
        // 5 byte encoding.
        decode_from_5_byte_slice_lower_bound, 5, 0x0001_0000, [0xFE, 0x00, 0x00, 0x01, 0x00];
        decode_from_5_byte_slice_endianness, 5, 0x0123_4567, [0xFE, 0x67, 0x45, 0x23, 0x01];
        decode_from_5_byte_slice_upper_bound, 5, 0xFFFF_FFFF, [0xFE, 0xFF, 0xFF, 0xFF, 0xFF];
        // 9 byte encoding.
        decode_from_9_byte_slice_lower_bound, 9, 0x0000_0001_0000_0000, [0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        decode_from_9_byte_slice_endianness, 9, 0x0123_4567_89AB_CDEF, [0xFF, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
        decode_from_9_byte_slice_upper_bound, 9, u64::MAX, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

        // Check slices that are bigger than the actual encoding.
        decode_1_byte_from_bigger_slice, 1, 32, [0x20, 0xAB, 0xBC];
        decode_3_byte_from_bigger_slice, 3, 0xFFFF, [0xFD, 0xFF, 0xFF, 0xAB, 0xBC];
        decode_5_byte_from_bigger_slice, 5, 0xFFFF_FFFF, [0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xAB, 0xBC];
        decode_9_byte_from_bigger_slice, 9, u64::MAX, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xAB, 0xBC];
    }

    #[test]
    #[should_panic]
    fn decode_from_empty_slice_panics() {
        let mut slice = [].as_slice();
        let _ = decode_unchecked(&mut slice);
    }

    #[test]
    #[should_panic]
    // Non-minimal is referred to as non-canonical in Core (`bitcoin/src/serialize.h`).
    fn decode_non_minimal_panics() {
        let mut slice = [0xFE, 0xCD, 0xAB].as_slice();
        let _ = decode_unchecked(&mut slice);
    }
}
