// SPDX-License-Identifier: CC0-1.0

//! Variable length integer encoding A.K.A [`CompactSize`].
//!
//! An integer can be encoded depending on the represented value to save space. Variable length
//! integers always precede an array/vector of a type of data that may vary in length.
//!
//! [`CompactSize`]: <https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer>

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
    assert!(!slice.is_empty(), "tried to decode an empty slice");

    match slice[0] {
        0xFF => {
            const SIZE: usize = 9;
            assert!(slice.len() >= SIZE, "slice too short, expected at least 9 bytes");

            let mut bytes = [0_u8; SIZE - 1];
            bytes.copy_from_slice(&slice[1..SIZE]);

            let v = u64::from_le_bytes(bytes);
            debug_assert!(v > u32::MAX.into(), "non-minimal encoding of a u64");
            *slice = &slice[SIZE..];
            v
        }
        0xFE => {
            const SIZE: usize = 5;
            assert!(slice.len() >= SIZE, "slice too short, expected at least 5 bytes");

            let mut bytes = [0_u8; SIZE - 1];
            bytes.copy_from_slice(&slice[1..SIZE]);

            let v = u32::from_le_bytes(bytes);
            debug_assert!(v > u16::MAX.into(), "non-minimal encoding of a u32");
            *slice = &slice[SIZE..];
            u64::from(v)
        }
        0xFD => {
            const SIZE: usize = 3;
            assert!(slice.len() >= SIZE, "slice too short, expected at least 3 bytes");

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
        decode_from_3_byte_slice_three_over_lower_bound, 3, 0x0100, [0xFD, 0x00, 0x01];
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
    #[should_panic(expected = "tried to decode an empty slice")]
    fn decode_from_empty_slice_panics() {
        let mut slice = [].as_slice();
        let _ = decode_unchecked(&mut slice);
    }

    #[test]
    #[should_panic(expected = "slice too short")]
    // Non-minimal is referred to as non-canonical in Core (`bitcoin/src/serialize.h`).
    fn decode_non_minimal_panics() {
        let mut slice = [0xFE, 0xCD, 0xAB].as_slice();
        let _ = decode_unchecked(&mut slice);
    }
}
