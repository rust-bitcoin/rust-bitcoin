// SPDX-License-Identifier: CC0-1.0

//! Variable length integer encoding A.K.A [`CompactSize`].
//!
//! An integer can be encoded depending on the represented value to save space. Variable length
//! integers always precede an array/vector of a type of data that may vary in length.
//!
//! [`CompactSize`]: <https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer>

use core::fmt;

use crate::write_err;

/// The maximum size of a serialized object in bytes or number of elements
/// (for eg vectors) when the size is encoded as CompactSize.
///
/// This is `MAX_SIZE` in Bitcoin Core.
pub const MAX_ENCODABLE_SIZE: u64 = 0x0200_0000;

/// Returns the number of bytes used to encode this `CompactSize` value.
///
/// # Returns
///
/// - 1 for 0..=0xFC
/// - 3 for 0xFD..=(2^16-1)
/// - 5 for 0x10000..=(2^32-1)
/// - 9 otherwise.
#[inline]
pub const fn encoded_size(value: u64) -> usize {
    match value {
        0..=0xFC => 1,
        0xFD..=0xFFFF => 3,
        0x10000..=0xFFFFFFFF => 5,
        _ => 9,
    }
}

/// Encodes `CompactSize` without allocating.
///
/// # Returns
///
/// An array with the encoded value in it as well as the length, in bytes, of the encoded value.
///
/// # Example
///
/// ```
/// use bitcoin_internals::compact_size;
///
/// let (encoded, size) = compact_size::encode(32);
/// // Typically you will want to grab the slice using `encoded[..size]`.
/// assert_eq!(&encoded[..size], [0x20].as_slice());
///
/// assert_eq!(size, 1);
/// assert_eq!(encoded, [0x20, 0, 0, 0, 0, 0, 0, 0, 0]);
/// ```
pub fn encode(value: u64) -> ([u8; 9], usize) {
    let mut buf = [0_u8; 9];
    let size;

    match value {
        0..=0xFC => {
            size = 1;
            buf[0] = value as u8; // Cast ok because of match.
        }
        0xFD..=0xFFFF => {
            size = 3;
            let v = value as u16; // Cast ok because of match.
            buf[0] = 0xFD;
            buf[1..size].copy_from_slice(&v.to_le_bytes());
        }
        0x10000..=0xFFFFFFFF => {
            size = 5;
            let v = value as u32; // Cast ok because of match.
            buf[0] = 0xFE;
            buf[1..size].copy_from_slice(&v.to_le_bytes());
        }
        _ => {
            size = 9;
            let v = value;
            buf[0] = 0xFF;
            buf[1..size].copy_from_slice(&v.to_le_bytes());
        }
    }
    (buf, size)
}

/// Gets the `CompactSize` encoded at the front of `slice`.
///
/// Does not modify `slice`, enforces invariant that `size < CompactSize::MAX_SIZE`.
///
/// # Returns
///
/// The `CompactSize` if one exists as well as the number of bytes used to encode it.
///
/// # Example
///
/// ```
/// use bitcoin_internals::compact_size;
///
/// // Extra bytes are ignored.
/// let (compact, _) = compact_size::decode(&[0x20, 0xAB, 0xCD]).unwrap();
/// assert_eq!(compact, 32);
/// ```
pub fn decode(slice: &[u8]) -> Result<(u64, usize), DecodeError> {
    if slice.is_empty() {
        return Err(DecodeError::Empty);
    }

    let res = match slice[0] {
        0xFF => {
            const SIZE: usize = 9;
            if slice.len() < SIZE {
                return Err(TooShortError::new(slice, SIZE).into());
            };

            let mut bytes = [0_u8; SIZE - 1];
            bytes.copy_from_slice(&slice[1..SIZE]);
            (u64::from_le_bytes(bytes), SIZE)
        }
        0xFE => {
            const SIZE: usize = 5;
            if slice.len() < SIZE {
                return Err(TooShortError::new(slice, SIZE).into());
            };

            let mut bytes = [0_u8; SIZE - 1];
            bytes.copy_from_slice(&slice[1..SIZE]);
            let v = u32::from_le_bytes(bytes);
            (u64::from(v), SIZE)
        }
        0xFD => {
            const SIZE: usize = 3;
            if slice.len() < SIZE {
                return Err(TooShortError::new(slice, SIZE).into());
            };

            let mut bytes = [0_u8; SIZE - 1];
            bytes.copy_from_slice(&slice[1..SIZE]);
            let v = u16::from_le_bytes(bytes);
            (u64::from(v), SIZE)
        }
        n => (u64::from(n), 1),
    };
    Ok(res)
}

/// Error returned when decoding a `CompactSize`.
///
/// In other words the object being serialized is too big to go over the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Tried to decode a `CompactSize` from an empty slice.
    Empty,
    /// Slice was too short to decode.
    TooShort(TooShortError),
}

crate::impl_from_infallible!(DecodeError);

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DecodeError::*;

        match *self {
            Empty => write!(f, "tried to decode a CompactSize from an empty slice"),
            TooShort(ref e) => write_err!(f, "decode"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DecodeError::*;

        match *self {
            Empty => None,
            TooShort(ref e) => Some(e),
        }
    }
}

impl From<TooShortError> for DecodeError {
    fn from(e: TooShortError) -> Self { Self::TooShort(e) }
}

/// Error returned if a slice is too short based on the initial byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TooShortError {
    initial_byte: u8,
    expected_minimum_length: usize,
    actual_length: usize,
}

impl TooShortError {
    // Caller to guarantee that slice is not empty.
    fn new(slice: &[u8], expected_minimum_length: usize) -> Self {
        TooShortError {
            initial_byte: slice[0],
            expected_minimum_length,
            actual_length: slice.len(),
        }
    }
}

crate::impl_from_infallible!(TooShortError);

impl fmt::Display for TooShortError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "tried to decode a `CompactSize` from a slice that is too short initial_byte: {}, expected_minimum_length: {}, actual_length: {}", self.initial_byte, self.expected_minimum_length, self.actual_length)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TooShortError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_value_1_byte() {
        // Check lower bound, upper bound (and implicitly endian-ness).
        for v in [0x00, 0x01, 0x02, 0xFA, 0xFB, 0xFC] {
            assert_eq!(encoded_size(v), 1);
            // Should be encoded as the value as a u8.
            let want = [v as u8];
            let (got, size) = encode(v);
            assert_eq!(size, 1); // sanity check
            assert_eq!(&got[..size], &want);
        }
    }

    #[test]
    fn decode_value_1_byte() {
        let want_size = 1;
        // Check lower bound, upper bound.
        for v in [0x00, 0x01, 0x02, 0xFA, 0xFB, 0xFC] {
            let (got, got_size) = match decode(&[v]) {
                Ok((compact, size)) => (compact, size),
                Err(e) => panic!("error {:?} on value: {}", e, v),
            };

            assert_eq!(got, u64::from(v));
            assert_eq!(got_size, want_size);
        }
    }

    macro_rules! check_encode {
        ($($test_name:ident, $size:expr, $value:expr, $want:expr);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    let (got, size) = encode($value);
                    assert_eq!(size, $size); // sanity check
                    assert_eq!(&got[..size], &$want);
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
                    let (got, size) = decode(&$encoded).unwrap();
                    assert_eq!(size, $size); // sanity check
                    assert_eq!(got, $want);
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
}
