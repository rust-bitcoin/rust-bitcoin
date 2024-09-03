// SPDX-License-Identifier: CC0-1.0

//! Internal script related helper functions and types.

/// Reads a `usize` from an iterator.
///
/// A script push data instruction includes the length of the data being pushed, this function reads
/// that length from an iterator (encoded in either 1, 2, or 4 bytes).
// We internally use implementation based on iterator so that it automatically advances as needed.
pub fn read_push_data_len(
    data: &mut core::slice::Iter<'_, u8>,
    size: PushDataLenLen,
) -> Result<usize, EarlyEndOfScriptError> {
    // The `size` enum enforces that the maximum shift will be 32 and
    // that we can only ever read up to 4 bytes.
    let size = size as usize;

    if data.len() < size {
        return Err(EarlyEndOfScriptError);
    };

    let mut ret = 0;
    for (i, item) in data.take(size).enumerate() {
        ret |= usize::from(*item) << (i * 8);
    }
    Ok(ret)
}

/// The number of bytes used to encode an unsigned integer as the length of a push data instruction.
///
/// This makes it easier to prove correctness of `next_push_data_len` and `read_push_data_len`.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PushDataLenLen {
    /// Unsigned integer comprising of a single byte.
    One = 1,
    /// Unsigned integer comprising of two bytes.
    Two = 2,
    /// Unsigned integer comprising of four bytes.
    Four = 4,
}

/// Indicates that we tried to read more bytes from the script than available.
#[derive(Debug)]
pub struct EarlyEndOfScriptError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_4_bytes() {
        let bytes = [0x01, 0x23, 0x45, 0x67];
        let want = u32::from_le_bytes([0x01, 0x23, 0x45, 0x67]);
        let got = read_push_data_len(&mut bytes.iter(), PushDataLenLen::Four).unwrap();
        assert_eq!(got, want as usize)
    }

    #[test]
    fn reads_2_bytes() {
        let bytes = [0x01, 0x23];
        let want = u16::from_le_bytes([0x01, 0x23]);
        let got = read_push_data_len(&mut bytes.iter(), PushDataLenLen::Two).unwrap();
        assert_eq!(got, want as usize)
    }

    #[test]
    fn reads_1_byte() {
        let bytes = [0x01];
        let want = 0x01;
        let got = read_push_data_len(&mut bytes.iter(), PushDataLenLen::One).unwrap();
        assert_eq!(got, want as usize)
    }
}
