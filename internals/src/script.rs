// SPDX-License-Identifier: CC0-1.0

//! Internal script related helper functions and types.

#[cfg(creusot)]
use creusot_std::prelude::*;
#[cfg(creusot)]
use creusot_std::prelude::{Clone, PartialEq};

/// Reads a `usize` from an iterator.
///
/// A script push data instruction includes the length of the data being pushed, this function reads
/// that length from an iterator (encoded in either 1, 2, or 4 bytes).
///
/// # Errors
///
/// Returns an error if the iterator does not contain enough bytes to read the length.
// We internally use implementation based on iterator so that it automatically advances as needed.
pub fn read_push_data_len(
    data: &mut core::slice::Iter<'_, u8>,
    size: PushDataLenLen,
) -> Result<u32, EarlyEndOfScriptError> {
    // The `size` enum enforces that the maximum shift will be 32 and
    // that we can only ever read up to 4 bytes.
    let size = size.to_usize();

    if data.len() < size {
        return Err(EarlyEndOfScriptError);
    }

    let mut ret = 0;
    let mut i = 0u32;
    #[cfg_attr(creusot, invariant(i@ == produced.len()))]
    #[cfg_attr(creusot, variant(size@ - produced.len()))]
    // Creusot has trouble proving take().enumerate() is correct, looks like a bug there
    #[allow(clippy::explicit_counter_loop)]
    for item in data.take(size) {
        ret |= u32::from(*item) << (i * 8);
        i += 1;
    }
    Ok(ret)
}

/// The number of bytes used to encode an unsigned integer as the length of a push data instruction.
///
/// This makes it easier to prove correctness of `next_push_data_len` and `read_push_data_len`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(not(creusot), derive(Hash))]
pub enum PushDataLenLen {
    /// Unsigned integer comprising of a single byte.
    One = 1,
    /// Unsigned integer comprising of two bytes.
    Two = 2,
    /// Unsigned integer comprising of four bytes.
    Four = 4,
}

impl PushDataLenLen {
    #[cfg_attr(creusot, ensures(result@ == self@))]
    fn to_usize(self) -> usize {
        // It seems Creusot doesn't translate casts properly
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
        }
    }
}

impl Ord for PushDataLenLen {
    #[cfg_attr(creusot, ensures(result == (*self).deep_model().cmp_log((*other).deep_model())))]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.to_usize().cmp(&other.to_usize())
    }
}

impl PartialOrd for PushDataLenLen {
    #[cfg_attr(creusot, ensures(result == (*self).deep_model().partial_cmp_log((*other).deep_model())))]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(creusot)]
impl View for PushDataLenLen {
    type ViewTy = Int;

    #[logic(open, inline)]
    fn view(self) -> Self::ViewTy {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
        }
    }
}

#[cfg(creusot)]
impl DeepModel for PushDataLenLen {
    type DeepModelTy = Int;

    #[logic(open, inline)]
    fn deep_model(self) -> Self::DeepModelTy {
        self.view()
    }
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
        assert_eq!(got, want);
    }

    #[test]
    fn reads_2_bytes() {
        let bytes = [0x01, 0x23];
        let want = u16::from_le_bytes([0x01, 0x23]);
        let got = read_push_data_len(&mut bytes.iter(), PushDataLenLen::Two).unwrap();
        assert_eq!(got, u32::from(want));
    }

    #[test]
    fn reads_1_byte() {
        let bytes = [0x01];
        let want = 0x01u32;
        let got = read_push_data_len(&mut bytes.iter(), PushDataLenLen::One).unwrap();
        assert_eq!(got, want);
    }
}
