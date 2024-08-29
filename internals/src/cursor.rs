// SPDX-License-Identifier: CC0-1.0

//! Private functions used in `witness` modules.

/// Encodes `value` into the `Witness::content` (`bytes`).
///
/// Correctness Requirements: value must always fit within u32
#[inline]
pub fn encode(bytes: &mut [u8], start_of_indices: usize, index: usize, value: usize) {
    let start = start_of_indices + index * 4;
    let end = start + 4;
    bytes[start..end]
        .copy_from_slice(&u32::to_ne_bytes(value.try_into().expect("larger than u32")));
}

/// Decodes a value from the `Witness::content` (`bytes`).
#[inline]
pub fn decode(bytes: &[u8], start_of_indices: usize, index: usize) -> Option<usize> {
    let start = start_of_indices + index * 4;
    let end = start + 4;
    if end > bytes.len() {
        None
    } else {
        Some(u32::from_ne_bytes(bytes[start..end].try_into().expect("is u32 size")) as usize)
    }
}
