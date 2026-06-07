// SPDX-License-Identifier: CC0-1.0

//! Hex encoding utilities.
//!
//! Various types in primitives need to be rendered in hexadecimal.
//! Since `consensus_encoding` only provides a method using `alloc`
//! to do this, this module provides utilities for alloc-less encoding
//! of `Encodable` types within the primitives crate.

use core::fmt;
use core::fmt::Write as _;

use encoding::{Encode, EncoderByteIter};
use hex::{BytesToHexIter, Case};

/// Hex encoding wrapper type for `Encode` types.
///
/// Implements `Display`, `Debug`, `LowerHex`, and `UpperHex`.
pub(crate) struct HexPrimitive<'a, T>(pub(crate) &'a T);

impl<T: Encode> HexPrimitive<'_, T> {
    /// Writes an encodable object to the given formatter in the requested case.
    #[inline]
    fn fmt_hex(&self, f: &mut fmt::Formatter, case: Case) -> fmt::Result {
        // Closure to write a given pad character out a given number of times.
        let write_pad = |f: &mut fmt::Formatter, pad_len: usize| -> fmt::Result {
            for _ in 0..pad_len {
                f.write_char(f.fill())?;
            }
            Ok(())
        };

        // Count hex chars
        let len = EncoderByteIter::new(self.0.encoder()).count() * 2;
        let iter = BytesToHexIter::new(EncoderByteIter::new(self.0.encoder()), case);

        let extra_len = if f.alternate() { 2 } else { 0 };
        let total_len = len + extra_len;

        // We pad for width, and truncate for precision, but not vice-versa
        let pad_width = f.width().unwrap_or(total_len);
        let trunc_width = f.precision().map_or(len, |v| v.saturating_sub(extra_len));

        let pad_diff = pad_width.saturating_sub(total_len);

        // Left padding
        let left_pad = match f.align() {
            Some(fmt::Alignment::Left) => 0,
            Some(fmt::Alignment::Center) => pad_diff / 2,
            Some(fmt::Alignment::Right) => pad_diff,
            None => 0,
        };
        write_pad(f, left_pad)?;

        // Alt characters
        if f.alternate() {
            f.write_str(match case {
                hex::Case::Lower => "0x",
                hex::Case::Upper => "0X",
            })?;
        }

        // Hex data
        let mut remaining = trunc_width;
        for chars in iter {
            if remaining == 0 {
                break;
            }
            f.write_char(chars[0].into())?;
            remaining -= 1;

            if remaining == 0 {
                break;
            }
            f.write_char(chars[1].into())?;
            remaining -= 1;
        }

        // Right padding
        write_pad(f, pad_diff.saturating_sub(left_pad))?;

        Ok(())
    }
}

impl<T: Encode> fmt::Display for HexPrimitive<'_, T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl<T: Encode> fmt::Debug for HexPrimitive<'_, T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl<T: Encode> fmt::LowerHex for HexPrimitive<'_, T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { self.fmt_hex(f, Case::Lower) }
}

impl<T: Encode> fmt::UpperHex for HexPrimitive<'_, T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { self.fmt_hex(f, Case::Upper) }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::format;

    #[cfg(feature = "alloc")]
    use super::*;
    #[cfg(feature = "alloc")]
    use crate::block;

    #[test]
    #[cfg(feature = "alloc")]
    fn hex_primitive_debug() {
        let header: block::Header =
            encoding::decode_from_slice(&[0u8; block::Header::SIZE]).expect("valid header");
        let hex = HexPrimitive(&header);

        assert!(!format!("{hex:?}").is_empty());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn hex_primitive_upper_hex_with_alternate_prefix() {
        let header: block::Header =
            encoding::decode_from_slice(&[0u8; block::Header::SIZE]).expect("valid header");

        assert!(format!("{:#X}", HexPrimitive(&header)).starts_with("0X"));
    }
}
