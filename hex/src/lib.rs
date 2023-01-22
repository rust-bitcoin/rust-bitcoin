// Hexadecimal Library - Written by the rust-bitcoin developers.
// SPDX-License-Identifier: CC0-1.0

//! This is a hex library designed to be fast.
//!
//! ## Basic Usage
//! ```
//! # #[cfg(feature = "alloc")]
//! # {
//! // Use the `package` key to improve import ergonomics (`hex` instead of `bitcoin-hex`).
//! // hex = { package = "bitcoin-hex", version = "*" }
//! # use bitcoin_hex as hex; // No need for this if using `package` as above.
//! use hex::{DisplayHex, FromHex};
//!
//! // Decode an arbitrary length hex string into a vector.
//! let v = Vec::from_hex("deadbeef").expect("valid hex digits");
//! // Or a known length hex string into a fixed size array.
//! let a = <[u8; 4]>::from_hex("deadbeef").expect("valid length and valid hex digits");
//! // We support `LowerHex` and `UpperHex` out of the box for `[u8]` slices.
//! println!("An array as lower hex: {:x}", a.as_hex());
//! // And for vecs since `Vec` derefs to byte slice.
//! println!("A vector as upper hex: {:X}", v.as_hex());
//! # }
//! ```

// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod buf_encoder;
pub mod display;
pub mod parse;

pub use display::DisplayHex;
pub use parse::{Error, FromHex};

/// Reexports of extension traits.
pub mod exts {
    pub use super::display::DisplayHex;
    pub use super::parse::FromHex;
}

/// Mainly reexports based on features.
pub(crate) mod prelude {
    #[cfg(feature = "alloc")]
    pub(crate) use alloc::string::String;
}

/// Possible case of hex.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Case {
    /// Produce lower-case chars (`[0-9a-f]`).
    ///
    /// This is the default.
    Lower,

    /// Produce upper-case chars (`[0-9A-F]`).
    Upper,
}

impl Default for Case {
    fn default() -> Self { Case::Lower }
}

impl Case {
    /// Returns the encoding table.
    ///
    /// The returned table may only contain displayable ASCII chars.
    #[inline]
    #[rustfmt::skip]
    pub(crate) fn table(self) -> &'static [u8; 16] {
        static LOWER: [u8; 16] = [b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e', b'f'];
        static UPPER: [u8; 16] = [b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E', b'F'];

        match self {
            Case::Lower => &LOWER,
            Case::Upper => &UPPER,
        }
    }
}

/// Encodes single byte as two ASCII chars using the given table.
///
/// The function guarantees only returning values from the provided table.
#[inline]
pub(crate) fn byte_to_hex(byte: u8, table: &[u8; 16]) -> [u8; 2] {
    [table[usize::from(byte.wrapping_shr(4))], table[usize::from(byte & 0x0F)]]
}
