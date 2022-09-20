//! Helpers for encoding bytes as hex strings.

pub mod buf_encoder;
pub mod display;

pub use buf_encoder::BufEncoder;

/// Reexports of extension traits.
pub mod exts {
    pub use super::display::DisplayHex;
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
