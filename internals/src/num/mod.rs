//! Helpers for integers

/// re-usable unsigned_abs()
pub fn unsigned_abs(x: i8) -> u8 {
    x.wrapping_abs() as u8
}
