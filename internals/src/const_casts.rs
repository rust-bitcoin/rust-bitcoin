//! Const-compatible integer casting functions.
//!
//! This module provides explicit, const-compatible functions for integer type conversions
//! that would normally be done using the [`Into`] trait. Since trait methods cannot be used
//! in `const` contexts, these functions serve as alternatives that make conversion intent
//! clear while maintaining compile-time evaluation capabilities.

/// Converts `u16` to `u64`
#[must_use]
pub const fn u16_to_u64(value: u16) -> u64 { value as u64 }

/// Converts `u32` to `u64`
#[must_use]
pub const fn u32_to_u64(value: u32) -> u64 { value as u64 }

/// Converts `u64` to `u128`
#[must_use]
pub const fn u64_to_u128(value: u64) -> u128 { value as u128 }

/// Converts `i16` to `i64`
#[must_use]
pub const fn i16_to_i64(value: i16) -> i64 { value as i64 }

/// Converts `u16` to `u32`
#[must_use]
pub const fn u16_to_u32(value: u16) -> u32 { value as u32 }

#[cfg(test)]
mod tests {
    use super::u64_to_u128;

    #[test]
    fn u64_to_u128_conversion() {
        assert_eq!(u64_to_u128(0), 0);
        assert_eq!(u64_to_u128(u64::MAX), u128::from(u64::MAX));
    }
}
