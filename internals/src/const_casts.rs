//! Const-compatible integer casting functions.
//!
//! This module provides explicit, const-compatible functions for integer type conversions
//! that would normally be done using the [`Into`] trait. Since trait methods cannot be used
//! in `const` contexts, these functions serve as alternatives that make conversion intent
//! clear while maintaining compile-time evaluation capabilities.

/// Converts `u16` to `u64`
pub const fn u16_to_u64(value: u16) -> u64 { value as u64 }

/// Converts `u32` to `u64`
pub const fn u32_to_u64(value: u32) -> u64 { value as u64 }

/// Converts `i16` to `i64`
pub const fn i16_to_i64(value: i16) -> i64 { value as i64 }

/// Converts `u16` to `u32`
pub const fn u16_to_u32(value: u16) -> u32 { value as u32 }
