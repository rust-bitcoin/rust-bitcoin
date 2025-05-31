// SPDX-License-Identifier: CC0-1.0

//! Const Integer Casts
//!
//! This module provides const-compatible functions for infallible integer type conversions.
//! These functions are meant to replace direct `as` casts in const contexts,
//! making the code more readable and easier to reason about.
//!
//! ## Motivation
//!
//! When writing code that needs to work in `const` contexts, we cannot use the
//! standard `Into`/`From` traits as they are not const-compatible. Using direct
//! `as` casts makes the code harder to reason about and can lead to confusion.
//!
//! A key benefit of these functions is their infallibility - one doesn't need to
//! worry about corrupting data when reading or writing code. The function names
//! clearly indicate which conversions are guaranteed to be safe.
//!
//! This module provides a set of explicitly named functions that make the intent
//! clear while maintaining const-compatibility.
//!
//! ## Usage
//!
//! Instead of writing:
//! ```ignore
//! let x: usize = some_u8 as usize;
//! ```
//!
//! Write:
//! ```ignore
//! let x: usize = crate::const_casts::u8_to_usize(some_u8);
//! ```

/// Converts u8 to usize.
#[inline]
pub const fn u8_to_usize(v: u8) -> usize {
    v as usize
}

/// Converts u8 to u16.
#[inline]
pub const fn u8_to_u16(v: u8) -> u16 {
    v as u16
}

/// Converts u8 to u32.
#[inline]
pub const fn u8_to_u32(v: u8) -> u32 {
    v as u32
}

/// Converts u8 to u64.
#[inline]
pub const fn u8_to_u64(v: u8) -> u64 {
    v as u64
}

/// Converts u16 to usize.
#[inline]
pub const fn u16_to_usize(v: u16) -> usize {
    v as usize
}

/// Converts u16 to u32.
#[inline]
pub const fn u16_to_u32(v: u16) -> u32 {
    v as u32
}

/// Converts u16 to u64.
#[inline]
pub const fn u16_to_u64(v: u16) -> u64 {
    v as u64
}

/// Converts u32 to u64.
#[inline]
pub const fn u32_to_u64(v: u32) -> u64 {
    v as u64
}


/// Converts usize to u64.
///
/// This function is safe on all practical platforms (16, 32, and 64 bit).
/// It would only be fallible on platforms with usize larger than 64 bits,
/// but no such platforms exist in practice.
#[inline]
pub const fn usize_to_u64(v: usize) -> u64 {
    v as u64
}


