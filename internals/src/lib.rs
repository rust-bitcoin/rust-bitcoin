// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin Internal
//!
//! This crate is only meant to be used internally by crates in the
//! [rust-bitcoin](https://github.com/rust-bitcoin) ecosystem.

#![no_std]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Coding conventions.
#![warn(missing_docs)]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::needless_borrows_for_generic_args)] // https://github.com/rust-lang/rust-clippy/issues/12454

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "test-serde")]
pub extern crate serde_json;

#[cfg(feature = "test-serde")]
pub extern crate bincode;

pub mod array_vec;
pub mod const_tools;
pub mod error;
pub mod macros;
mod parse;
#[cfg(feature = "serde")]
#[macro_use]
pub mod serde;

/// Reads a `usize` from an iterator of bytes.
// TODO: Where should this live?
pub fn read_uint_iter(
    data: &mut core::slice::Iter<'_, u8>,
    size: usize,
) -> Result<usize, UintError> {
    if data.len() < size {
        Err(UintError::EarlyEndOfScript)
    } else if size > usize::from(u16::MAX / 8) {
        // Casting to u32 would overflow
        Err(UintError::NumericOverflow) // FIXME: Add another error variant for here?
    } else {
        let mut ret = 0;
        for (i, item) in data.take(size).enumerate() {
            ret = usize::from(*item)
                // Casting is safe because we checked above to not repeat the same check in a loop
                .checked_shl((i * 8) as u32)
                .ok_or(UintError::NumericOverflow)? // FIXME: This is related to `size` not overflow.
                .checked_add(ret)
                // FIXME: Isn't this unreachable because we are adding a byte at a time?
                .ok_or(UintError::NumericOverflow)?;
        }
        Ok(ret)
    }
}

/// Error returned by `read_uint_iter`.
pub enum UintError {
    /// FIXME: This name does not make sense anymore.
    EarlyEndOfScript,
    /// Input data caused `usize` to overflow.
    NumericOverflow,
}

crate::impl_from_infallible!(UintError);
