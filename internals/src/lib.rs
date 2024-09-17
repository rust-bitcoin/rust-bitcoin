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
#![doc(test(attr(warn(unused))))]
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

// The pub module is a workaround for strange error:
// "macro-expanded `macro_export` macros from the current crate cannot be referred to by absolute paths"
#[doc(hidden)]
pub mod rust_version {
    include!(concat!(env!("OUT_DIR"), "/rust_version.rs"));
}

pub mod array_vec;
pub mod compact_size;
pub mod const_tools;
pub mod error;
pub mod macros;
mod parse;
pub mod script;
#[cfg(feature = "serde")]
#[macro_use]
pub mod serde;

/// A conversion trait for unsigned integer types smaller than or equal to 64-bits.
///
/// This trait exists because [`usize`] doesn't implement `Into<u64>`. We only support 32 and 64 bit
/// architectures because of consensus code so we can infallibly do the conversion.
pub trait ToU64 {
    /// Converts unsigned integer type to a [`u64`].
    fn to_u64(self) -> u64;
}

macro_rules! impl_to_u64 {
    ($($ty:ident),*) => {
        $(
            impl ToU64 for $ty { fn to_u64(self) -> u64 { self.into() } }
        )*
    }
}
impl_to_u64!(u8, u16, u32, u64);

impl ToU64 for usize {
    fn to_u64(self) -> u64 {
        crate::const_assert!(
            core::mem::size_of::<usize>() <= 8;
            "platforms that have usize larger than 64 bits are not supported"
        );
        self as u64
    }
}
