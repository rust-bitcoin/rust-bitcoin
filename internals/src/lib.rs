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

// We only support 32 and 64 bit machines.
//
// - We can't guarantee this lib works on architectures with less than 32 bit pointer width.
// - 128 bit machines don't exist yet but Rust does not implement `Into<u64>` for `usize`,
//   presumably to support 128 machines when they do exist. This makes conversion from `usize`
//   fallible which is annoying so we explicitly do not support 128 bit architectures.
#[cfg(all(not(target_pointer_width = "32"), not(target_pointer_width = "64")))]
compile_error!("bitcoin-internals currently only supports 32 and 64 bit architectures.");

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod array_vec;
pub mod const_tools;
pub mod error;
pub mod macros;
mod parse;
pub mod serde;
