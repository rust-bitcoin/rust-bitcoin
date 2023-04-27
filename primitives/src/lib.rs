
// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin - primitive types.
//!
//! This crate provides primitive data types that are used throughout the [`rust-bitcoin`] ecosystem.
//!
//! The rules used to work out what goes in this crate are:
//!
//! - Types that don't depend on anything else from the ecosystem except `bitcoin-internals`.
//! - Types that operate only on Rust types.
//!
//! So if `rust-bitcoin` is analogous to std then `bitcoin-primitives` is analogous to core (calling
//! it core would have obviously been confusing).
//!
//! [`rust-bitcoin`]: <https://github.com/rust-bitcoin>

#![no_std]

// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

// Coding conventions.
#![warn(missing_docs)]

// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;
