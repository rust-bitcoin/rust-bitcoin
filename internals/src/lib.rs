// Written by the Rust Bitcoin developers.
// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin Internal
//!
//! This crate is only meant to be used internally by crates in the
//! [rust-bitcoin](https://github.com/rust-bitcoin) ecosystem.
//!

#![no_std]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_cfg))]
// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]
#![deny(unused_must_use)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod hex;

/// Mainly reexports based on features.
pub(crate) mod prelude {
    #[cfg(feature = "alloc")]
    pub(crate) use alloc::string::String;
}
