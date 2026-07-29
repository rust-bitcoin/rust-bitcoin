// SPDX-License-Identifier: CC0-1.0

//! Rust Bitcoin Internal
//!
//! This crate is only meant to be used internally by crates in the
//! [rust-bitcoin](https://github.com/rust-bitcoin) ecosystem.

#![no_std]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]

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

#[doc(hidden)]
pub mod _export {
    #[cfg(feature = "alloc")]
    pub extern crate alloc;
}

pub mod array;
pub mod array_vec;
pub mod error;
pub mod script;
pub mod slice;
#[cfg(feature = "serde")]
#[macro_use]
pub mod serde;
pub mod const_casts;

/// Asserts a boolean expression at compile time.
#[macro_export]
macro_rules! const_assert {
    ($x:expr $(; $message:expr)?) => {
        const _: () = {
            if !$x {
                // We can't use formatting in const, only concatenating literals.
                panic!(concat!("assertion ", stringify!($x), " failed" $(, ": ", $message)?))
            }
        };
    }
}
