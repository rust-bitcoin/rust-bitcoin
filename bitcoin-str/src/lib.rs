// Rust Bitcoin Stringly Encodings - Written by the rust-bitcoin developers.
// SPDX-License-Identifier: CC0-1.0

//! Stringly encodings used by the Bitcoin network.
//!

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

// Experimental features we need.
#![cfg_attr(bench, feature(test))]
#![cfg_attr(docsrs, feature(doc_cfg))]

// Coding conventions
#![forbid(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]
#![deny(unused_must_use)]

// Disable 16-bit support at least for now as we can't guarantee it yet.
#[cfg(target_pointer_width = "16")]
compile_error!(
    "rust-bitcoin currently only supports architectures with pointers wider than 16 bits, let us
    know if you want 16-bit support. Note that we do NOT guarantee that we will implement it!"
);

#[cfg(bench)]
extern crate test;

#[cfg(feature = "alloc")]
extern crate alloc;

/// Re-export of the [`bech32`] crate.
/// [`bech32`]: <https://docs.rs/bech32/latest/bech32/>
#[cfg(feature = "bech32")]
pub use bech32;

/// Re-export of the [`base64`] crate.
/// [`base64`]: <https://docs.rs/base64/latest/base64/>
#[cfg(feature = "base64")]
pub use base64;

// Only warn for std builds, if devs are doing no-std builds they probably know what they are doing.
#[cfg(all(feature = "std", feature = "bech32", not(feature = "bech32-std")))]
compile_error!("If you enable \"std\" and want \"bech32\" you should enable \"bech32-std\"");
#[cfg(all(feature = "std", feature = "base64", not(feature = "base64-std")))]
compile_error!("If you enable \"std\" and want \"base64\" you should enable \"base64-std\"");

#[rustfmt::skip]
mod prelude {
    #[cfg(all(feature = "alloc", not(feature = "std"), not(test)))]
    pub use alloc::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Cow, ToOwned}, slice, rc, sync};

    #[cfg(any(feature = "std", test))]
    pub use std::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Cow, ToOwned}, slice, rc, sync};

    #[cfg(all(feature = "alloc", not(feature = "std"), not(test)))]
    pub use alloc::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(any(feature = "std", test))]
    pub use std::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};
}

pub mod hex;
