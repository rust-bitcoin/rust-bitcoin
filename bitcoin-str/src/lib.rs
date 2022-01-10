// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Rust Bitcoin String Encoding/Decoding.
//!
//! This library provides encoding and decoding into/from various string formats used by Bitcoin.
//!
//! - base58
//! - bech32
//! - bech32m
//! - hex
//! - base64 (optional)
//!

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

// Experimental features we need
#![cfg_attr(all(test, feature = "unstable"), feature(test))]

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
#![deny(broken_intra_doc_links)]

#[cfg(not(any(feature = "std", feature = "no-std")))]
compile_error!("at least one of the `std` or `no-std` features must be enabled");

// Disable 16-bit support at least for now as we can't guarantee it yet.
#[cfg(target_pointer_width = "16")]
compile_error!("rust-bitcoin currently only supports architectures with pointers wider
                than 16 bits, let us know if you want 16-bit support. Note that we do
                NOT guarantee that we will implement it!");

#[cfg(feature = "no-std")]
#[macro_use]
extern crate alloc;
#[cfg(feature = "no-std")]
extern crate core2;

#[cfg(any(feature = "std", test))]
extern crate core; // for Rust 1.29 and no-std tests

// Re-exported dependencies.
pub extern crate bech32;
pub extern crate bitcoin_hashes as hashes;

#[cfg(feature = "base64")]
#[cfg_attr(docsrs, doc(cfg(feature = "base64")))]
pub extern crate base64;

pub mod base58;
pub mod endian;

pub mod hex {
    //! Re-exports hex de/serialization code from `bitcoin_hashes`.
    //!
    // There is a chicken and the egg problem with putting _all_ the en/decoding code in a single crate.
    // Hashing cannot be separated totally from en/decoding because base58 -> hashing -> hex.

    pub use hashes::hex::{Error, ToHex, FromHex, HexIterator, format_hex, format_hex_reverse};
    // TODO: This doesn't work with Rust 1.29 (same problem trying to use macros from hashes in ../bitcoin)
    pub use hashes::hex_fmt_impl;
}

mod prelude {
    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Cow, ToOwned}, slice, rc, sync};

    #[cfg(any(feature = "std", test))]
    pub use std::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Cow, ToOwned}, slice, rc, sync};
}
