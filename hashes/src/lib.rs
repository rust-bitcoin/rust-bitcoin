// SPDX-License-Identifier: CC0-1.0

//! Rust hashes library.
//!
//! This is a simple, no-dependency library which implements the hash functions
//! needed by Bitcoin. These are SHA256, SHA256d, and RIPEMD160. As an ancillary
//! thing, it exposes hexadecimal serialization and deserialization, since these
//! are needed to display hashes anway.
//!
//! ## Commonly used operations
//!
//! Hashing a single byte slice or a string:
//!
//! ```rust
//! use bitcoin_hashes::sha256;
//! use bitcoin_hashes::Hash;
//!
//! let bytes = [0u8; 5];
//! let hash_of_bytes = sha256::Hash::hash(&bytes);
//! let hash_of_string = sha256::Hash::hash("some string".as_bytes());
//! ```
//!
//!
//! Hashing content from a reader:
//!
//! ```rust
//! use bitcoin_hashes::sha256;
//! use bitcoin_hashes::Hash;
//!
//! #[cfg(std)]
//! # fn main() -> std::io::Result<()> {
//! let mut reader: &[u8] = b"hello"; // in real code, this could be a `File` or `TcpStream`
//! let mut engine = sha256::HashEngine::default();
//! std::io::copy(&mut reader, &mut engine)?;
//! let hash = sha256::Hash::from_engine(engine);
//! # Ok(())
//! # }
//!
//! #[cfg(not(std))]
//! # fn main() {}
//! ```
//!
//!
//! Hashing content by [`std::io::Write`] on HashEngine:
//!
//! ```rust
//! use bitcoin_hashes::sha256;
//! use bitcoin_hashes::Hash;
//! use std::io::Write;
//!
//! #[cfg(std)]
//! # fn main() -> std::io::Result<()> {
//! let mut part1: &[u8] = b"hello";
//! let mut part2: &[u8] = b" ";
//! let mut part3: &[u8] = b"world";
//! let mut engine = sha256::HashEngine::default();
//! engine.write_all(part1)?;
//! engine.write_all(part2)?;
//! engine.write_all(part3)?;
//! let hash = sha256::Hash::from_engine(engine);
//! # Ok(())
//! # }
//!
//! #[cfg(not(std))]
//! # fn main() {}
//! ```

// Coding conventions
#![warn(missing_docs)]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(bench, feature(test))]
// In general, rust is absolutely horrid at supporting users doing things like,
// for example, compiling Rust code for real environments. Disable useless lints
// that don't do anything but annoy us and cant actually ever be resolved.
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]
#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
// Instead of littering the codebase for non-fuzzing code just globally allow.
#![cfg_attr(hashes_fuzz, allow(dead_code, unused_imports))]

#[cfg(all(not(test), not(feature = "std"), feature = "core2"))]
extern crate actual_core2 as core2;
#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate core;

#[cfg(feature = "serde")]
/// A generic serialization/deserialization framework.
pub extern crate serde;

#[cfg(all(test, feature = "serde"))]
extern crate serde_test;
#[cfg(bench)]
extern crate test;

/// Re-export the `hex-conservative` crate.
pub extern crate hex;

#[doc(hidden)]
pub mod _export {
    /// A re-export of core::*
    pub mod _core {
        pub use core::*;
    }
}

#[cfg(feature = "schemars")]
extern crate schemars;

mod internal_macros;
#[macro_use]
mod util;
#[macro_use]
pub mod serde_macros;
pub mod cmp;
pub mod hash160;
pub mod hmac;
#[cfg(any(test, feature = "std", feature = "core2"))]
mod impls;
pub mod ripemd160;
pub mod sha1;
pub mod sha256;
pub mod sha256d;
pub mod sha256t;
pub mod sha512;
pub mod sha512_256;
pub mod siphash24;

use core::{borrow, fmt, hash, ops};
// You get I/O if you enable "std" or "core2" (as well as during testing).
#[cfg(any(test, feature = "std"))]
use std::io;

#[cfg(all(not(test), not(feature = "std"), feature = "core2"))]
use core2::io;
pub use hmac::{Hmac, HmacEngine};

/// A hashing engine which bytes can be serialized into.
pub trait HashEngine: Clone + Default {
    /// Byte array representing the internal state of the hash engine.
    type MidState;

    /// Outputs the midstate of the hash engine. This function should not be
    /// used directly unless you really know what you're doing.
    fn midstate(&self) -> Self::MidState;

    /// Length of the hash's internal block size, in bytes.
    const BLOCK_SIZE: usize;

    /// Add data to the hash engine.
    fn input(&mut self, data: &[u8]);

    /// Return the number of bytes already n_bytes_hashed(inputted).
    fn n_bytes_hashed(&self) -> usize;
}

/// Trait which applies to hashes of all types.
pub trait Hash:
    Copy
    + Clone
    + PartialEq
    + Eq
    + PartialOrd
    + Ord
    + hash::Hash
    + fmt::Debug
    + fmt::Display
    + fmt::LowerHex
    + ops::Index<ops::RangeFull, Output = [u8]>
    + ops::Index<ops::RangeFrom<usize>, Output = [u8]>
    + ops::Index<ops::RangeTo<usize>, Output = [u8]>
    + ops::Index<ops::Range<usize>, Output = [u8]>
    + ops::Index<usize, Output = u8>
    + borrow::Borrow<[u8]>
{
    /// A hashing engine which bytes can be serialized into. It is expected
    /// to implement the `io::Write` trait, and to never return errors under
    /// any conditions.
    type Engine: HashEngine;

    /// The byte array that represents the hash internally.
    type Bytes: hex::FromHex + Copy;

    /// Constructs a new engine.
    fn engine() -> Self::Engine { Self::Engine::default() }

    /// Produces a hash from the current state of a given engine.
    fn from_engine(e: Self::Engine) -> Self;

    /// Length of the hash, in bytes.
    const LEN: usize;

    /// Copies a byte slice into a hash object.
    fn from_slice(sl: &[u8]) -> Result<Self, FromSliceError>;

    /// Hashes some bytes.
    fn hash(data: &[u8]) -> Self {
        let mut engine = Self::engine();
        engine.input(data);
        Self::from_engine(engine)
    }

    /// Flag indicating whether user-visible serializations of this hash
    /// should be backward. For some reason Satoshi decided this should be
    /// true for `Sha256dHash`, so here we are.
    const DISPLAY_BACKWARD: bool = false;

    /// Returns the underlying byte array.
    fn to_byte_array(self) -> Self::Bytes;

    /// Returns a reference to the underlying byte array.
    fn as_byte_array(&self) -> &Self::Bytes;

    /// Constructs a hash from the underlying byte array.
    fn from_byte_array(bytes: Self::Bytes) -> Self;

    /// Returns an all zero hash.
    ///
    /// An all zeros hash is a made up construct because there is not a known input that can create
    /// it, however it is used in various places in Bitcoin e.g., the Bitcoin genesis block's
    /// previous blockhash and the coinbase transaction's outpoint txid.
    fn all_zeros() -> Self;
}

/// Attempted to create a hash from an invalid length slice.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FromSliceError {
    expected: usize,
    got: usize,
}

impl fmt::Display for FromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid slice length {} (expected {})", self.got, self.expected)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

#[cfg(test)]
mod tests {
    use crate::{sha256d, Hash};

    hash_newtype! {
        /// A test newtype
        struct TestNewtype(sha256d::Hash);

        /// A test newtype
        struct TestNewtype2(sha256d::Hash);
    }

    #[test]
    fn convert_newtypes() {
        let h1 = TestNewtype::hash(&[]);
        let h2: TestNewtype2 = h1.to_raw_hash().into();
        assert_eq!(&h1[..], &h2[..]);

        let h = sha256d::Hash::hash(&[]);
        let h2: TestNewtype = h.to_string().parse().unwrap();
        assert_eq!(h2.to_raw_hash(), h);
    }
}
