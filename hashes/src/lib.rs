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
//! use bitcoin_hashes::Sha256;
//!
//! let bytes = [0u8; 5];
//! let hash_of_bytes = Sha256::hash(&bytes);
//! let hash_of_string = Sha256::hash("some string".as_bytes());
//! ```
//!
//!
//! Hashing content from a reader:
//!
//! ```rust
//! use bitcoin_hashes::Sha256;
//!
//! #[cfg(std)]
//! # fn main() -> std::io::Result<()> {
//! let mut reader: &[u8] = b"hello"; // in real code, this could be a `File` or `TcpStream`
//! let mut engine = Sha256::engine();
//! std::io::copy(&mut reader, &mut engine)?;
//! let hash = Sha256::from_engine(engine);
//! # Ok(())
//! # }
//!
//! #[cfg(not(std))]
//! # fn main() {}
//! ```
//!
//!
//! Hashing content by [`std::io::Write`] on `HashEngine`:
//!
//! ```rust
//! use bitcoin_hashes::Sha256;
//! use std::io::Write;
//!
//! #[cfg(std)]
//! # fn main() -> std::io::Result<()> {
//! let mut part1: &[u8] = b"hello";
//! let mut part2: &[u8] = b" ";
//! let mut part3: &[u8] = b"world";
//! let mut engine = Sha256::engine();
//! engine.write_all(part1)?;
//! engine.write_all(part2)?;
//! engine.write_all(part3)?;
//! let hash = Sha256::from_engine(engine);
//! # Ok(())
//! # }
//!
//! #[cfg(not(std))]
//! # fn main() {}
//! ```

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(bench, feature(test))]
// Coding conventions.
#![warn(missing_docs)]
// Instead of littering the codebase for non-fuzzing code just globally allow.
#![cfg_attr(hashes_fuzz, allow(dead_code, unused_imports))]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::needless_borrows_for_generic_args)] // https://github.com/rust-lang/rust-clippy/issues/12454

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate core;

#[cfg(feature = "bitcoin-io")]
extern crate bitcoin_io as io;

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
pub mod hkdf;
pub mod hmac;
#[cfg(feature = "bitcoin-io")]
mod impls;
pub mod ripemd160;
pub mod sha1;
pub mod sha256;
pub mod sha256d;
pub mod sha256t;
pub mod sha384;
pub mod sha512;
pub mod sha512_256;
pub mod siphash24;

use core::{convert, fmt, hash};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    hkdf::Hkdf,
    hmac::{Hmac, HmacEngine},
};

/// HASH-160: Alias for the [`hash160::Hash`] hash type.
#[doc(inline)]
pub use hash160::Hash as Hash160;
/// RIPEMD-160: Alias for the [`ripemd160::Hash`] hash type.
#[doc(inline)]
pub use ripemd160::Hash as Ripemd160;
/// SHA-1: Alias for the [`sha1::Hash`] hash type.
#[doc(inline)]
pub use sha1::Hash as Sha1;
/// SHA-256: Alias for the [`sha256::Hash`] hash type.
#[doc(inline)]
pub use sha256::Hash as Sha256;
/// Double SHA-256: Alias for the [`sha256d::Hash`] hash type.
#[doc(inline)]
pub use sha256d::Hash as Sha256d;
/// SHA-384: Alias for the [`sha384::Hash`] hash type.
#[doc(inline)]
pub use sha384::Hash as Sha384;
/// SHA-512: Alias for the [`sha512::Hash`] hash type.
#[doc(inline)]
pub use sha512::Hash as Sha512;
/// SHA-512-256: Alias for the [`sha512_256::Hash`] hash type.
#[doc(inline)]
pub use sha512_256::Hash as Sha512_256;
/// SipHash-2-4: Alias for the [`siphash24::Hash`] hash type.
#[doc(inline)]
pub use siphash24::Hash as Siphash24;

/// Tagged SHA-256: Type alias for the [`sha256t::Hash`] hash type.
pub type Sha256t<T> = sha256t::Hash<T>;

/// HMAC-SHA-256: Type alias for the [`Hmac<Sha256>`] type.
pub type HmacSha256 = Hmac<sha256::Hash>;

/// HMAC-SHA-512: Type alias for the [`Hmac<Sha512>`] type.
pub type HmacSha512 = Hmac<sha512::Hash>;

/// HKDF-HMAC-SHA-256: Type alias for the [`Hkdf<Sha256>`] type.
pub type HkdfSha256 = Hkdf<sha256::Hash>;

/// HKDF-HMAC-SHA-512: Type alias for the [`Hkdf<Sha512>`] type.
pub type HkdfSha512 = Hkdf<sha512::Hash>;

/// A hashing engine which bytes can be serialized into.
pub trait HashEngine: Clone {
    /// Length of the hash's internal block size, in bytes.
    const BLOCK_SIZE: usize;

    /// Add data to the hash engine.
    fn input(&mut self, data: &[u8]);

    /// Return the number of bytes already n_bytes_hashed(inputted).
    fn n_bytes_hashed(&self) -> usize;
}

/// Trait describing hash digests which can be constructed by hashing arbitrary data.
///
/// Some methods have been bound to engines which implement Default, which is
/// generally an unkeyed hash function.
pub trait GeneralHash: Hash {
    /// A hashing engine which bytes can be serialized into. It is expected
    /// to implement the `io::Write` trait, and to never return errors under
    /// any conditions.
    type Engine: HashEngine;

    /// Constructs a new engine.
    fn engine() -> Self::Engine
    where
        Self::Engine: Default,
    {
        Self::Engine::default()
    }

    /// Produces a hash from the current state of a given engine.
    fn from_engine(e: Self::Engine) -> Self;

    /// Hashes some bytes.
    fn hash(data: &[u8]) -> Self
    where
        Self::Engine: Default,
    {
        let mut engine = Self::engine();
        engine.input(data);
        Self::from_engine(engine)
    }

    /// Hashes all the byte slices retrieved from the iterator together.
    fn hash_byte_chunks<B, I>(byte_slices: I) -> Self
    where
        B: AsRef<[u8]>,
        I: IntoIterator<Item = B>,
        Self::Engine: Default,
    {
        let mut engine = Self::engine();
        for slice in byte_slices {
            engine.input(slice.as_ref());
        }
        Self::from_engine(engine)
    }

    /// Hashes the entire contents of the `reader`.
    #[cfg(feature = "bitcoin-io")]
    fn hash_reader<R: io::BufRead>(reader: &mut R) -> Result<Self, io::Error>
    where
        Self::Engine: Default,
    {
        let mut engine = Self::engine();
        loop {
            let bytes = reader.fill_buf()?;

            let read = bytes.len();
            // Empty slice means EOF.
            if read == 0 {
                break;
            }

            engine.input(bytes);
            reader.consume(read);
        }
        Ok(Self::from_engine(engine))
    }
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
    + convert::AsRef<[u8]>
{
    /// The byte array that represents the hash internally.
    type Bytes: hex::FromHex + Copy;

    /// Length of the hash, in bytes.
    const LEN: usize;

    /// Copies a byte slice into a hash object.
    fn from_slice(sl: &[u8]) -> Result<Self, FromSliceError>;

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
}

/// Attempted to create a hash from an invalid length slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromSliceError {
    expected: usize,
    got: usize,
}

impl FromSliceError {
    /// Returns the expected slice length.
    pub fn expected_length(&self) -> usize { self.expected }

    /// Returns the invalid slice length.
    pub fn invalid_length(&self) -> usize { self.got }
}

impl fmt::Display for FromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid slice length {} (expected {})", self.got, self.expected)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromSliceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256d;

    hash_newtype! {
        /// A test newtype
        struct TestNewtype(sha256d::Hash);

        /// A test newtype
        struct TestNewtype2(sha256d::Hash);
    }

    #[rustfmt::skip]
    const DUMMY: TestNewtype = TestNewtype::from_byte_array([
        0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
        0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a,
        0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b,
        0x15, 0x26, 0x37, 0x48, 0x59, 0x6a, 0x7b, 0x8c,
    ]);

    #[test]
    fn newtype_fmt_roundtrip() {
        let orig = DUMMY;
        let hex = format!("{}", orig);
        let rinsed = hex.parse::<TestNewtype>().expect("failed to parse hex");
        assert_eq!(rinsed, orig)
    }

    #[test]
    #[cfg(feature = "bitcoin-io")]
    fn hash_reader() {
        use crate::sha256;

        let mut reader: &[u8] = b"hello";
        assert_eq!(sha256::Hash::hash_reader(&mut reader).unwrap(), sha256::Hash::hash(b"hello"),)
    }
}
