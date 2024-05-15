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
//! Hashing a single byte slice or a string (use the hash type directly):
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
//! Hashing content from a reader (use the hash module and `HashEngine` trait):
//!
//! ```rust
//! use bitcoin_hashes::{sha256, HashEngine};
//!
//! # #[cfg(feature = "std")] {
//! # fn main() -> std::io::Result<()> {
//! let mut reader: &[u8] = b"hello"; // in real code, this could be a `File` or `TcpStream`
//! let mut engine = sha256::Engine::new();
//! std::io::copy(&mut reader, &mut engine)?;
//! let hash = sha256::Hash::from_engine(engine);
//! # Ok(())
//! # }}
//! ```
//!
//!
//! Hashing content by [`std::io::Write`] on an Engine:
//!
//! ```rust
//! use bitcoin_hashes::{sha256, HashEngine};
//! use std::io::Write;
//!
//! # #[cfg(feature = "std")] {
//! # fn main() -> std::io::Result<()> {
//! let mut part1: &[u8] = b"hello";
//! let mut part2: &[u8] = b" ";
//! let mut part3: &[u8] = b"world";
//! let mut engine = sha256::Engine::new();
//! engine.write_all(part1)?;
//! engine.write_all(part2)?;
//! engine.write_all(part3)?;
//! let hash = sha256::Hash::from_engine(engine);
//! # Ok(())
//! # }}
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

#[cfg(feature = "serde")]
/// A generic serialization/deserialization framework.
pub extern crate serde;

#[cfg(all(test, feature = "serde"))]
extern crate serde_test;
#[cfg(bench)]
extern crate test;

/// Re-export the `bitcoin-io` crate.
#[cfg(feature = "bitcoin-io")]
pub extern crate bitcoin_io;

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
mod macros;
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
    hmac::Hmac,
    hkdf::Hkdf,
    sha256t::Tag,
};

/// SHA-1: Type alias for the [`sha1::Hash`] hash type.
pub type Sha1 = sha1::Hash;

/// SHA-256: Type alias for the [`sha256::Hash`] hash type.
pub type Sha256 = sha256::Hash;

/// SHA-384: Type alias for the [`sha384::Hash`] hash type.
pub type Sha384 = sha384::Hash;

/// SHA-512: Type alias for the [`sha512::Hash`] hash type.
pub type Sha512 = sha512::Hash;

/// SHA-512-256: Type alias for the [`sha512_256::Hash`] hash type.
pub type Sha512_256 = sha512_256::Hash;

/// RIPEMD-160: Type alias for the [`ripemd160::Hash`] hash type.
pub type Ripemd160 = ripemd160::Hash;

/// SipHash-2-4: Type alias for the [`siphash24::Hash`] hash type.
pub type Siphash24 = siphash24::Hash;

/// Tagged SHA-256: Type alias for the [`sha256t::Hash`] hash type.
pub type Sha256t<T> = sha256t::Hash<T>;

/// HASH-160: Type alias for the [`hash160::Hash`] hash type.
pub type Hash160 = hash160::Hash;

/// Double SHA-256: Type alias for the [`sha256d::Hash`] hash type.
pub type Sha256d = sha256d::Hash;

/// Hash type for computing an HMAC-SHA-1.
pub type HmacSha1 = Hmac<sha1::Engine, { sha1::DIGEST_SIZE }>;

/// Hash type for computing an HMAC-SHA-256.
pub type HmacSha256 = Hmac<sha256::Engine, { sha256::DIGEST_SIZE }>;

/// Hash type for computing an HMAC-SHA-384.
pub type HmacSha384 = Hmac<sha384::Engine, { sha384::DIGEST_SIZE }>;

/// Hash type for computing an HMAC-SHA-512.
pub type HmacSha512 = Hmac<sha512::Engine, { sha512::DIGEST_SIZE }>;

/// Hash type for computing an HMAC-SHA-512/256.
pub type HmacSha512_256 = Hmac<sha512_256::Engine, { sha512_256::DIGEST_SIZE }>;

/// Hash type for computing an HMAC-RIPEMD-160.
pub type HmacRipemd160 = Hmac<ripemd160::Engine, { ripemd160::DIGEST_SIZE }>;

/// Hash type for computing an HMAC-Siphash-2-4.
pub type HmacSiphash24 = Hmac<siphash24::Engine, { siphash24::DIGEST_SIZE }>;

/// Hash type for computing an HKDF based on HMAC-SHA-1.
pub type HkdfHmacSha1 = Hkdf<sha1::Engine, { sha1::DIGEST_SIZE }>;

/// Hash type for computing an HKDF based on HMAC-SHA-256.
pub type HkdfHmacSha256 = Hkdf<sha256::Engine, { sha256::DIGEST_SIZE }>;

/// Hash type for computing an HKDF based on HMAC-SHA-384.
pub type HkdfHmacSha384 = Hkdf<sha384::Engine, { sha384::DIGEST_SIZE }>;

/// Hash type for computing an HKDF based on HMAC-SHA-512.
pub type HkdfHmacSha512 = Hkdf<sha512::Engine, { sha512::DIGEST_SIZE }>;

/// Hash type for computing an HKDF based on HMAC-SHA-512/256.
pub type HkdfHmacSha512_256 = Hkdf<sha512_256::Engine, { sha512_256::DIGEST_SIZE }>;

/// Hash type for computing an HKDF based on HMAC-RIPEMD-160.
pub type HkdfHmacRipemd160 = Hkdf<ripemd160::Engine, { ripemd160::DIGEST_SIZE }>;

/// Hash type for computing an HKDF based on HMAC-Siphash-2-4.
pub type HkdfHmacSiphash24 = Hkdf<siphash24::Engine, { siphash24::DIGEST_SIZE }>;

/// A hashing engine which bytes can be serialized into.
pub trait HashEngine: Clone + Default {
    /// The digest returned by this hash engine.
    ///
    /// This is expected to be an array.
    // trait const types don't work as one would think without nightly.
    // ref: https://users.rust-lang.org/t/error-e0401-cant-use-generic-parameters-from-outer-function/84512
    type Digest: Copy
        + Clone
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + hash::Hash
        + convert::AsRef<[u8]>;

    /// Byte array representing the internal state of the hash engine.
    type Midstate;

    /// Length of the hash's internal block size, in bytes.
    const BLOCK_SIZE: usize;

    /// Add data to the hash engine.
    fn input(&mut self, data: &[u8]);

    /// Return the number of bytes already n_bytes_hashed(inputted).
    fn n_bytes_hashed(&self) -> usize;

    /// Returns the final digest from the current state of the hash engine.
    fn finalize(self) -> Self::Digest;

    /// Creates a default hash engine, adds `bytes` to it, then finalizes the engine.
    ///
    /// # Returns
    ///
    /// The digest created by hashing `bytes` with engine's hashing algorithm.
    fn hash(bytes: &[u8]) -> Self::Digest {
        let mut engine = Self::default();
        engine.input(bytes);
        engine.finalize()
    }

    /// Hashes all the byte slices retrieved from the iterator together.
    fn hash_byte_chunks<B, I>(byte_slices: I) -> Self::Digest
    where
        B: AsRef<[u8]>,
        I: IntoIterator<Item = B>,
    {
        let mut engine = Self::default();
        for slice in byte_slices {
            engine.input(slice.as_ref());
        }
        engine.finalize()
    }

    /// Outputs the midstate of the hash engine.
    ///
    /// This function should not be used unless you really know what you're doing
    /// (i.e. you probably should be a professional cryptographer to use this function).
    fn midstate(&self) -> Self::Midstate;

    /// Create a new [`HashEngine`] from a [`Self::Midstate`].
    ///
    /// This function should not be used unless you really know what you're doing
    /// (i.e. you probably should be a professional cryptographer to use this function).
    fn from_midstate(midstate: Self::Midstate, length: usize) -> Self;
}

/// Attempted to create a hash from an invalid length slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromSliceError {
    expected: usize,
    got: usize,
}

impl FromSliceError {
    /// Creates a new error (args are the same order as standard error code order).
    fn new(got: usize, expected: usize) -> Self { Self { got, expected } }

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
    use crate::sha256d;

    hash_newtype! {
        /// A test newtype engine.
        struct TestNewtypeEngine(sha256d);

        /// A test newtype.
        struct TestNewtype(_);
    }

    #[test]
    fn newtype_fmt_roundtrip() {
        let orig = TestNewtype::hash(&[]);
        let hex = format!("{}", orig);
        let rinsed = hex.parse::<TestNewtype>().expect("failed to parse hex");
        assert_eq!(rinsed, orig)
    }
}
