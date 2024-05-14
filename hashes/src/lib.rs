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
//! use bitcoin_hashes::sha256;
//!
//! #[cfg(std)]
//! # fn main() -> std::io::Result<()> {
//! let mut reader: &[u8] = b"hello"; // in real code, this could be a `File` or `TcpStream`
//! let mut engine = sha256::Engine::default();
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
//! use std::io::Write;
//!
//! #[cfg(std)]
//! # fn main() -> std::io::Result<()> {
//! let mut part1: &[u8] = b"hello";
//! let mut part2: &[u8] = b" ";
//! let mut part3: &[u8] = b"world";
//! let mut engine = sha256::Engine::default();
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
pub extern crate actual_serde as serde;

#[cfg(all(test, feature = "serde"))]
extern crate serde_test;

#[cfg(bench)]
extern crate test;

/// Re-export the `rust-chf` crate.
pub extern crate chf;

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

/// Re-export the cryptographic hash function modules.
pub use chf::{
    hmac, ripemd160, sha1, sha256, sha256t::Tag, sha384, sha512, sha512_256, siphash24,
    FromSliceError, HashEngine,
};

/// Type alias for the [`sha1::Hash`] hash type.
pub type Sha1 = sha1::Hash;

/// Type alias for the [`sha256::Hash`] hash type.
pub type Sha256 = sha256::Hash;

/// Type alias for the [`sha384::Hash`] hash type.
pub type Sha384 = sha384::Hash;

/// Type alias for the [`sha512::Hash`] hash type.
pub type Sha512 = sha512::Hash;

/// Type alias for the [`sha512_256::Hash`] hash type.
pub type Sha512_256 = sha512_256::Hash;

/// Type alias for the [`ripemd160::Hash`] hash type.
pub type Ripemd160 = ripemd160::Hash;

/// Type alias for the [`siphash24::Hash`] hash type.
pub type Siphash24 = siphash24::Hash;

/// Type alias for the [`hmac::Hash`] hash type.
pub type Hmac<const N: usize> = hmac::Hash<N>;

/// Type alias for the [`sha256t::Hash`] hash type.
pub type Sha256t<T> = sha256t::Hash<T>; // FIXME: Perhaps `Sha256T` or `TaggedSha256`?

/// Type alias for the [`hash160::Hash`] hash type.
pub type Hash160 = hash160::Hash;

/// Type alias for the [`sha256d::Hash`] hash type.
pub type Sha256d = sha256d::Hash; // FIXME: Perhaps `Sha256D` or maybe `Hash256` (and change the module name)?

mod internal_macros;
#[macro_use]
mod macros;
#[macro_use]
pub mod serde_macros;
pub mod cmp;
pub mod hash160;
pub mod sha256d;
#[macro_use]
pub mod sha256t;

#[cfg(test)]
mod tests {
    use crate::sha256d;

    hash_newtype! {
        /// A test newtype
        struct TestNewtype(sha256d);

        /// A test newtype
        struct TestNewtype2(sha256d);
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

    #[test]
    fn newtype_fmt_roundtrip() {
        let orig = TestNewtype::hash(&[]);
        let hex = format!("{}", orig);
        let rinsed = hex.parse::<TestNewtype>().expect("failed to parse hex");
        assert_eq!(rinsed, orig)
    }
}
