// SPDX-License-Identifier: CC0-1.0

//! Rust Bitcoin Hashes Library
//!
//! This library implements the hash functions needed by Bitcoin. As an ancillary thing, it exposes
//! hexadecimal serialization and deserialization, since these are needed to display hashes.
//!
//! # Examples
//!
//! Hashing a single byte slice or a string:
//!
//! ```
//! use bitcoin_hashes::Sha256;
//!
//! let bytes = [0u8; 5];
//! let _hash_of_bytes = Sha256::hash(&bytes);
//! let _hash_of_string = Sha256::hash("some string".as_bytes());
//! ```
//!
//!
//! Hashing content from a reader:
//!
//! ```
//! # #[cfg(feature = "std")] {
//! use bitcoin_hashes::Sha256;
//!
//! let mut reader: &[u8] = b"hello"; // In real code, this could be a `File` or `TcpStream`.
//! let mut engine = Sha256::engine();
//! std::io::copy(&mut reader, &mut engine).expect("engine writes don't error");
//! let _hash = Sha256::from_engine(engine);
//! # }
//! ```
//!
//!
//! Hashing content using [`std::io::Write`] on a `HashEngine`:
//!
//! ```
//! # #[cfg(feature = "std")] {
//! use std::io::Write as _;
//! use bitcoin_hashes::Sha256;
//!
//! let part1: &[u8] = b"hello";
//! let part2: &[u8] = b" ";
//! let part3: &[u8] = b"world";
//! let mut engine = Sha256::engine();
//! engine.write_all(part1).expect("engine writes don't error");
//! engine.write_all(part2).unwrap();
//! engine.write_all(part3).unwrap();
//! let _hash = Sha256::from_engine(engine);
//! # }
//! ```

#![no_std]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(bench, feature(test))]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Pedantic lints that we enforce.
#![warn(clippy::return_self_not_must_use)]
// Instead of littering the codebase for non-fuzzing and bench code just globally allow.
#![cfg_attr(hashes_fuzz, allow(dead_code, unused_imports))]
#![cfg_attr(bench, allow(dead_code, unused_imports))]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)`instead of enforcing `format!("{x}")`

#[cfg(feature = "alloc")]
extern crate alloc;

extern crate core;

#[cfg(feature = "std")]
extern crate std;

/// A generic serialization/deserialization framework.
#[cfg(feature = "serde")]
pub extern crate serde;

#[cfg(all(test, feature = "serde"))]
extern crate serde_test;
#[cfg(bench)]
extern crate test;

/// Re-export the `hex-conservative` crate.
#[cfg(feature = "hex")]
pub extern crate hex;

#[doc(hidden)]
pub mod _export {
    /// A re-export of core::*
    pub mod _core {
        pub use core::*;
    }
}

#[deprecated(since = "TBD", note = "unused now that `Hash::from_slice` is deprecated")]
mod error;
mod internal_macros;

pub mod cmp;
pub mod hash160;
pub mod hkdf;
pub mod hmac;
#[macro_use]
pub mod macros;
pub mod ripemd160;
pub mod sha1;
pub mod sha256;
pub mod sha256d;
pub mod sha256t;
pub mod sha384;
pub mod sha512;
pub mod sha512_256;
pub mod siphash24;
pub mod sha3_256;

use core::fmt::{self, Write as _};
use core::{convert, hash};

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
/// SHA3-256: Alias for the [`sha3_256::Hash`] hash type.
pub use sha3_256::Hash as Sha3_256;

/// Attempted to create a hash from an invalid length slice.
#[deprecated(since = "TBD", note = "unused now that `Hash::from_slice` is deprecated")]
#[allow(deprecated_in_future)]
pub type FromSliceError = crate::error::FromSliceError; // Alias instead of re-export so we can deprecate it.

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
    /// The `Hash` type returned when finalizing this engine.
    type Hash: Hash;

    /// The byte array that is used internally in `finalize`.
    type Bytes: Copy + IsByteArray;

    /// Length of the hash, in bytes.
    const LEN: usize = Self::Bytes::LEN;

    /// Length of the hash's internal block size, in bytes.
    const BLOCK_SIZE: usize;

    /// Adds data to the hash engine.
    fn input(&mut self, data: &[u8]);

    /// Returns the number of bytes already input into the engine.
    fn n_bytes_hashed(&self) -> u64;

    /// Finalizes this engine.
    fn finalize(self) -> Self::Hash;
}

/// Trait which applies to hashes of all types.
pub trait Hash:
    Copy + Clone + PartialEq + Eq + PartialOrd + Ord + hash::Hash + convert::AsRef<[u8]>
{
    /// The byte array that represents the hash internally.
    type Bytes: Copy + IsByteArray;

    /// Length of the hash, in bytes.
    const LEN: usize = Self::Bytes::LEN;

    /// Flag indicating whether user-visible serializations of this hash should be backward.
    ///
    /// For some reason Satoshi decided this should be true for `Sha256dHash`, so here we are.
    const DISPLAY_BACKWARD: bool = false;

    /// Constructs a new hash from the underlying byte array.
    fn from_byte_array(bytes: Self::Bytes) -> Self;

    /// Returns the underlying byte array.
    fn to_byte_array(self) -> Self::Bytes;

    /// Returns a reference to the underlying byte array.
    fn as_byte_array(&self) -> &Self::Bytes;
}

/// Ensures that a type is an array.
pub trait IsByteArray: AsRef<[u8]> + sealed::IsByteArray {
    /// The length of the array.
    const LEN: usize;
}

impl<const N: usize> IsByteArray for [u8; N] {
    const LEN: usize = N;
}

mod sealed {
    pub trait IsByteArray {}

    impl<const N: usize> IsByteArray for [u8; N] {}
}

fn incomplete_block_len<H: HashEngine>(eng: &H) -> usize {
    let block_size = <H as HashEngine>::BLOCK_SIZE as u64; // Cast usize to u64 is ok.

    // After modulo operation we know cast u64 to usize as ok.
    (eng.n_bytes_hashed() % block_size) as usize
}

/// Writes `bytes` as a `hex` string to the formatter.
///
/// For when we cannot rely on having the `hex` feature enabled. Ignores formatter options and just
/// writes with plain old `f.write_char()`.
pub fn debug_hex(bytes: &[u8], f: &mut fmt::Formatter) -> fmt::Result {
    const HEX_TABLE: [u8; 16] = *b"0123456789abcdef";

    for &b in bytes {
        let lower = HEX_TABLE[usize::from(b >> 4)];
        let upper = HEX_TABLE[usize::from(b & 0b00001111)];
        f.write_char(char::from(lower))?;
        f.write_char(char::from(upper))?;
    }
    Ok(())
}

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

    #[cfg(feature = "hex")]
    crate::impl_hex_for_newtype!(TestNewtype, TestNewtype2);
    #[cfg(not(feature = "hex"))]
    crate::impl_debug_only_for_newtype!(TestNewtype, TestNewtype2);

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn newtype_fmt_roundtrip() {
        use alloc::format;

        #[rustfmt::skip]
        const DUMMY: TestNewtype = TestNewtype::from_byte_array([
            0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
            0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a,
            0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b,
            0x15, 0x26, 0x37, 0x48, 0x59, 0x6a, 0x7b, 0x8c,
        ]);

        let orig = DUMMY;
        let hex = format!("{}", orig);
        let rinsed = hex.parse::<TestNewtype>().expect("failed to parse hex");
        assert_eq!(rinsed, orig)
    }
}
