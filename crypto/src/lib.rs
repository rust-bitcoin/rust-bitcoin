// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin Cryptography

#![no_std]
// Experimental features we need.
#![doc(test(attr(warn(unused))))]
// Coding conventions.
#![warn(deprecated_in_future)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub extern crate hex;

pub extern crate base58;

pub extern crate network;

pub extern crate secp256k1;

pub mod ecdsa;
pub mod key;
pub mod sighash;
#[cfg(feature = "alloc")]
pub mod taproot;

#[doc(inline)]
pub use self::key::{FullPublicKey, Keypair, LegacyPublicKey, PrivateKey, XOnlyPublicKey};

include!("../include/newtype.rs"); // Explained in `REPO_DIR/docs/README.md`.
