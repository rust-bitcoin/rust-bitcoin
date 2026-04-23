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

pub extern crate base58;
pub extern crate hex_stable as hex;
pub extern crate io;
pub extern crate network;
pub extern crate secp256k1;
pub extern crate taproot_primitives;

#[cfg(feature = "alloc")]
pub mod ecdsa;
#[cfg(feature = "alloc")]
pub mod key;
#[cfg(feature = "alloc")]
pub mod sighash;

#[doc(inline)]
#[cfg(feature = "alloc")]
pub use self::{
    key::{FullPublicKey, Keypair, PrivateKey, LegacyPublicKey, XOnlyPublicKey},
};

#[cfg(feature = "alloc")]
include!("../include/newtype.rs"); // Explained in `REPO_DIR/docs/README.md`.
