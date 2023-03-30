// Rust Bitcoin Library - Written by the rust-bitcoin developers.
// SPDX-License-Identifier: CC0-1.0

//! Cryptography
//!
//! Cryptography related functionality: keys and signatures.
//!

pub mod ecdsa; // Should only be used by the PSBT code.
pub mod key;
pub mod legacy;
pub mod segwit_v0;
pub mod sighash;
// Contents re-exported in `bitcoin::taproot`.
pub(crate) mod taproot;
