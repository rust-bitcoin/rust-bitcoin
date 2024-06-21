// SPDX-License-Identifier: CC0-1.0

//! Cryptography
//!
//! Cryptography related functionality: keys and signatures.

pub mod ecdsa;
// Contents re-exported in `primitives::key`.
pub mod key;
pub mod sighash;
// Contents re-exported in `primitives::taproot`.
pub mod taproot;
