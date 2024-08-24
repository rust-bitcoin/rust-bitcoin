// SPDX-License-Identifier: CC0-1.0

//! Cryptography
//!
//! Cryptography related functionality: keys and signatures.

#[cfg(feature = "secp256k1")]
pub mod ecdsa;
pub mod key;
pub mod sighash;
// Contents re-exported in `bitcoin::taproot`.
#[cfg(feature = "secp256k1")]
pub(crate) mod taproot;
