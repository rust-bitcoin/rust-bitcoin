// SPDX-License-Identifier: CC0-1.0

//! The `WitnessCommitment` type.

#[cfg(not(feature = "hex"))]
use core::fmt;
#[cfg(feature = "hex")]
use core::str;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::sha256d;

/// A hash corresponding to the witness structure commitment in the coinbase transaction.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WitnessCommitment(sha256d::Hash);

impl WitnessCommitment {
    /// Dummy hash used as the previous blockhash of the genesis block.
    pub const GENESIS_PREVIOUS_BLOCK_HASH: Self = Self::from_byte_array([0; 32]);
}

// The new hash wrapper type.
type HashType = WitnessCommitment;
// The inner hash type from `hashes`.
type Inner = sha256d::Hash;

include!("./generic.rs");
