// SPDX-License-Identifier: CC0-1.0

//! The `WitnessCommitment` type.

#[cfg(not(feature = "hex"))]
use core::fmt;
#[cfg(feature = "hex")]
use core::str;

use hashes::sha256d;
#[cfg(feature = "hex")]
use hex::FromHex as _;

const LEN: usize = 32;
#[cfg(feature = "hex")]
const REVERSE: bool = true;

/// A hash corresponding to the witness structure commitment in the coinbase transaction.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WitnessCommitment(sha256d::Hash);

type HashType = WitnessCommitment;

impl WitnessCommitment {
    /// Dummy hash used as the previous blockhash of the genesis block.
    pub const GENESIS_PREVIOUS_BLOCK_HASH: Self = Self::from_byte_array([0; 32]);

    /// Constructs a new type from the underlying byte array.
    pub const fn from_byte_array(bytes: [u8; LEN]) -> Self {
        Self(sha256d::Hash::from_byte_array(bytes))
    }
}

include!("./generic.rs");
